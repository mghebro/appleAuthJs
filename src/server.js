// Import necessary modules
const express = require("express");
const path = require("path");
const fs = require("fs"); // For reading the private key file
const AppleAuth = require("./apple-auth"); // Your provided apple-auth.js
const jwt = require('jsonwebtoken'); // For decoding the ID token
const qs = require("querystring"); // Already used in apple-auth.js, but good to have for clarity

const app = express();
// The port is no longer directly used by app.listen() but can be kept for local testing if desired.
const port = process.env.PORT || 3000; 

// --- Simple In-Memory User Store (for demonstration purposes) ---
// In a real application, you would use a database (e.g., MongoDB, PostgreSQL, Firebase Firestore).
const users = {};

// Middleware to parse URL-encoded bodies (for form submissions)
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // To parse JSON bodies if needed

// Serve static files (like your index.html if you put it in a 'public' folder)
// For this example, we'll serve index.html directly from a route.

// --- Apple Auth Configuration ---
// IMPORTANT: These values should be set as environment variables on your Netlify site.
// DO NOT hardcode sensitive credentials in production code.
const config = {
    client_id: process.env.APPLE_CLIENT_ID || "com.mghebro.si", // Your Services ID (e.g., com.yourcompany.yourapp.service)
    team_id: process.env.APPLE_TEAM_ID || "TTFPHSNRGQ", // Your 10-character Team ID
    // This redirect_uri MUST match what you configure in Apple Developer Portal and your hosted domain
    redirect_uri: process.env.APPLE_REDIRECT_URI || "https:/mghebro-auth-test.netlify.app/auth/apple/callback",
    key_id: process.env.APPLE_KEY_ID || "ZR62KJ2BYT", // Your 10-character Key ID for the Sign in with Apple private key
    scope: "name email", // The scope of information you want to request
};

// Private key location:
// On Netlify, you'll need to ensure this .p8 file is deployed with your functions.
// Alternatively, you could read the private key content from an environment variable (base64 encoded).
const privateKeyLocation = process.env.APPLE_PRIVATE_KEY_PATH || path.join(__dirname, "AuthKey_ZR62KJ2BYT.p8"); // Replace YOURKEYID with your actual Key ID

// Check if the private key file exists
if (!fs.existsSync(privateKeyLocation)) {
    console.error(`Error: Private key file not found at ${privateKeyLocation}`);
    console.error(
        "Please ensure your private key (.p8 file) is correctly deployed or its path/content is set via environment variables."
    );
    // In a Netlify Function, process.exit(1) might not be ideal.
    // You might want to throw an error that the function catches and returns a 500.
    // For now, we'll keep it for clarity, but be aware of serverless context.
    // process.exit(1);
    throw new Error("Apple private key file not found.");
}

// Initialize AppleAuth
const appleAuth = new AppleAuth(
    config,
    privateKeyLocation,
    "file", // privateKeyMethod: 'file' if reading from a file, 'text' if the key is a string
    { debug: true } // Enable debug mode for verbose error messages
);

// --- Routes ---

// Home route - serves the login page
app.get("/", (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Sign in with Apple Example</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
            <style>
                body {
                    font-family: 'Inter', sans-serif;
                    background-color: #f0f2f5;
                }
            </style>
        </head>
        <body class="flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-lg text-center max-w-md w-full">
                <h1 class="text-3xl font-bold text-gray-800 mb-6">Sign in with Apple</h1>
                <p class="text-gray-600 mb-8">
                    Click the button below to authenticate using your Apple ID.
                </p>
                <a href="${appleAuth.loginURL()}" class="inline-block bg-black text-white py-3 px-6 rounded-full text-lg font-semibold hover:bg-gray-800 transition duration-300 shadow-md">
                    Sign in with Apple
                </a>
                <div id="response-message" class="mt-8 p-4 bg-gray-100 rounded-md text-gray-700 text-left hidden">
                    <h3 class="font-semibold text-lg mb-2">Authentication Response:</h3>
                    <pre id="response-data" class="whitespace-pre-wrap break-words text-sm"></pre>
                </div>
            </div>

            <script>
                // This script handles displaying the response if redirected back with data
                const urlParams = new URLSearchParams(window.location.search);
                const code = urlParams.get('code');
                const id_token = urlParams.get('id_token');
                const state = urlParams.get('state');
                const user = urlParams.get('user'); // This might contain user name/email if Apple sends it

                const responseMessageDiv = document.getElementById('response-message');
                const responseDataPre = document.getElementById('response-data');

                if (code || id_token || state || user) {
                    responseMessageDiv.classList.remove('hidden');
                    var responseText = 'No direct parameters found in URL. Check server logs for full token response.';
                    if (code) responseText += '\\nCode: ' + code;
                    if (id_token) responseText += '\\nID Token (decoded on server): See server logs';
                    if (state) responseText += '\\nState: ' + state;
                    if (user) responseText += '\\nUser (initial name/email): ' + user; // Note: User data is usually in ID Token

                    responseDataPre.textContent = responseText;
                }
            </script>
        </body>
        </html>
    `);
});

// Apple Auth Callback route
app.post("/auth/apple/callback", async (req, res) => {
    try {
        // Apple sends data as form-urlencoded POST request
        const { code, id_token, state, user } = req.body;

        console.log("--- Apple Callback Received ---");
        console.log("Code:", code);
        console.log("ID Token (raw):", id_token);
        console.log("State:", state);
        console.log("User (initial data from Apple, if provided):", user); // This 'user' parameter is only sent on first login

        // Verify the state parameter to prevent CSRF attacks
        if (state !== appleAuth.state) {
            console.error("CSRF Attack Detected: State mismatch!");
            return res.status(403).send("State mismatch. Possible CSRF attack.");
        }

        // Exchange the authorization code for an access token
        const tokenResponse = await appleAuth.accessToken(code);

        console.log("\n--- Apple Token Response ---");
        console.log(tokenResponse);

        // --- Backend Logic: Decode ID Token and User Management ---
        let decodedIdToken = null;
        let userEmail = "N/A";
        let userName = "N/A";
        let userAppleId = "N/A";

        if (tokenResponse.id_token) {
            try {
                // Decode the ID token.
                // IMPORTANT: In a production environment, you MUST verify the signature
                // of the ID token using Apple's public keys (JWKS endpoint).
                // For simplicity, this example only decodes the payload.
                decodedIdToken = jwt.decode(tokenResponse.id_token);
                console.log("\n--- Decoded ID Token Payload ---");
                console.log(decodedIdToken);

                userAppleId = decodedIdToken.sub; // 'sub' is the unique identifier for the user from Apple
                userEmail = decodedIdToken.email || "N/A";
                // The 'name' claim is often not directly in the ID token unless requested and provided by Apple.
                // The 'user' parameter in the initial callback (req.body.user) might contain name on first login.
                if (user && typeof user === "string") {
                    try {
                        const parsedUser = JSON.parse(user);
                        userName = parsedUser.name
                            ? `${parsedUser.name.firstName || ""} ${
                                  parsedUser.name.lastName || ""
                              }`.trim()
                            : "N/A";
                    } catch (parseError) {
                        console.warn("Could not parse user string:", parseError);
                    }
                }

                // --- Simulate User Database Operations ---
                if (userAppleId) {
                    if (users[userAppleId]) {
                        // User exists, update their session/refresh token
                        console.log(`\nUser ${userAppleId} already exists. Updating data.`);
                        users[userAppleId].lastLogin = new Date();
                        users[userAppleId].refreshToken = tokenResponse.refresh_token; // Store refresh token
                        users[userAppleId].accessToken = tokenResponse.access_token; // Store access token
                        // Update name/email if they are new or changed (e.g., from first login 'user' param)
                        if (userName !== "N/A" && !users[userAppleId].name)
                            users[userAppleId].name = userName;
                        if (userEmail !== "N/A" && !users[userAppleId].email)
                            users[userAppleId].email = userEmail;
                    } else {
                        // New user, create a record
                        console.log(`\nNew user ${userAppleId}. Creating record.`);
                        users[userAppleId] = {
                            appleId: userAppleId,
                            email: userEmail,
                            name: userName,
                            refreshToken: tokenResponse.refresh_token, // Store refresh token
                            accessToken: tokenResponse.access_token, // Store access token
                            createdAt: new Date(),
                            lastLogin: new Date(),
                        };
                    }
                    console.log("Current in-memory users:", users);
                }
            } catch (jwtError) {
                console.error("Error decoding ID token:", jwtError);
            }
        }
        // --- End Backend Logic ---

        // For demonstration, we'll send a success message.
        // In a real application, you would create a user session,
        // redirect to a dashboard, etc.
        res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Apple Auth Success</title>
                <script src="https://cdn.tailwindcss.com"></script>
                <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
                <style>
                    body {
                        font-family: 'Inter', sans-serif;
                        background-color: #f0f2f5;
                    }
                </style>
            </head>
            <body class="flex items-center justify-center min-h-screen">
                <div class="bg-white p-8 rounded-lg shadow-lg text-center max-w-md w-full">
                    <h1 class="text-3xl font-bold text-green-600 mb-4">Authentication Successful!</h1>
                    <p class="text-gray-700 mb-6">
                        You have successfully signed in with Apple.
                        Check your server console for the full token response and user data.
                    </p>
                    <div class="bg-gray-100 p-4 rounded-md text-left mb-6">
                        <h3 class="font-semibold text-lg mb-2">Token Response Summary:</h3>
                        <pre class="whitespace-pre-wrap break-words text-sm">
                            Access Token: ${
                                tokenResponse.access_token
                                    ? tokenResponse.access_token.substring(0, 20) +
                                      "..."
                                    : "N/A"
                            }
                            ID Token: ${
                                tokenResponse.id_token
                                    ? tokenResponse.id_token.substring(0, 20) +
                                      "..."
                                    : "N/A"
                            }
                            Expires In: ${tokenResponse.expires_in} seconds
                            Token Type: ${tokenResponse.token_type}
                        </pre>
                    </div>
                    <div class="bg-blue-50 p-4 rounded-md text-left mb-6 border border-blue-200">
                        <h3 class="font-semibold text-lg mb-2 text-blue-800">Decoded User Information:</h3>
                        <pre class="whitespace-pre-wrap break-words text-sm text-blue-700">
                            Apple ID (sub): ${userAppleId}
                            Email: ${userEmail}
                            Name: ${userName}
                        </pre>
                    </div>
                    <a href="/" class="inline-block bg-blue-600 text-white py-2 px-5 rounded-full text-md font-semibold hover:bg-blue-700 transition duration-300 shadow-md">
                        Go back to Home
                    </a>
                </div>
            </body>
            </html>
        `);
    } catch (error) {
        console.error("Error during Apple authentication callback:", error);
        res.status(500).send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Apple Auth Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
                <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
                <style>
                    body {
                        font-family: 'Inter', sans-serif;
                        background-color: #f0f2f5;
                    }
                </style>
            </head>
            <body class="flex items-center justify-center min-h-screen">
                <div class="bg-white p-8 rounded-lg shadow-lg text-center max-w-md w-full">
                    <h1 class="text-3xl font-bold text-red-600 mb-4">Authentication Error</h1>
                    <p class="text-gray-700 mb-6">
                        An error occurred during Apple authentication. Please check the server logs for details.
                    </p>
                    <p class="text-red-500 text-sm mb-6">${
                        error.message || error
                    }</p>
                    <a href="/" class="inline-block bg-blue-600 text-white py-2 px-5 rounded-full text-md font-semibold hover:bg-blue-700 transition duration-300 shadow-md">
                        Try Again
                    </a>
                </div>
            </body>
            </html>
        `);
    }
});
// The app.listen() call is removed for Netlify Functions.
// module.exports is used to export the Express app for the Netlify Function handler.
module.exports = app;
