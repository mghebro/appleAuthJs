// Import necessary modules
const express = require("express");
const path = require("path");
const fs = require("fs");
const AppleAuth = require("./apple-auth");
const jwt = require("jsonwebtoken");
const qs = require("querystring");
const axios = require('axios'); // Import axios for making HTTP requests to C# backend

const app = express();
const port = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const config = {
  client_id: process.env.APPLE_CLIENT_ID || "com.mghebro.si",
  team_id: process.env.APPLE_TEAM_ID || "TTFPHSNRGQ",
  redirect_uri: process.env.APPLE_REDIRECT_URI || "https://mghebro-auth-test.netlify.app/auth/apple/callback",
  key_id: process.env.APPLE_KEY_ID || "ZR62KJ2BYT",
  scope: "name email",
};

// Private key handling with multiple fallback methods
let privateKeyContent;
let privateKeyMethod;

if (process.env.APPLE_PRIVATE_KEY) {
  let rawKey = process.env.APPLE_PRIVATE_KEY;

  // Try multiple methods to get the correct private key format
  if (rawKey.includes('\\n')) {
    // Method 1: Replace escaped newlines
    privateKeyContent = rawKey.replace(/\\n/g, '\n');
    console.log("🔧 Method 1: Converted \\n to newlines");
  } else if (!rawKey.includes('\n') && rawKey.length > 200) {
    // Method 2: Assume it's base64 encoded
    try {
      privateKeyContent = Buffer.from(rawKey, 'base64').toString('utf8');
      console.log("🔧 Method 2: Decoded from base64");
    } catch (err) {
      console.log("🔧 Method 2 failed, trying method 3");
      privateKeyContent = rawKey;
    }
  } else {
    // Method 3: Use as-is
    privateKeyContent = rawKey;
    console.log("🔧 Method 3: Using key as-is");
  }

  privateKeyMethod = "text";

  // DEBUG: Check private key format
  console.log("🔍 Private Key Debug Info:");
  console.log("Original length:", rawKey.length);
  console.log("Processed length:", privateKeyContent.length);
  console.log("Starts with:", privateKeyContent.substring(0, 30));
  console.log("Ends with:", privateKeyContent.substring(privateKeyContent.length - 30));
  console.log("Contains BEGIN:", privateKeyContent.includes("-----BEGIN"));
  console.log("Contains END:", privateKeyContent.includes("-----END"));
  console.log("Newline count:", (privateKeyContent.match(/\n/g) || []).length);
  console.log("Raw newline count:", (rawKey.match(/\n/g) || []).length);

  console.log("✅ Using private key from environment variable");
} else {
  const privateKeyLocation = path.join(__dirname, "AuthKey_ZR62KJ2BYT.p8");
  console.log("🔍 Looking for private key at:", privateKeyLocation);

  if (!fs.existsSync(privateKeyLocation)) {
    console.error(`❌ Error: Private key file not found at ${privateKeyLocation}`);
    console.error("💡 Tip: Set APPLE_PRIVATE_KEY environment variable instead");
    throw new Error("Apple private key not found in environment variable or file");
  }

  privateKeyContent = privateKeyLocation;
  privateKeyMethod = "file";
  console.log("✅ Using private key from file");
}

// Initialize AppleAuth
const appleAuth = new AppleAuth(
    config,
    privateKeyContent,
    privateKeyMethod,
    { debug: true }
);

console.log("🍎 Apple Auth initialized successfully");

// --- C# Backend API Endpoint ---
// IMPORTANT: Replace with the actual URL of your C# backend API
const CSHARP_BACKEND_API_URL = "https://4cf9ba56841b.ngrok-free.app/api/AppleService/auth/apple-callback"; // Example URL
// --- End C# Backend API Endpoint ---

// Routes
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
                const urlParams = new URLSearchParams(window.location.search);
                const code = urlParams.get('code');
                const id_token = urlParams.get('id_token');
                const state = urlParams.get('state');
                const user = urlParams.get('user');

                const responseMessageDiv = document.getElementById('response-message');
                const responseDataPre = document.getElementById('response-data');

                if (code || id_token || state || user) {
                    responseMessageDiv.classList.remove('hidden');
                    var responseText = 'No direct parameters found in URL. Check server logs for full token response.';
                    if (code) responseText += '\\nCode: ' + code;
                    if (id_token) responseText += '\\nID Token (decoded on server): See server logs';
                    if (state) responseText += '\\nState: ' + state;
                    if (user) responseText += '\\nUser (initial name/email): ' + user;

                    responseDataPre.textContent = responseText;
                }
            </script>
        </body>
        </html>
    `);
});

app.post("https://4cf9ba56841b.ngrok-free.app/api/AppleService/auth/apple-callback", async (req, res) => {
  let userAppleId = null; // Declare outside try-catch for broader scope
  let userEmail = null;
  let userName = null;
  let isPrivateEmail = false;
  let csharpBackendResponse = null;

  try {
    const { code, id_token, state, user } = req.body;

    console.log("--- Apple Callback Received ---");
    console.log("Code:", code);
    console.log("ID Token (raw):", id_token);
    console.log("State:", state);
    console.log("User (initial data from Apple, if provided):", user);

    if (state !== appleAuth.state) {
      console.error("CSRF Attack Detected: State mismatch!");
      return res.status(403).send("State mismatch. Possible CSRF attack.");
    }

    const tokenResponse = await appleAuth.accessToken(code);

    console.log("\n--- Apple Token Response ---");
    console.log(tokenResponse);

    if (tokenResponse.id_token) {
      try {
        const decodedIdToken = jwt.decode(tokenResponse.id_token);
        console.log("\n--- Decoded ID Token Payload ---");
        console.log(decodedIdToken);

        userAppleId = decodedIdToken.sub;
        userEmail = decodedIdToken.email || null;

        // Check if it's a private relay email
        if (userEmail && userEmail.includes('@privaterelay.appleid.com')) {
          isPrivateEmail = true;
        }

        // Parse user object if provided (only on first sign-in)
        if (user && typeof user === "string") {
          try {
            const parsedUser = JSON.parse(user);
            if (parsedUser.name) {
              const firstName = parsedUser.name.firstName || "";
              const lastName = parsedUser.name.lastName || "";
              userName = `${firstName} ${lastName}`.trim() || null;
            }
          } catch (parseError) {
            console.warn("Could not parse user string:", parseError);
          }
        }

        // --- FORWARD USER DATA TO C# BACKEND ---
        const userDataToForward = {
          appleId: userAppleId,
          email: userEmail,
          name: userName,
          isPrivateEmail: isPrivateEmail,
          refreshToken: tokenResponse.refresh_token,
          accessToken: tokenResponse.access_token,
          // You might also forward the id_token itself if your C# backend wants to verify it
          idToken: tokenResponse.id_token
        };

        try {
          console.log(`Attempting to send user data to C# backend at ${CSHARP_BACKEND_API_URL}`);
          const csharpResponse = await axios.post(CSHARP_BACKEND_API_URL, userDataToForward);
          csharpBackendResponse = csharpResponse.data; // Store response from C# backend
          console.log("✅ C# Backend Response:", csharpBackendResponse);
        } catch (csharpError) {
          console.error("❌ Error sending data to C# backend:", csharpError.response ? csharpError.response.data : csharpError.message);
          // Decide how to handle this error:
          // 1. Fail the entire authentication flow.
          // 2. Proceed but indicate that user data might not be saved.
          // For now, we'll proceed but log the error.
        }
        // --- END FORWARDING ---

      } catch (jwtError) {
        console.error("Error decoding ID token:", jwtError);
      }
    }

    // Prepare display values for the HTML response
    const displayEmail = userEmail || "Not provided";
    const displayName = userName || "Not provided (only available on first sign-in)";
    const emailType = isPrivateEmail ? " (Private Relay)" : "";

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
                        ${userName ? `Welcome, ${userName}!` : 'Welcome back!'}
                    </p>
                    <div class="bg-gray-100 p-4 rounded-md text-left mb-6">
                        <h3 class="font-semibold text-lg mb-2">Token Response Summary:</h3>
                        <pre class="whitespace-pre-wrap break-words text-sm">Access Token: ${tokenResponse.access_token ? tokenResponse.access_token.substring(0, 20) + "..." : "Not received"}
ID Token: ${tokenResponse.id_token ? tokenResponse.id_token.substring(0, 20) + "..." : "Not received"}
Expires In: ${tokenResponse.expires_in} seconds
Token Type: ${tokenResponse.token_type}</pre>
                    </div>
                    <div class="bg-blue-50 p-4 rounded-md text-left mb-6 border border-blue-200">
                        <h3 class="font-semibold text-lg mb-2 text-blue-800">User Information:</h3>
                        <div class="text-sm text-blue-700">
                            <p class="mb-2"><strong>Apple ID:</strong> ${userAppleId || "Not available"}</p>
                            <p class="mb-2"><strong>Email:</strong> ${displayEmail}${emailType}</p>
                            <p class="mb-2"><strong>Name:</strong> ${displayName}</p>
                            <p class="text-xs text-gray-600 mt-3">Note: Apple only provides the user's name on the first authentication.</p>
                        </div>
                    </div>
                    ${csharpBackendResponse ? `
                    <div class="bg-purple-50 p-4 rounded-md text-left mb-6 border border-purple-200">
                        <h3 class="font-semibold text-lg mb-2 text-purple-800">C# Backend Status:</h3>
                        <pre class="whitespace-pre-wrap break-words text-sm">${JSON.stringify(csharpBackendResponse, null, 2)}</pre>
                    </div>
                    ` : ''}
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
                    <p class="text-red-500 text-sm mb-6">${error.message || error}</p>
                    <a href="/" class="inline-block bg-blue-600 text-white py-2 px-5 rounded-full text-md font-semibold hover:bg-blue-700 transition duration-300 shadow-md">
                        Try Again
                    </a>
                </div>
            </body>
            </html>
        `);
  }
});

module.exports = app;
