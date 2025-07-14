// Import necessary modules
const express = require("express");
const path = require("path");
const fs = require("fs");
const AppleAuth = require("./apple-auth");
const jwt = require("jsonwebtoken");
const qs = require("querystring");

const app = express();
const port = process.env.PORT || 3000;

const users = {};

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

app.post("/auth/apple/callback", async (req, res) => {
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

    let decodedIdToken = null;
    let userEmail = "N/A";
    let userName = "N/A";
    let userAppleId = "N/A";

    if (tokenResponse.id_token) {
      try {
        decodedIdToken = jwt.decode(tokenResponse.id_token);
        console.log("\n--- Decoded ID Token Payload ---");
        console.log(decodedIdToken);

        userAppleId = decodedIdToken.sub;
        userEmail = decodedIdToken.email || "N/A";
        
        if (user && typeof user === "string") {
          try {
            const parsedUser = JSON.parse(user);
            userName = parsedUser.name
              ? `${parsedUser.name.firstName || ""} ${parsedUser.name.lastName || ""}`.trim()
              : "N/A";
          } catch (parseError) {
            console.warn("Could not parse user string:", parseError);
          }
        }

        if (userAppleId) {
          if (users[userAppleId]) {
            console.log(`\nUser ${userAppleId} already exists. Updating data.`);
            users[userAppleId].lastLogin = new Date();
            users[userAppleId].refreshToken = tokenResponse.refresh_token;
            users[userAppleId].accessToken = tokenResponse.access_token;
            if (userName !== "N/A" && !users[userAppleId].name)
              users[userAppleId].name = userName;
            if (userEmail !== "N/A" && !users[userAppleId].email)
              users[userAppleId].email = userEmail;
          } else {
            console.log(`\nNew user ${userAppleId}. Creating record.`);
            users[userAppleId] = {
              appleId: userAppleId,
              email: userEmail,
              name: userName,
              refreshToken: tokenResponse.refresh_token,
              accessToken: tokenResponse.access_token,
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
                            Access Token: ${tokenResponse.access_token ? tokenResponse.access_token.substring(0, 20) + "..." : "N/A"}
                            ID Token: ${tokenResponse.id_token ? tokenResponse.id_token.substring(0, 20) + "..." : "N/A"}
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