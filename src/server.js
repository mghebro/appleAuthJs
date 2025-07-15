// Import necessary modules
const express = require("express");
const path = require("path");
const fs = require("fs");
const AppleAuth = require("./apple-auth");
const jwt = require("jsonwebtoken");
const qs = require("querystring");
const axios = require("axios"); // Import axios for making HTTP requests to C# backend

const app = express();
const port = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const config = {
  client_id: process.env.APPLE_CLIENT_ID || "com.mghebro.si",
  team_id: process.env.APPLE_TEAM_ID || "TTFPHSNRGQ",
  redirect_uri:
    process.env.APPLE_REDIRECT_URI ||
    "https://mghebro-auth-test.netlify.app/auth/apple-callback",
  key_id: process.env.APPLE_KEY_ID || "ZR62KJ2BYT",
  scope: "name email",
};

// Private key handling with multiple fallback methods
let privateKeyContent;
let privateKeyMethod;

if (process.env.APPLE_PRIVATE_KEY) {
  let rawKey = process.env.APPLE_PRIVATE_KEY;

  // Try multiple methods to get the correct private key format
  if (rawKey.includes("\\n")) {
    // Method 1: Replace escaped newlines
    privateKeyContent = rawKey.replace(/\\n/g, "\n");
    console.log("🔧 Method 1: Converted \\n to newlines");
  } else if (!rawKey.includes("\n") && rawKey.length > 200) {
    // Method 2: Assume it's base64 encoded
    try {
      privateKeyContent = Buffer.from(rawKey, "base64").toString("utf8");
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
  console.log(
    "Ends with:",
    privateKeyContent.substring(privateKeyContent.length - 30)
  );
  console.log("Contains BEGIN:", privateKeyContent.includes("-----BEGIN"));
  console.log("Contains END:", privateKeyContent.includes("-----END"));
  console.log("Newline count:", (privateKeyContent.match(/\n/g) || []).length);
  console.log("Raw newline count:", (rawKey.match(/\n/g) || []).length);

  console.log("✅ Using private key from environment variable");
} else {
  const privateKeyLocation = path.join(__dirname, "AuthKey_ZR62KJ2BYT.p8");
  console.log("🔍 Looking for private key at:", privateKeyLocation);

  if (!fs.existsSync(privateKeyLocation)) {
    console.error(
      `❌ Error: Private key file not found at ${privateKeyLocation}`
    );
    console.error("💡 Tip: Set APPLE_PRIVATE_KEY environment variable instead");
    throw new Error(
      "Apple private key not found in environment variable or file"
    );
  }

  privateKeyContent = privateKeyLocation;
  privateKeyMethod = "file";
  console.log("✅ Using private key from file");
}

// Initialize AppleAuth
const appleAuth = new AppleAuth(config, privateKeyContent, privateKeyMethod, {
  debug: true,
});

console.log("🍎 Apple Auth initialized successfully");

// --- C# Backend API Endpoint ---
// IMPORTANT: This is the URL where your C# backend will be listening for the forwarded data.
// Make sure this matches your C# controller's route.
const CSHARP_BACKEND_API_URL =
  "https://2daf548e5cf8.ngrok-free.app/api/AppleService/auth/apple-callback"; // Corrected example URL
// --- End C# Backend API Endpoint ---

// Routes
app.get("/api/AppleService", (req, res) => {
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

// CORRECTED ROUTE DEFINITION: This route handles the callback from Apple
app.post(CSHARP_BACKEND_API_URL, async (req, res) => {
  let userAppleId = null;
  let userEmail = null;
  let userName = null;
  let isPrivateEmail = false;
  let csharpBackendResponse = null;

  try {
    const { code, id_token, state, user } = req.body;

    console.log("--- Apple Callback Received ---");
    console.log("Code:", code);
    console.log("State:", state);
    console.log("User data:", user);

    // Verify CSRF protection
    if (state !== appleAuth.state) {
      console.error("CSRF Attack Detected: State mismatch!");
      return res.status(403).send("State mismatch. Possible CSRF attack.");
    }

    // Exchange authorization code for tokens
    const tokenResponse = await appleAuth.accessToken(code);
    console.log("\n--- Apple Token Response ---");
    console.log(tokenResponse);

    if (tokenResponse.id_token) {
      try {
        // Decode the ID token
        const decodedIdToken = jwt.decode(tokenResponse.id_token);
        console.log("\n--- Decoded ID Token ---");
        console.log(decodedIdToken);

        userAppleId = decodedIdToken.sub;
        userEmail = decodedIdToken.email || null;

        // Check for private relay email
        if (userEmail && userEmail.includes('@privaterelay.appleid.com')) {
          isPrivateEmail = true;
        }

        // Parse user data (only provided on first sign-in)
        if (user && typeof user === "string") {
          try {
            const parsedUser = JSON.parse(user);
            if (parsedUser.name) {
              const firstName = parsedUser.name.firstName || "";
              const lastName = parsedUser.name.lastName || "";
              userName = `${firstName} ${lastName}`.trim() || null;
            }
          } catch (parseError) {
            console.warn("Could not parse user data:", parseError);
          }
        }

        // Prepare data for C# backend
        const authRequest = {
          code: code,
          redirectUri: config.redirect_uri,
          appleId: userAppleId,
          email: userEmail,
          name: userName,
          isPrivateEmail: isPrivateEmail,
          refreshToken: tokenResponse.refresh_token,
          accessToken: tokenResponse.access_token
        };

        try {
          console.log(`Sending auth data to C# backend at ${CSHARP_BACKEND_API_URL}`);
          console.log("Auth request data:", authRequest);
          
          const csharpResponse = await axios.post(CSHARP_BACKEND_API_URL, authRequest, {
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json'
            }
          });
          
          csharpBackendResponse = csharpResponse.data;
          console.log("✅ C# Backend Response:", csharpBackendResponse);

          // If C# backend returns success with JWT token, redirect to frontend
          if (csharpBackendResponse.status === 200 && csharpBackendResponse.data) {
            const frontendUrl = process.env.FRONTEND_URL || 'https://mghebro-auth-test.netlify.app';
            const successUrl = `${frontendUrl}/auth/success?token=${csharpBackendResponse.data.accessToken}&email=${encodeURIComponent(csharpBackendResponse.data.email || '')}`;
            return res.redirect(successUrl);
          }
          
        } catch (csharpError) {
          console.error("❌ Error sending data to C# backend:", csharpError.response ? csharpError.response.data : csharpError.message);
          // Return error page
          return res.status(500).send(generateErrorHTML("Failed to complete authentication", csharpError.message));
        }

      } catch (jwtError) {
        console.error("Error decoding ID token:", jwtError);
        return res.status(500).send(generateErrorHTML("Token decode error", jwtError.message));
      }
    }

    // Success page (fallback if not redirecting)
    res.send(generateSuccessHTML(tokenResponse, userAppleId, userEmail, userName, isPrivateEmail, csharpBackendResponse));

  } catch (error) {
    console.error("Error during Apple authentication callback:", error);
    res.status(500).send(generateErrorHTML("Authentication error", error.message));
  }
});

// Helper functions for generating HTML responses
function generateSuccessHTML(tokenResponse, userAppleId, userEmail, userName, isPrivateEmail, csharpResponse) {
  const displayEmail = userEmail || "Not provided";
  const displayName = userName || "Not provided (only available on first sign-in)";
  const emailType = isPrivateEmail ? " (Private Relay)" : "";

  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Apple Auth Success</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="flex items-center justify-center min-h-screen bg-gray-100">
        <div class="bg-white p-8 rounded-lg shadow-lg text-center max-w-md w-full">
            <h1 class="text-3xl font-bold text-green-600 mb-4">Authentication Successful!</h1>
            <div class="bg-blue-50 p-4 rounded-md text-left mb-6">
                <p><strong>Apple ID:</strong> ${userAppleId || "Not available"}</p>
                <p><strong>Email:</strong> ${displayEmail}${emailType}</p>
                <p><strong>Name:</strong> ${displayName}</p>
            </div>
            ${csharpResponse ? `
            <div class="bg-purple-50 p-4 rounded-md text-left mb-6">
                <h3 class="font-semibold">Backend Response:</h3>
                <pre class="text-sm">${JSON.stringify(csharpResponse, null, 2)}</pre>
            </div>
            ` : ''}
            <a href="/" class="bg-blue-600 text-white py-2 px-4 rounded">Home</a>
        </div>
    </body>
    </html>
  `;
}

function generateErrorHTML(title, message) {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Authentication Error</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="flex items-center justify-center min-h-screen bg-gray-100">
        <div class="bg-white p-8 rounded-lg shadow-lg text-center max-w-md w-full">
            <h1 class="text-3xl font-bold text-red-600 mb-4">${title}</h1>
            <p class="text-gray-700 mb-6">${message}</p>
            <a href="/" class="bg-blue-600 text-white py-2 px-4 rounded">Try Again</a>
        </div>
    </body>
    </html>
  `;
}

module.exports = app;
