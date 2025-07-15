// Import necessary modules
const express = require("express");
const path = require("path");
const fs = require("fs");
const AppleAuth = require("./apple-auth");
const jwt = require("jsonwebtoken");
const qs = require("querystring");
const axios = require("axios");

const app = express();
const port = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const config = {
  client_id: process.env.APPLE_CLIENT_ID || "com.mghebro.si",
  team_id: process.env.APPLE_TEAM_ID || "TTFPHSNRGQ",
  redirect_uri: "https://mghebro-auth-test.netlify.app/auth/apple/callback", // Fixed
  key_id: process.env.APPLE_KEY_ID || "ZR62KJ2BYT",
  scope: "name email",
};

// Private key handling
let privateKeyContent;
let privateKeyMethod;

if (process.env.APPLE_PRIVATE_KEY) {
  let rawKey = process.env.APPLE_PRIVATE_KEY;

  if (rawKey.includes("\\n")) {
    privateKeyContent = rawKey.replace(/\\n/g, "\n");
    console.log("🔧 Method 1: Converted \\n to newlines");
  } else if (!rawKey.includes("\n") && rawKey.length > 200) {
    try {
      privateKeyContent = Buffer.from(rawKey, "base64").toString("utf8");
      console.log("🔧 Method 2: Decoded from base64");
    } catch (err) {
      console.log("🔧 Method 2 failed, trying method 3");
      privateKeyContent = rawKey;
    }
  } else {
    privateKeyContent = rawKey;
    console.log("🔧 Method 3: Using key as-is");
  }

  privateKeyMethod = "text";
  console.log("✅ Using private key from environment variable");
} else {
  const privateKeyLocation = path.join(__dirname, "AuthKey_ZR62KJ2BYT.p8");
  console.log("🔍 Looking for private key at:", privateKeyLocation);

  if (!fs.existsSync(privateKeyLocation)) {
    console.error(`❌ Error: Private key file not found at ${privateKeyLocation}`);
    throw new Error("Apple private key not found in environment variable or file");
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

// C# Backend API URL
const CSHARP_BACKEND_API_URL = process.env.CSHARP_BACKEND_URL || "https://4709379df349.ngrok-free.app/api/AppleService/auth/apple-callback";

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
        </div>
    </body>
    </html>
  `);
});

// FIXED: Correct route path for Apple callback
app.post("/auth/apple/callback", async (req, res) => {
  let userAppleId = null;
  let userEmail = null;
  let userName = null;
  let isPrivateEmail = false;

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
            },
            timeout: 10000 // 10 second timeout
          });
          
          console.log("✅ C# Backend Response:", csharpResponse.data);

          // If C# backend returns success with JWT token, redirect to success page
          if (csharpResponse.data.status === 200 && csharpResponse.data.data) {
            const frontendUrl = process.env.FRONTEND_URL || 'https://mghebro-auth-test.netlify.app';
            const successUrl = `${frontendUrl}/success.html?token=${csharpResponse.data.data.accessToken}&email=${encodeURIComponent(csharpResponse.data.data.email || '')}`;
            return res.redirect(successUrl);
          } else {
            throw new Error(`C# Backend returned error: ${csharpResponse.data.message || 'Unknown error'}`);
          }
          
        } catch (csharpError) {
          console.error("❌ Error sending data to C# backend:", csharpError.response ? csharpError.response.data : csharpError.message);
          
          // Return error page instead of success
          return res.status(500).send(generateErrorHTML(
            "Backend Authentication Failed", 
            `Failed to complete authentication with backend: ${csharpError.message}`
          ));
        }

      } catch (jwtError) {
        console.error("Error decoding ID token:", jwtError);
        return res.status(500).send(generateErrorHTML("Token decode error", jwtError.message));
      }
    } else {
      throw new Error("No ID token received from Apple");
    }

  } catch (error) {
    console.error("Error during Apple authentication callback:", error);
    res.status(500).send(generateErrorHTML("Authentication error", error.message));
  }
});

// Add a test endpoint to verify the server is working
app.get("/test", (req, res) => {
  res.json({ 
    message: "Server is working", 
    timestamp: new Date().toISOString(),
    config: {
      client_id: config.client_id,
      redirect_uri: config.redirect_uri
    }
  });
});

// Helper functions for generating HTML responses
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