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
  redirect_uri: "https://mghebro-auth-test.netlify.app/auth/apple/callback",
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

// C# Backend API URL - Updated to use environment variable with fallback
const CSHARP_BACKEND_URL = process.env.CSHARP_BACKEND_URL || "https://98be9a6964b0.ngrok-free.app/api/AppleService/auth/apple-callback";

console.log("🔗 C# Backend URL:", CSHARP_BACKEND_URL);

// Test C# backend connectivity
async function testCSharpBackend() {
  try {
    // Test 1: Try the test endpoint
    console.log("🧪 Testing C# backend connectivity...");
    console.log("🔗 Full backend URL:", CSHARP_BACKEND_URL);
    
    const baseUrl = CSHARP_BACKEND_URL.replace('/auth/apple-callback', '');
    const testUrl = `${baseUrl}/test`;
    
    console.log("🧪 Testing C# backend test endpoint:", testUrl);
    
    const response = await axios.get(testUrl, { 
      timeout: 5000,
      headers: {
        'User-Agent': 'AppleAuth-Test/1.0'
      }
    });
    console.log("✅ C# Backend test endpoint response:", response.status, response.data);
    
    // Test 2: Try the main endpoint with GET (should return 405 but confirms route exists)
    try {
      const getResponse = await axios.get(CSHARP_BACKEND_URL, { timeout: 5000 });
      console.log("✅ C# Backend callback endpoint GET response:", getResponse.status);
    } catch (error) {
      if (error.response?.status === 405) {
        console.log("✅ C# Backend callback endpoint exists (returns 405 for GET as expected)");
        return true;
      } else {
        console.log("❓ C# Backend callback endpoint GET error:", error.response?.status, error.message);
      }
    }
    
    return true;
  } catch (error) {
    console.log("❌ C# Backend test failed:");
    console.log("   Error:", error.message);
    console.log("   Status:", error.response?.status);
    console.log("   Data:", error.response?.data);
    return false;
  }
}

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
            <div class="mt-6">
                <a href="/debug" class="text-blue-600 underline">Debug Info</a>
            </div>
        </div>
    </body>
    </html>
  `);
});

// Debug endpoint
app.get("/debug", async (req, res) => {
  const backendStatus = await testCSharpBackend();
  
  res.json({
    message: "Debug Information",
    timestamp: new Date().toISOString(),
    config: {
      client_id: config.client_id,
      redirect_uri: config.redirect_uri,
      csharp_backend_url: CSHARP_BACKEND_URL
    },
    backend_status: backendStatus ? "✅ Accessible" : "❌ Not accessible",
    environment: {
      node_env: process.env.NODE_ENV,
      has_apple_private_key: !!process.env.APPLE_PRIVATE_KEY,
      has_csharp_backend_url: !!process.env.CSHARP_BACKEND_URL
    }
  });
});

// Apple callback route
app.post("/auth/apple/callback", async (req, res) => {
  let userAppleId = null;
  let userEmail = null;
  let userName = null;
  let isPrivateEmail = false;

  try {
    const { code, id_token, state, user } = req.body;

    console.log("--- Apple Callback Received ---");
    console.log("Code:", code ? "Present" : "Missing");
    console.log("State:", state);
    console.log("User data:", user);

    // Verify CSRF protection (skip for now to debug)
    // if (state !== appleAuth.state) {
    //   console.error("CSRF Attack Detected: State mismatch!");
    //   return res.status(403).send("State mismatch. Possible CSRF attack.");
    // }

    // Exchange authorization code for tokens
    const tokenResponse = await appleAuth.accessToken(code);
    console.log("\n--- Apple Token Response ---");
    console.log("Access token present:", !!tokenResponse.access_token);
    console.log("ID token present:", !!tokenResponse.id_token);
    console.log("Refresh token present:", !!tokenResponse.refresh_token);

    if (tokenResponse.id_token) {
      try {
        // Decode the ID token
        const decodedIdToken = jwt.decode(tokenResponse.id_token);
        console.log("\n--- Decoded ID Token ---");
        console.log("Subject (Apple ID):", decodedIdToken.sub);
        console.log("Email:", decodedIdToken.email);

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

        console.log("\n--- Sending to C# Backend ---");
        console.log("URL:", CSHARP_BACKEND_URL);
        console.log("Payload:", JSON.stringify(authRequest, null, 2));

        try {
          const csharpResponse = await axios.post(CSHARP_BACKEND_URL, authRequest, {
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json',
              'User-Agent': 'AppleAuth-NodeJS/1.0'
            },
            timeout: 15000, // 15 second timeout
            validateStatus: function (status) {
              return status < 500; // Accept all responses except 5xx errors
            }
          });
          
          console.log("✅ C# Backend Response Status:", csharpResponse.status);
          console.log("✅ C# Backend Response Headers:", csharpResponse.headers);
          console.log("✅ C# Backend Response Data:", csharpResponse.data);

          // Check if response is successful
          if (csharpResponse.status === 200 && csharpResponse.data) {
            // Handle different response structures
            let responseData = csharpResponse.data;
            
            // If your C# API returns { status: 200, data: {...}, message: "..." }
            if (responseData.status === 200 && responseData.data) {
              const frontendUrl = process.env.FRONTEND_URL || 'https://mghebro-auth-test.netlify.app';
              const successUrl = `${frontendUrl}/success.html?token=${responseData.data.accessToken}&email=${encodeURIComponent(responseData.data.email || '')}`;
              return res.redirect(successUrl);
            }
            // If your C# API returns the data directly
            else if (responseData.accessToken || responseData.token) {
              const frontendUrl = process.env.FRONTEND_URL || 'https://mghebro-auth-test.netlify.app';
              const token = responseData.accessToken || responseData.token;
              const email = responseData.email || userEmail || '';
              const successUrl = `${frontendUrl}/success.html?token=${token}&email=${encodeURIComponent(email)}`;
              return res.redirect(successUrl);
            }
            else {
              // Show success with debug info
              return res.send(generateSuccessHTML(tokenResponse, userAppleId, userEmail, userName, isPrivateEmail, responseData));
            }
          } else {
            throw new Error(`C# Backend returned status ${csharpResponse.status}: ${JSON.stringify(csharpResponse.data)}`);
          }
          
        } catch (csharpError) {
          console.error("❌ Error sending data to C# backend:");
          console.error("Error message:", csharpError.message);
          console.error("Response status:", csharpError.response?.status);
          console.error("Response data:", csharpError.response?.data);
          console.error("Request config:", {
            url: csharpError.config?.url,
            method: csharpError.config?.method,
            headers: csharpError.config?.headers
          });
          
          // Return error page with detailed information
          const errorDetails = {
            message: csharpError.message,
            status: csharpError.response?.status,
            statusText: csharpError.response?.statusText,
            url: CSHARP_BACKEND_URL,
            responseData: csharpError.response?.data
          };
          
          return res.status(500).send(generateErrorHTML(
            "Backend Authentication Failed", 
            `Failed to communicate with C# backend. Details: ${JSON.stringify(errorDetails, null, 2)}`
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

// Test endpoint
app.get("/test", (req, res) => {
  res.json({ 
    message: "Server is working", 
    timestamp: new Date().toISOString(),
    config: {
      client_id: config.client_id,
      redirect_uri: config.redirect_uri,
      csharp_backend_url: CSHARP_BACKEND_URL
    }
  });
});

// Helper functions
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
        <div class="bg-white p-8 rounded-lg shadow-lg text-center max-w-2xl w-full">
            <h1 class="text-3xl font-bold text-green-600 mb-4">Authentication Successful!</h1>
            <div class="bg-blue-50 p-4 rounded-md text-left mb-6">
                <h3 class="font-semibold mb-2">User Information:</h3>
                <p><strong>Apple ID:</strong> ${userAppleId || "Not available"}</p>
                <p><strong>Email:</strong> ${displayEmail}${emailType}</p>
                <p><strong>Name:</strong> ${displayName}</p>
            </div>
            ${csharpResponse ? `
            <div class="bg-purple-50 p-4 rounded-md text-left mb-6">
                <h3 class="font-semibold mb-2">Backend Response:</h3>
                <pre class="text-sm overflow-auto">${JSON.stringify(csharpResponse, null, 2)}</pre>
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
        <div class="bg-white p-8 rounded-lg shadow-lg text-center max-w-2xl w-full">
            <h1 class="text-3xl font-bold text-red-600 mb-4">${title}</h1>
            <div class="bg-red-50 p-4 rounded-md text-left mb-6">
                <pre class="text-sm overflow-auto whitespace-pre-wrap">${message}</pre>
            </div>
            <div class="flex gap-4 justify-center">
                <a href="/" class="bg-blue-600 text-white py-2 px-4 rounded">Try Again</a>
                <a href="/debug" class="bg-gray-600 text-white py-2 px-4 rounded">Debug Info</a>
            </div>
        </div>
    </body>
    </html>
  `;
}

module.exports = app;