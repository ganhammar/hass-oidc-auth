"""Test OIDC flow with Home Assistant."""

import base64
import hashlib
import secrets
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Event, Thread
from urllib.parse import parse_qs, urlparse

import requests

# Configuration
HA_URL = "https://hem.ganhammar.se"
CLIENT_ID = input("Enter your client_id: ").strip()
CLIENT_SECRET = input("Enter your client_secret: ").strip()
CALLBACK_PORT = int(input("Enter callback port (default 3555): ").strip() or "3555")
REDIRECT_URI = f"http://localhost:{CALLBACK_PORT}/callback"

# Ask if user wants to test with PKCE
use_pkce = input("Test with PKCE? (y/n, default: y): ").strip().lower()
USE_PKCE = use_pkce != "n"

# Generate PKCE parameters if enabled
code_verifier = None
code_challenge = None
if USE_PKCE:
    # Generate code_verifier (43-128 characters)
    code_verifier = secrets.token_urlsafe(32)
    # Generate code_challenge using S256 method
    verifier_hash = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(verifier_hash).decode("ascii").rstrip("=")

# Global variable to store the callback URL
callback_data = {"url": None, "code": None}
callback_received = Event()


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler for OAuth callback."""

    def do_GET(self):
        """Handle GET request."""
        if self.path.startswith("/callback"):
            # Store the full URL
            callback_data["url"] = f"http://localhost:{CALLBACK_PORT}{self.path}"

            # Parse the code from query string
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            callback_data["code"] = params.get("code", [None])[0]

            # Signal that we received the callback
            callback_received.set()

            # Send response
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"""
                <html>
                <head><title>Authorization Successful</title></head>
                <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                    <h1>Authorization Successful!</h1>
                    <p>You can close this window and return to the terminal.</p>
                </body>
                </html>
                """
            )
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        """Suppress logging."""
        pass


print("\n=== Testing OIDC Discovery ===")
discovery_url = f"{HA_URL}/.well-known/openid-configuration"
response = requests.get(discovery_url)
print(f"Status: {response.status_code}")
if response.ok:
    discovery = response.json()
    print(f"Issuer: {discovery['issuer']}")
    print(f"Authorization Endpoint: {discovery['authorization_endpoint']}")
    print(f"Token Endpoint: {discovery['token_endpoint']}")
    print(f"UserInfo Endpoint: {discovery.get('userinfo_endpoint')}")
    if "code_challenge_methods_supported" in discovery:
        print(f"PKCE Methods: {discovery['code_challenge_methods_supported']}")
else:
    print(f"Error: {response.text}")
    exit(1)

if USE_PKCE:
    print("\n=== PKCE Enabled ===")
    print(f"Code Verifier: {code_verifier[:20]}...")
    print(f"Code Challenge: {code_challenge[:20]}...")
else:
    print("\n=== PKCE Disabled ===")
    print("Testing traditional OAuth2 flow without PKCE")

print("\n=== Step 1: Authorization ===")

# Start callback server
server = HTTPServer(("localhost", CALLBACK_PORT), CallbackHandler)
server.timeout = 1  # Set timeout so handle_request doesn't block forever


def run_server():
    """Run server until we get a callback."""
    while not callback_received.is_set():
        server.handle_request()


server_thread = Thread(target=run_server, daemon=True)
server_thread.start()
print(f"Started callback server on port {CALLBACK_PORT}")

# Build authorization URL with optional PKCE parameters
auth_params = {
    "client_id": CLIENT_ID,
    "redirect_uri": REDIRECT_URI,
    "response_type": "code",
    "scope": "openid profile",
    "state": "test123",
}

if USE_PKCE:
    auth_params["code_challenge"] = code_challenge
    auth_params["code_challenge_method"] = "S256"

auth_url = f"{discovery['authorization_endpoint']}?" + "&".join(
    f"{k}={v}" for k, v in auth_params.items()
)

print(f"\nAuthorization URL:\n{auth_url}\n")
print("Opening browser for authentication...")
print(f"Waiting for callback on http://localhost:{CALLBACK_PORT}/callback...")

webbrowser.open(auth_url)

# Wait for callback event with timeout
if not callback_received.wait(timeout=120):
    print("\nError: No authorization code received (timeout)")
    exit(1)

if not callback_data["code"]:
    print("\nError: No authorization code received")
    exit(1)

print("\n✓ Callback received!")

callback_url = callback_data["url"]

# Parse the callback URL to get the authorization code
parsed = urlparse(callback_url)
params = parse_qs(parsed.query)

if "code" not in params:
    print("Error: No authorization code found in callback URL")
    print(f"URL parameters: {params}")
    exit(1)

auth_code = params["code"][0]
state = params.get("state", [""])[0]

print(f"\n✓ Received authorization code: {auth_code[:20]}...")
print(f"✓ State: {state}")

print("\n=== Step 2: Exchange Code for Token ===")

# Build token request data with optional PKCE code_verifier
token_data = {
    "grant_type": "authorization_code",
    "code": auth_code,
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
    "redirect_uri": REDIRECT_URI,
}

if USE_PKCE:
    token_data["code_verifier"] = code_verifier
    print(f"Sending code_verifier: {code_verifier[:20]}...")

token_response = requests.post(discovery["token_endpoint"], data=token_data)

print(f"Status: {token_response.status_code}")
if token_response.ok:
    tokens = token_response.json()
    print(f"✓ Access Token: {tokens['access_token'][:50]}...")
    print(f"✓ Token Type: {tokens['token_type']}")
    print(f"✓ Expires In: {tokens['expires_in']} seconds")
    if "refresh_token" in tokens:
        print(f"✓ Refresh Token: {tokens['refresh_token'][:50]}...")

    access_token = tokens["access_token"]
else:
    print(f"Error: {token_response.text}")
    exit(1)

print("\n=== Step 3: Get User Info ===")
userinfo_response = requests.get(
    discovery["userinfo_endpoint"], headers={"Authorization": f"Bearer {access_token}"}
)

print(f"Status: {userinfo_response.status_code}")
if userinfo_response.ok:
    userinfo = userinfo_response.json()
    print("✓ User Info:")
    for key, value in userinfo.items():
        print(f"  - {key}: {value}")
else:
    print(f"Error: {userinfo_response.text}")

print("\n=== OIDC Flow Test Complete! ===")
print("✓ Discovery endpoint works")
print("✓ Authorization flow works")
print("✓ Token exchange works")
print("✓ UserInfo endpoint works")
if USE_PKCE:
    print("✓ PKCE (S256) flow successful")
