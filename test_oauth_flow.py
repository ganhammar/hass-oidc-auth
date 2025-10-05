#!/usr/bin/env python3
"""Test OAuth flow with Dynamic Client Registration."""

import base64
import hashlib
import json
import secrets
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Event, Thread
from urllib.parse import parse_qs, urlencode, urlparse

import requests

# Configuration
BASE_URL = input("Enter your Home Assistant URL (e.g., https://hem.ganhammar.se): ").strip()
REDIRECT_URI = "http://localhost:8888/callback"

# Global variables
auth_code = None
auth_code_received = Event()


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler for OAuth callback."""

    def do_GET(self):
        """Handle GET request."""
        global auth_code

        parsed = urlparse(self.path)
        if parsed.path == "/callback":
            params = parse_qs(parsed.query)
            if "code" in params:
                auth_code = params["code"][0]
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body><h1>Authorization successful!</h1>"
                    b"<p>You can close this window and return to the terminal.</p></body></html>"
                )
                auth_code_received.set()
            else:
                error = params.get("error", ["unknown"])[0]
                error_desc = params.get("error_description", ["No description"])[0]
                self.send_response(400)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(
                    f"<html><body><h1>Authorization failed!</h1>"
                    f"<p>Error: {error}</p><p>{error_desc}</p></body></html>".encode()
                )

    def log_message(self, format, *args):
        """Suppress log messages."""
        pass


def start_callback_server():
    """Start the callback server."""
    server = HTTPServer(("localhost", 8888), CallbackHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def main():
    """Run the OAuth flow test."""
    print("\n=== OAuth 2.0 Dynamic Client Registration Test ===\n")

    # Step 1: Discover OAuth endpoints
    print("Step 1: Discovering OAuth endpoints...")
    discovery_url = f"{BASE_URL}/.well-known/openid-configuration"
    print(f"  GET {discovery_url}")

    try:
        response = requests.get(discovery_url)
        response.raise_for_status()
        discovery = response.json()
        print("  ✓ Discovery successful")
    except Exception as e:
        print(f"  ✗ Discovery failed: {e}")
        sys.exit(1)

    print(f"\n  Endpoints discovered:")
    print(f"    - Authorization: {discovery['authorization_endpoint']}")
    print(f"    - Token: {discovery['token_endpoint']}")
    print(f"    - Registration: {discovery['registration_endpoint']}")

    # Step 2: Register client dynamically
    print("\nStep 2: Registering OAuth client dynamically...")
    registration_url = discovery["registration_endpoint"]
    print(f"  POST {registration_url}")

    registration_data = {
        "client_name": "OAuth Test Client",
        "redirect_uris": [REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic",
    }

    try:
        response = requests.post(registration_url, json=registration_data)
        response.raise_for_status()
        client_info = response.json()
        print("  ✓ Client registered successfully")
    except Exception as e:
        print(f"  ✗ Client registration failed: {e}")
        if hasattr(e, "response") and e.response is not None:
            print(f"    Response: {e.response.text}")
        sys.exit(1)

    client_id = client_info["client_id"]
    client_secret = client_info["client_secret"]
    print(f"\n  Client credentials:")
    print(f"    - Client ID: {client_id[:20]}...")
    print(f"    - Client Secret: {client_secret[:20]}...")

    # Step 3: Generate PKCE parameters
    print("\nStep 3: Generating PKCE parameters...")
    code_verifier = secrets.token_urlsafe(32)
    verifier_hash = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(verifier_hash).decode("ascii").rstrip("=")
    print(f"  ✓ Code challenge: {code_challenge[:20]}...")

    # Step 4: Start callback server
    print("\nStep 4: Starting callback server...")
    server = start_callback_server()
    print(f"  ✓ Listening on {REDIRECT_URI}")

    # Step 5: Authorization request
    print("\nStep 5: Starting authorization flow...")
    auth_params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile email",
        "state": secrets.token_urlsafe(16),
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    auth_url = f"{discovery['authorization_endpoint']}?{urlencode(auth_params)}"
    print(f"  Opening browser to: {auth_url[:80]}...")
    webbrowser.open(auth_url)

    print("\n  ⏳ Waiting for authorization (please log in to Home Assistant)...")
    auth_code_received.wait(timeout=300)

    if auth_code is None:
        print("  ✗ Authorization timeout or failed")
        server.shutdown()
        sys.exit(1)

    print("  ✓ Authorization code received")

    # Step 6: Exchange code for tokens
    print("\nStep 6: Exchanging authorization code for tokens...")
    token_url = discovery["token_endpoint"]
    print(f"  POST {token_url}")

    # Create Basic auth header
    credentials = f"{client_id}:{client_secret}"
    b64_credentials = base64.b64encode(credentials.encode()).decode()

    token_data = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
    }

    headers = {"Authorization": f"Basic {b64_credentials}"}

    try:
        response = requests.post(token_url, data=token_data, headers=headers)
        response.raise_for_status()
        tokens = response.json()
        print("  ✓ Tokens received successfully")
    except Exception as e:
        print(f"  ✗ Token exchange failed: {e}")
        if hasattr(e, "response") and e.response is not None:
            print(f"    Response: {e.response.text}")
        server.shutdown()
        sys.exit(1)

    access_token = tokens["access_token"]
    print(f"\n  Tokens:")
    print(f"    - Access Token: {access_token[:20]}...")
    if "refresh_token" in tokens:
        print(f"    - Refresh Token: {tokens['refresh_token'][:20]}...")

    # Step 7: Test MCP endpoint
    print("\nStep 7: Testing MCP endpoint with access token...")
    mcp_url = f"{BASE_URL}/api/mcp"
    print(f"  POST {mcp_url}")

    mcp_request = {
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {}},
        "id": 1,
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    try:
        response = requests.post(mcp_url, json=mcp_request, headers=headers)
        response.raise_for_status()
        mcp_response = response.json()
        print("  ✓ MCP endpoint responded successfully")
        print(f"\n  MCP Response:")
        print(f"    {json.dumps(mcp_response, indent=2)}")
    except Exception as e:
        print(f"  ✗ MCP request failed: {e}")
        if hasattr(e, "response") and e.response is not None:
            print(f"    Response: {e.response.text}")

    # Cleanup
    server.shutdown()
    print("\n=== Test Complete ===\n")


if __name__ == "__main__":
    main()
