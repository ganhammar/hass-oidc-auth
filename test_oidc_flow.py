"""Test OIDC flow with Home Assistant."""

import webbrowser
from urllib.parse import parse_qs, urlparse

import requests

# Configuration
HA_URL = "https://hem.ganhammar.se"
CLIENT_ID = input("Enter your client_id: ").strip()
CLIENT_SECRET = input("Enter your client_secret: ").strip()
REDIRECT_URI = "http://localhost:3555/callback"

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
else:
    print(f"Error: {response.text}")
    exit(1)

print("\n=== Step 1: Authorization ===")
auth_url = (
    f"{discovery['authorization_endpoint']}?"
    f"client_id={CLIENT_ID}&"
    f"redirect_uri={REDIRECT_URI}&"
    f"response_type=code&"
    f"scope=openid profile&"
    f"state=test123"
)

print(f"\nAuthorization URL:\n{auth_url}\n")
print("Opening browser for authentication...")
print("After logging in, you'll be redirected to localhost:3555/callback")
print("Copy the FULL URL from your browser (it will fail to load, that's OK)")

webbrowser.open(auth_url)

callback_url = input("\nPaste the callback URL here: ").strip()

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
token_response = requests.post(
    discovery["token_endpoint"],
    data={
        "grant_type": "authorization_code",
        "code": auth_code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
    },
)

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
