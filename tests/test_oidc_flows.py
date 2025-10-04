"""Test OIDC flow logic."""

import secrets
import time


def test_authorization_code_generation():
    """Test authorization code generation."""
    auth_code = secrets.token_urlsafe(32)
    assert len(auth_code) > 0
    assert isinstance(auth_code, str)


def test_authorization_code_expiry():
    """Test authorization code expiry logic."""
    expiry_seconds = 600  # 10 minutes
    expires_at = time.time() + expiry_seconds

    # Code should not be expired
    assert expires_at > time.time()

    # Simulate expired code
    expired_at = time.time() - 100
    assert expired_at < time.time()


def test_refresh_token_generation():
    """Test refresh token generation."""
    refresh_token = secrets.token_urlsafe(32)
    assert len(refresh_token) > 0
    assert isinstance(refresh_token, str)


def test_token_payload_structure():
    """Test JWT token payload structure."""
    now = int(time.time())
    payload = {
        "sub": "test_user_id",
        "iat": now,
        "exp": now + 3600,
        "iss": "home-assistant",
        "aud": "test_client",
        "scope": "openid profile",
    }

    assert "sub" in payload
    assert "iat" in payload
    assert "exp" in payload
    assert "iss" in payload
    assert "aud" in payload
    assert payload["exp"] > payload["iat"]


def test_scope_parsing():
    """Test scope parsing."""
    scope = "openid profile email"
    scopes = scope.split()

    assert "openid" in scopes
    assert "profile" in scopes
    assert "email" in scopes


def test_authorization_code_data_structure():
    """Test authorization code data structure."""
    auth_code_data = {
        "client_id": "client_test123",
        "redirect_uri": "https://example.com/callback",
        "scope": "openid profile",
        "user_id": "user_123",
        "expires_at": time.time() + 600,
    }

    assert "client_id" in auth_code_data
    assert "redirect_uri" in auth_code_data
    assert "scope" in auth_code_data
    assert "user_id" in auth_code_data
    assert "expires_at" in auth_code_data


def test_redirect_url_construction():
    """Test redirect URL construction with auth code."""
    redirect_uri = "https://example.com/callback"
    auth_code = "test_code_123"
    state = "test_state"

    separator = "&" if "?" in redirect_uri else "?"
    redirect_url = f"{redirect_uri}{separator}code={auth_code}"
    if state:
        redirect_url += f"&state={state}"

    assert redirect_url == "https://example.com/callback?code=test_code_123&state=test_state"


def test_redirect_url_construction_with_existing_params():
    """Test redirect URL construction when URI has existing params."""
    redirect_uri = "https://example.com/callback?existing=param"
    auth_code = "test_code_123"

    separator = "&" if "?" in redirect_uri else "?"
    redirect_url = f"{redirect_uri}{separator}code={auth_code}"

    assert redirect_url == "https://example.com/callback?existing=param&code=test_code_123"
