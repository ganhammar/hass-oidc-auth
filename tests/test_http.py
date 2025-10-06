"""Tests for HTTP endpoints."""

import json
import time
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from custom_components.oidc_provider.const import DOMAIN
from custom_components.oidc_provider.http import (
    OAuth2AuthorizationServerMetadataView,
    OIDCContinueView,
    OIDCDiscoveryView,
    OIDCJWKSView,
    OIDCRegisterView,
    _get_base_url,
)


def test_get_base_url_with_forwarded_headers():
    """Test _get_base_url with X-Forwarded headers (proxy setup)."""
    # Create a mock request with X-Forwarded headers
    request = Mock()
    request.headers = {
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": "example.com",
    }
    request.url.origin.return_value = "http://localhost:8123"

    result = _get_base_url(request)

    assert result == "https://example.com"
    # Verify that request.url.origin() was not called when headers are present
    request.url.origin.assert_not_called()


def test_get_base_url_without_forwarded_headers():
    """Test _get_base_url without X-Forwarded headers (direct connection)."""
    # Create a mock request without X-Forwarded headers
    request = Mock()
    request.headers = {}
    request.url.origin.return_value = "http://192.168.1.100:8123"

    result = _get_base_url(request)

    assert result == "http://192.168.1.100:8123"
    # Verify that request.url.origin() was called
    request.url.origin.assert_called_once()


def test_get_base_url_with_partial_forwarded_headers():
    """Test _get_base_url with only one X-Forwarded header (should use fallback)."""
    # Create a mock request with only X-Forwarded-Proto
    request = Mock()
    request.headers = {
        "X-Forwarded-Proto": "https",
    }
    request.url.origin.return_value = "http://localhost:8123"

    result = _get_base_url(request)

    assert result == "http://localhost:8123"
    # Should fall back to origin() when both headers aren't present
    request.url.origin.assert_called_once()


def test_get_base_url_with_only_host_header():
    """Test _get_base_url with only X-Forwarded-Host (should use fallback)."""
    # Create a mock request with only X-Forwarded-Host
    request = Mock()
    request.headers = {
        "X-Forwarded-Host": "example.com",
    }
    request.url.origin.return_value = "http://localhost:8123"

    result = _get_base_url(request)

    assert result == "http://localhost:8123"
    # Should fall back to origin() when both headers aren't present
    request.url.origin.assert_called_once()


@pytest.mark.asyncio
async def test_oidc_discovery_endpoint():
    """Test OIDC discovery endpoint returns correct metadata."""
    # Create a mock request
    request = Mock()
    request.headers = {}
    request.url.origin.return_value = "https://homeassistant.local"

    # Create the view and call get
    view = OIDCDiscoveryView()
    response = await view.get(request)

    # Verify response
    assert response.status == 200
    assert response.content_type == "application/json"

    # Parse JSON response
    import json

    body = response.body.decode("utf-8")
    data = json.loads(body)

    # Verify required OIDC fields
    assert data["issuer"] == "https://homeassistant.local"
    assert data["authorization_endpoint"] == "https://homeassistant.local/oidc/authorize"
    assert data["token_endpoint"] == "https://homeassistant.local/oidc/token"
    assert data["userinfo_endpoint"] == "https://homeassistant.local/oidc/userinfo"
    assert data["jwks_uri"] == "https://homeassistant.local/oidc/jwks"
    assert data["registration_endpoint"] == "https://homeassistant.local/oidc/register"

    # Verify supported features
    assert "code" in data["response_types_supported"]
    assert "S256" in data["code_challenge_methods_supported"]
    assert "openid" in data["scopes_supported"]
    assert "client_secret_post" in data["token_endpoint_auth_methods_supported"]
    assert "client_secret_basic" in data["token_endpoint_auth_methods_supported"]


@pytest.mark.asyncio
async def test_oidc_discovery_with_proxy():
    """Test OIDC discovery endpoint with proxy headers."""
    # Create a mock request with X-Forwarded headers
    request = Mock()
    request.headers = {
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": "ha.example.com",
    }
    request.url.origin.return_value = "http://localhost:8123"

    # Create the view and call get
    view = OIDCDiscoveryView()
    response = await view.get(request)

    # Parse response
    body = response.body.decode("utf-8")
    data = json.loads(body)

    # Verify URLs use the proxy host
    assert data["issuer"] == "https://ha.example.com"
    assert data["authorization_endpoint"] == "https://ha.example.com/oidc/authorize"
    assert data["token_endpoint"] == "https://ha.example.com/oidc/token"


@pytest.mark.asyncio
async def test_oauth2_authorization_server_metadata():
    """Test OAuth 2.0 Authorization Server Metadata endpoint."""
    request = Mock()
    request.headers = {}
    request.url.origin.return_value = "https://homeassistant.local"

    view = OAuth2AuthorizationServerMetadataView()
    response = await view.get(request)

    assert response.status == 200
    body = response.body.decode("utf-8")
    data = json.loads(body)

    # Verify required fields
    assert data["issuer"] == "https://homeassistant.local"
    assert data["authorization_endpoint"] == "https://homeassistant.local/oidc/authorize"
    assert data["token_endpoint"] == "https://homeassistant.local/oidc/token"
    assert data["registration_endpoint"] == "https://homeassistant.local/oidc/register"
    assert "authorization_code" in data["grant_types_supported"]
    assert "refresh_token" in data["grant_types_supported"]


@pytest.mark.asyncio
async def test_oidc_jwks_endpoint():
    """Test OIDC JWKS endpoint returns public key."""
    # Create mock hass with RSA keys
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    request = Mock()
    request.app = {"hass": Mock()}
    request.app["hass"].data = {
        DOMAIN: {
            "jwt_public_key": public_key,
        }
    }

    view = OIDCJWKSView()
    response = await view.get(request)

    assert response.status == 200
    body = response.body.decode("utf-8")
    data = json.loads(body)

    # Verify JWKS structure
    assert "keys" in data
    assert len(data["keys"]) == 1
    key = data["keys"][0]
    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert key["alg"] == "RS256"
    assert "n" in key  # modulus
    assert "e" in key  # exponent


@pytest.mark.asyncio
async def test_oidc_continue_view_missing_request_id():
    """Test continue view with missing request_id."""
    request = MagicMock()
    request.query = {}
    request.app = {"hass": Mock()}

    view = OIDCContinueView()
    response = await view.get(request)

    assert response.status == 400
    assert b"Missing request_id" in response.body


@pytest.mark.asyncio
async def test_oidc_continue_view_invalid_request_id():
    """Test continue view with invalid request_id."""
    hass = Mock()
    hass.data = {DOMAIN: {"pending_auth_requests": {}}}

    request = MagicMock()
    request.query = {"request_id": "invalid"}
    request.app = {"hass": hass}
    request.__getitem__.return_value = Mock(id="user123")

    view = OIDCContinueView()
    response = await view.get(request)

    assert response.status == 400
    assert b"Invalid or expired request" in response.body


@pytest.mark.asyncio
async def test_oidc_continue_view_expired_request():
    """Test continue view with expired request."""
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "pending_auth_requests": {
                "req123": {
                    "client_id": "client123",
                    "redirect_uri": "https://example.com/callback",
                    "scope": "openid",
                    "state": "state123",
                    "expires_at": time.time() - 100,  # Expired
                }
            },
            "authorization_codes": {},
        }
    }

    request = MagicMock()
    request.query = {"request_id": "req123"}
    request.app = {"hass": hass}
    request.__getitem__.return_value = Mock(id="user123")

    view = OIDCContinueView()
    response = await view.get(request)

    assert response.status == 400
    assert b"Request expired" in response.body
    # Verify expired request was cleaned up
    assert "req123" not in hass.data[DOMAIN]["pending_auth_requests"]


@pytest.mark.asyncio
async def test_oidc_continue_view_success():
    """Test successful continue flow."""
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "pending_auth_requests": {
                "req123": {
                    "client_id": "client123",
                    "redirect_uri": "https://example.com/callback",
                    "scope": "openid profile",
                    "state": "state123",
                    "code_challenge": "challenge123",
                    "code_challenge_method": "S256",
                    "expires_at": time.time() + 600,
                }
            },
            "authorization_codes": {},
        }
    }

    request = MagicMock()
    request.query = {"request_id": "req123"}
    request.app = {"hass": hass}
    request.__getitem__.return_value = Mock(id="user123")

    view = OIDCContinueView()
    response = await view.get(request)

    assert response.status == 200
    body = response.body.decode("utf-8")
    data = json.loads(body)

    # Verify redirect URL
    assert "redirect_url" in data
    assert data["redirect_url"].startswith("https://example.com/callback?code=")
    assert "state=state123" in data["redirect_url"]

    # Verify authorization code was created
    assert len(hass.data[DOMAIN]["authorization_codes"]) == 1

    # Verify pending request was cleaned up
    assert "req123" not in hass.data[DOMAIN]["pending_auth_requests"]


@pytest.mark.asyncio
async def test_oidc_register_view_success():
    """Test successful dynamic client registration."""
    from unittest.mock import patch

    hass = Mock()
    hass.data = {DOMAIN: {"clients": {}, "store": Mock()}}
    hass.data[DOMAIN]["store"].async_save = MagicMock(return_value=None)

    request = Mock()
    request.app = {"hass": hass}
    request.json = AsyncMock(
        return_value={
            "client_name": "Test Client",
            "redirect_uris": ["https://example.com/callback"],
        }
    )

    view = OIDCRegisterView()

    # Mock create_client to avoid actual implementation
    with patch("custom_components.oidc_provider.http.create_client") as mock_create:
        mock_create.return_value = {
            "client_id": "test_client_id",
            "client_secret": "test_client_secret",
            "client_name": "Test Client",
            "redirect_uris": ["https://example.com/callback"],
        }

        response = await view.post(request)

    body = response.body.decode("utf-8")
    data = json.loads(body)

    # Debug: print error if not 201
    if response.status != 201:
        print(f"Status: {response.status}, Body: {data}")

    assert response.status == 201
    assert data["client_id"] == "test_client_id"
    assert data["client_secret"] == "test_client_secret"
    assert data["client_name"] == "Test Client"


@pytest.mark.asyncio
async def test_oidc_register_view_minimal():
    """Test client registration with minimal valid data."""
    hass = Mock()
    store = Mock()
    store.async_save = AsyncMock(return_value=None)
    hass.data = {DOMAIN: {"clients": {}, "store": store}}

    request = Mock()
    request.app = {"hass": hass}
    request.json = AsyncMock(
        return_value={
            "redirect_uris": ["https://example.com/callback"],
        }
    )

    view = OIDCRegisterView()
    response = await view.post(request)

    # Should succeed with default client name
    assert response.status == 201
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert "client_id" in data
    assert "client_secret" in data


@pytest.mark.asyncio
async def test_oidc_register_view_invalid_redirect_uri():
    """Test client registration rejects invalid redirect URI."""
    hass = Mock()
    store = Mock()
    store.async_save = AsyncMock(return_value=None)
    hass.data = {DOMAIN: {"clients": {}, "store": store}}

    request = Mock()
    request.app = {"hass": hass}
    request.json = AsyncMock(
        return_value={
            "client_name": "Test Client",
            "redirect_uris": ["not-a-valid-url"],
        }
    )

    view = OIDCRegisterView()
    response = await view.post(request)

    assert response.status == 400
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert data["error"] == "invalid_redirect_uri"
    assert "not-a-valid-url" in data["error_description"]
