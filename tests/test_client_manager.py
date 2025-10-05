"""Tests for client manager."""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

DOMAIN = "oidc_provider"

# Load security module first (dependency)
security_path = Path(__file__).parent.parent / "custom_components" / "oidc_provider" / "security.py"
security_spec = importlib.util.spec_from_file_location("security", security_path)
security_module = importlib.util.module_from_spec(security_spec)
sys.modules["oidc_provider.security"] = security_module
security_spec.loader.exec_module(security_module)

# Now load client_manager
client_manager_path = (
    Path(__file__).parent.parent / "custom_components" / "oidc_provider" / "client_manager.py"
)
spec = importlib.util.spec_from_file_location("client_manager", client_manager_path)
client_manager_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client_manager_module)
create_client = client_manager_module.create_client


@pytest.fixture
def mock_hass():
    """Create a mock Home Assistant instance."""
    hass = Mock()
    hass.data = {DOMAIN: {}}
    return hass


def test_create_client_with_defaults(mock_hass):
    """Test creating a client with default values."""
    result = create_client(
        mock_hass, client_name="Test Client", redirect_uris=["http://localhost/callback"]
    )

    # Verify returned data
    assert result["client_name"] == "Test Client"
    assert result["redirect_uris"] == ["http://localhost/callback"]
    assert result["grant_types"] == ["authorization_code", "refresh_token"]
    assert result["response_types"] == ["code"]
    assert result["token_endpoint_auth_method"] == "client_secret_basic"

    # Verify client_id and client_secret are generated
    assert "client_id" in result
    assert "client_secret" in result
    assert len(result["client_id"]) > 20
    assert len(result["client_secret"]) > 20

    # Verify client is stored in hass.data
    client_id = result["client_id"]
    assert client_id in mock_hass.data[DOMAIN]["clients"]

    stored_client = mock_hass.data[DOMAIN]["clients"][client_id]
    assert stored_client["client_name"] == "Test Client"
    assert stored_client["redirect_uris"] == ["http://localhost/callback"]
    assert "client_secret_hash" in stored_client
    assert "client_secret" not in stored_client  # Plain text not stored


def test_create_client_with_custom_client_id(mock_hass):
    """Test creating a client with a custom client ID."""
    custom_id = "my_custom_client_id"

    result = create_client(
        mock_hass,
        client_id=custom_id,
        client_name="Custom ID Client",
        redirect_uris=["http://example.com/callback"],
    )

    assert result["client_id"] == custom_id
    assert custom_id in mock_hass.data[DOMAIN]["clients"]


def test_create_client_with_custom_grant_types(mock_hass):
    """Test creating a client with custom grant types."""
    result = create_client(
        mock_hass,
        client_name="Custom Grant Client",
        redirect_uris=["http://localhost/callback"],
        grant_types=["authorization_code"],
        response_types=["code"],
    )

    assert result["grant_types"] == ["authorization_code"]
    assert result["response_types"] == ["code"]

    stored = mock_hass.data[DOMAIN]["clients"][result["client_id"]]
    assert stored["grant_types"] == ["authorization_code"]


def test_create_client_secret_is_hashed(mock_hass):
    """Test that client secret is hashed in storage."""
    result = create_client(
        mock_hass, client_name="Hash Test Client", redirect_uris=["http://localhost/callback"]
    )

    client_id = result["client_id"]

    stored = mock_hass.data[DOMAIN]["clients"][client_id]

    # Verify secret is not stored in plain text
    assert "client_secret" not in stored
    assert "client_secret_hash" in stored

    # Verify the hash format (should be salt:hash)
    secret_hash = stored["client_secret_hash"]
    assert ":" in secret_hash
    parts = secret_hash.split(":")
    assert len(parts) == 2
    assert len(parts[0]) == 64  # Salt hex length
    assert len(parts[1]) == 64  # Hash hex length


def test_create_client_initializes_clients_dict(mock_hass):
    """Test that create_client initializes clients dict if it doesn't exist."""
    # Don't pre-initialize clients
    assert "clients" not in mock_hass.data[DOMAIN]

    create_client(
        mock_hass, client_name="Init Test Client", redirect_uris=["http://localhost/callback"]
    )

    # Verify clients dict was created
    assert "clients" in mock_hass.data[DOMAIN]
    assert isinstance(mock_hass.data[DOMAIN]["clients"], dict)


def test_create_client_multiple_clients(mock_hass):
    """Test creating multiple clients."""
    client1 = create_client(
        mock_hass, client_name="Client 1", redirect_uris=["http://localhost:8001/callback"]
    )

    client2 = create_client(
        mock_hass, client_name="Client 2", redirect_uris=["http://localhost:8002/callback"]
    )

    # Verify both clients are stored
    assert client1["client_id"] in mock_hass.data[DOMAIN]["clients"]
    assert client2["client_id"] in mock_hass.data[DOMAIN]["clients"]

    # Verify they have different IDs and secrets
    assert client1["client_id"] != client2["client_id"]
    assert client1["client_secret"] != client2["client_secret"]


def test_create_client_with_multiple_redirect_uris(mock_hass):
    """Test creating a client with multiple redirect URIs."""
    redirect_uris = [
        "http://localhost:8080/callback",
        "http://localhost:3000/callback",
        "https://example.com/callback",
    ]

    result = create_client(
        mock_hass, client_name="Multi Redirect Client", redirect_uris=redirect_uris
    )

    assert result["redirect_uris"] == redirect_uris
    stored = mock_hass.data[DOMAIN]["clients"][result["client_id"]]
    assert stored["redirect_uris"] == redirect_uris


def test_create_client_with_empty_redirect_uris(mock_hass):
    """Test creating a client with empty redirect URIs list."""
    result = create_client(mock_hass, client_name="No Redirect Client", redirect_uris=[])

    assert result["redirect_uris"] == []


def test_create_client_with_client_secret_post(mock_hass):
    """Test creating a client with client_secret_post auth method."""
    result = create_client(
        mock_hass,
        client_name="Post Auth Client",
        redirect_uris=["http://localhost/callback"],
        token_endpoint_auth_method="client_secret_post",
    )

    assert result["token_endpoint_auth_method"] == "client_secret_post"
    stored = mock_hass.data[DOMAIN]["clients"][result["client_id"]]
    assert stored["token_endpoint_auth_method"] == "client_secret_post"


def test_create_client_id_uniqueness(mock_hass):
    """Test that generated client IDs are unique."""
    client_ids = set()

    for i in range(100):
        result = create_client(
            mock_hass, client_name=f"Client {i}", redirect_uris=["http://localhost/callback"]
        )
        client_ids.add(result["client_id"])

    # All 100 client IDs should be unique
    assert len(client_ids) == 100


def test_create_client_secret_uniqueness(mock_hass):
    """Test that generated client secrets are unique."""
    secrets = set()

    for i in range(100):
        result = create_client(
            mock_hass, client_name=f"Client {i}", redirect_uris=["http://localhost/callback"]
        )
        secrets.add(result["client_secret"])

    # All 100 client secrets should be unique
    assert len(secrets) == 100
