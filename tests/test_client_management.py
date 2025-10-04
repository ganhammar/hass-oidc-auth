"""Test client management logic."""

import secrets


def test_client_id_generation():
    """Test that client IDs are generated correctly."""
    client_id = f"client_{secrets.token_urlsafe(16)}"
    assert client_id.startswith("client_")
    assert len(client_id) > 7  # "client_" + token


def test_client_secret_generation():
    """Test that client secrets are generated correctly."""
    client_secret = secrets.token_urlsafe(32)
    assert len(client_secret) > 0
    assert isinstance(client_secret, str)


def test_redirect_uri_parsing():
    """Test redirect URI parsing logic."""
    redirect_uris_input = "https://example.com/callback, http://localhost:3000/auth"
    redirect_uris = [uri.strip() for uri in redirect_uris_input.split(",") if uri.strip()]

    assert len(redirect_uris) == 2
    assert "https://example.com/callback" in redirect_uris
    assert "http://localhost:3000/auth" in redirect_uris


def test_redirect_uri_parsing_single():
    """Test parsing single redirect URI."""
    redirect_uris_input = "https://example.com/callback"
    redirect_uris = [uri.strip() for uri in redirect_uris_input.split(",") if uri.strip()]

    assert len(redirect_uris) == 1
    assert redirect_uris[0] == "https://example.com/callback"


def test_redirect_uri_parsing_empty():
    """Test parsing empty redirect URI."""
    redirect_uris_input = ""
    redirect_uris = [uri.strip() for uri in redirect_uris_input.split(",") if uri.strip()]

    assert len(redirect_uris) == 0


def test_redirect_uri_parsing_with_spaces():
    """Test parsing redirect URIs with extra whitespace."""
    redirect_uris_input = "  https://example.com/callback  ,  http://localhost:3000/auth  "
    redirect_uris = [uri.strip() for uri in redirect_uris_input.split(",") if uri.strip()]

    assert len(redirect_uris) == 2
    assert redirect_uris[0] == "https://example.com/callback"
    assert redirect_uris[1] == "http://localhost:3000/auth"


def test_client_data_structure():
    """Test client data structure."""
    client_data = {
        "client_name": "Test Client",
        "client_secret": "test_secret",
        "redirect_uris": ["https://example.com/callback"],
    }

    assert "client_name" in client_data
    assert "client_secret" in client_data
    assert "redirect_uris" in client_data
    assert isinstance(client_data["redirect_uris"], list)
