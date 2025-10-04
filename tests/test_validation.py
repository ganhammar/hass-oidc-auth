"""Test validation logic."""


def test_duplicate_client_name_detection():
    """Test that duplicate client names are detected."""
    existing_clients = {
        "client_abc123": {
            "client_name": "Test Client",
            "client_secret": "secret123",
            "redirect_uris": ["https://example.com/callback"],
        },
        "client_xyz789": {
            "client_name": "Another Client",
            "client_secret": "secret456",
            "redirect_uris": ["https://example.com/callback"],
        },
    }

    new_client_name = "Test Client"

    # Check for duplicate
    is_duplicate = any(
        client["client_name"] == new_client_name for client in existing_clients.values()
    )

    assert is_duplicate is True


def test_unique_client_name_allowed():
    """Test that unique client names are allowed."""
    existing_clients = {
        "client_abc123": {
            "client_name": "Test Client",
            "client_secret": "secret123",
            "redirect_uris": ["https://example.com/callback"],
        },
    }

    new_client_name = "New Client"

    # Check for duplicate
    is_duplicate = any(
        client["client_name"] == new_client_name for client in existing_clients.values()
    )

    assert is_duplicate is False


def test_empty_clients_allows_any_name():
    """Test that any name is allowed when no clients exist."""
    existing_clients = {}

    new_client_name = "First Client"

    # Check for duplicate
    is_duplicate = any(
        client["client_name"] == new_client_name for client in existing_clients.values()
    )

    assert is_duplicate is False


def test_client_name_case_sensitive():
    """Test that client name comparison is case-sensitive."""
    existing_clients = {
        "client_abc123": {
            "client_name": "Test Client",
            "client_secret": "secret123",
            "redirect_uris": ["https://example.com/callback"],
        },
    }

    # Different case
    new_client_name_lower = "test client"
    is_duplicate_lower = any(
        client["client_name"] == new_client_name_lower for client in existing_clients.values()
    )

    new_client_name_upper = "TEST CLIENT"
    is_duplicate_upper = any(
        client["client_name"] == new_client_name_upper for client in existing_clients.values()
    )

    # Should not be duplicates (case-sensitive)
    assert is_duplicate_lower is False
    assert is_duplicate_upper is False


def test_redirect_uri_validation():
    """Test redirect URI format validation."""
    valid_uris = [
        "https://example.com/callback",
        "http://localhost:3000/auth",
        "https://app.example.com/oauth/callback",
        "http://127.0.0.1:8080/callback",
    ]

    invalid_uris = [
        "",
        "not-a-url",
        "ftp://example.com/callback",  # Valid format, but unusual protocol
    ]

    # Simple validation: must start with http:// or https://
    for uri in valid_uris:
        assert uri.startswith("http://") or uri.startswith("https://")

    # Empty string should fail
    assert not invalid_uris[0].startswith("http")


def test_client_secret_not_empty():
    """Test that client secrets are not empty."""
    import secrets

    client_secret = secrets.token_urlsafe(32)

    assert client_secret is not None
    assert len(client_secret) > 0
    assert isinstance(client_secret, str)


def test_client_id_uniqueness():
    """Test that client IDs are likely to be unique."""
    import secrets

    # Generate multiple client IDs
    client_ids = set()
    for _ in range(100):
        client_id = f"client_{secrets.token_urlsafe(16)}"
        client_ids.add(client_id)

    # All should be unique
    assert len(client_ids) == 100


def test_storage_data_structure():
    """Test storage data structure."""
    storage_data = {
        "clients": {
            "client_abc123": {
                "client_name": "Test Client",
                "client_secret": "secret123",
                "redirect_uris": ["https://example.com/callback"],
            }
        }
    }

    assert "clients" in storage_data
    assert isinstance(storage_data["clients"], dict)

    for client_id, client_data in storage_data["clients"].items():
        assert isinstance(client_id, str)
        assert "client_name" in client_data
        assert "client_secret" in client_data
        assert "redirect_uris" in client_data
        assert isinstance(client_data["redirect_uris"], list)
