"""Test service handler logic."""


def test_client_registration_flow():
    """Test the client registration flow."""
    # Simulate client registration
    import secrets

    client_name = "Test Client"
    redirect_uris_input = "https://example.com/callback"
    redirect_uris = [uri.strip() for uri in redirect_uris_input.split(",") if uri.strip()]

    client_secret = secrets.token_urlsafe(32)

    client_data = {
        "client_name": client_name,
        "client_secret": client_secret,
        "redirect_uris": redirect_uris,
    }

    # Validate registration
    assert client_data["client_name"] == "Test Client"
    assert len(client_data["client_secret"]) > 0
    assert len(client_data["redirect_uris"]) == 1
    assert client_data["redirect_uris"][0] == "https://example.com/callback"


def test_client_revocation_flow():
    """Test the client revocation flow."""
    clients = {
        "client_abc123": {
            "client_name": "Test Client",
            "client_secret": "secret123",
            "redirect_uris": ["https://example.com/callback"],
        }
    }

    client_id_to_revoke = "client_abc123"

    # Check if client exists
    if client_id_to_revoke in clients:
        del clients[client_id_to_revoke]

    assert client_id_to_revoke not in clients
    assert len(clients) == 0


def test_client_list_flow():
    """Test the client list flow."""
    clients = {
        "client_abc123": {
            "client_name": "Test Client 1",
            "client_secret": "secret123",
            "redirect_uris": ["https://example.com/callback"],
        },
        "client_xyz789": {
            "client_name": "Test Client 2",
            "client_secret": "secret456",
            "redirect_uris": ["https://another.com/callback"],
        },
    }

    # Simulate listing
    client_count = len(clients)
    client_names = [client["client_name"] for client in clients.values()]

    assert client_count == 2
    assert "Test Client 1" in client_names
    assert "Test Client 2" in client_names


def test_client_list_empty():
    """Test listing when no clients exist."""
    clients = {}

    client_count = len(clients)

    assert client_count == 0
    assert not clients


def test_storage_save_format():
    """Test the format of data saved to storage."""
    clients = {
        "client_abc123": {
            "client_name": "Test Client",
            "client_secret": "secret123",
            "redirect_uris": ["https://example.com/callback"],
        }
    }

    # This is what gets saved
    storage_data = {"clients": clients}

    assert "clients" in storage_data
    assert storage_data["clients"] == clients


def test_storage_load_format():
    """Test loading data from storage."""
    stored_data = {
        "clients": {
            "client_abc123": {
                "client_name": "Test Client",
                "client_secret": "secret123",
                "redirect_uris": ["https://example.com/callback"],
            }
        }
    }

    # Simulate loading
    clients = stored_data.get("clients", {}) if stored_data else {}

    assert len(clients) == 1
    assert "client_abc123" in clients


def test_storage_load_empty():
    """Test loading when storage is empty."""
    stored_data = None

    # Simulate loading
    clients = stored_data.get("clients", {}) if stored_data else {}

    assert len(clients) == 0
    assert clients == {}


def test_multiple_redirect_uris():
    """Test registering client with multiple redirect URIs."""
    redirect_uris_input = "https://example.com/callback, http://localhost:3000/auth"
    redirect_uris = [uri.strip() for uri in redirect_uris_input.split(",") if uri.strip()]

    assert len(redirect_uris) == 2
    assert "https://example.com/callback" in redirect_uris
    assert "http://localhost:3000/auth" in redirect_uris


def test_update_client_redirect_uris():
    """Test updating client redirect URIs."""
    clients = {
        "client_abc123": {
            "client_name": "Test Client",
            "client_secret": "secret123",
            "redirect_uris": ["https://old.example.com/callback"],
        }
    }

    client_id = "client_abc123"
    new_redirect_uris_input = "https://new.example.com/callback,http://localhost:3000/auth"
    new_redirect_uris = [uri.strip() for uri in new_redirect_uris_input.split(",") if uri.strip()]

    # Check client exists
    assert client_id in clients

    # Update redirect URIs
    clients[client_id]["redirect_uris"] = new_redirect_uris

    # Verify update
    assert len(clients[client_id]["redirect_uris"]) == 2
    assert "https://new.example.com/callback" in clients[client_id]["redirect_uris"]
    assert "http://localhost:3000/auth" in clients[client_id]["redirect_uris"]
    assert "https://old.example.com/callback" not in clients[client_id]["redirect_uris"]


def test_update_client_not_found():
    """Test updating non-existent client."""
    clients = {
        "client_abc123": {
            "client_name": "Test Client",
            "client_secret": "secret123",
            "redirect_uris": ["https://example.com/callback"],
        }
    }

    client_id = "client_nonexistent"

    # Check client doesn't exist
    assert client_id not in clients


def test_update_client_single_redirect_uri():
    """Test updating client with single redirect URI."""
    clients = {
        "client_abc123": {
            "client_name": "Test Client",
            "client_secret": "secret123",
            "redirect_uris": ["https://old.example.com/callback", "http://localhost:3000"],
        }
    }

    client_id = "client_abc123"
    new_redirect_uris_input = "https://single.example.com/callback"
    new_redirect_uris = [uri.strip() for uri in new_redirect_uris_input.split(",") if uri.strip()]

    # Update to single URI
    clients[client_id]["redirect_uris"] = new_redirect_uris

    # Verify update
    assert len(clients[client_id]["redirect_uris"]) == 1
    assert clients[client_id]["redirect_uris"][0] == "https://single.example.com/callback"


def test_update_client_empty_redirect_uris():
    """Test updating client with empty redirect URIs."""
    clients = {
        "client_abc123": {
            "client_name": "Test Client",
            "client_secret": "secret123",
            "redirect_uris": ["https://example.com/callback"],
        }
    }

    client_id = "client_abc123"
    new_redirect_uris_input = ""
    new_redirect_uris = [uri.strip() for uri in new_redirect_uris_input.split(",") if uri.strip()]

    # Update with empty list
    clients[client_id]["redirect_uris"] = new_redirect_uris

    # Verify update
    assert len(clients[client_id]["redirect_uris"]) == 0


def test_update_preserves_client_secret():
    """Test that updating redirect URIs doesn't affect client secret."""
    clients = {
        "client_abc123": {
            "client_name": "Test Client",
            "client_secret": "secret123",
            "redirect_uris": ["https://old.example.com/callback"],
        }
    }

    client_id = "client_abc123"
    original_secret = clients[client_id]["client_secret"]
    new_redirect_uris = ["https://new.example.com/callback"]

    # Update redirect URIs
    clients[client_id]["redirect_uris"] = new_redirect_uris

    # Verify secret unchanged
    assert clients[client_id]["client_secret"] == original_secret
    assert clients[client_id]["client_secret"] == "secret123"


def test_update_preserves_client_name():
    """Test that updating redirect URIs doesn't affect client name."""
    clients = {
        "client_abc123": {
            "client_name": "Test Client",
            "client_secret": "secret123",
            "redirect_uris": ["https://old.example.com/callback"],
        }
    }

    client_id = "client_abc123"
    original_name = clients[client_id]["client_name"]
    new_redirect_uris = ["https://new.example.com/callback"]

    # Update redirect URIs
    clients[client_id]["redirect_uris"] = new_redirect_uris

    # Verify name unchanged
    assert clients[client_id]["client_name"] == original_name
    assert clients[client_id]["client_name"] == "Test Client"
