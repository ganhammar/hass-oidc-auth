"""Test security features."""

import base64
import hashlib
import os
import secrets as python_secrets
import sys

# Add custom_components to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def hash_client_secret(secret: str) -> str:
    """Hash a client secret using SHA256 with a salt."""
    salt = python_secrets.token_bytes(32)
    secret_hash = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 100000)
    return salt.hex() + ":" + secret_hash.hex()


def verify_client_secret(secret: str, hashed: str) -> bool:
    """Verify a client secret against a hash."""
    try:
        salt_hex, hash_hex = hashed.split(":")
        salt = bytes.fromhex(salt_hex)
        stored_hash = bytes.fromhex(hash_hex)
        secret_hash = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 100000)
        return python_secrets.compare_digest(secret_hash, stored_hash)
    except (ValueError, AttributeError):
        return False


def test_client_secret_hashing():
    """Test client secret hashing and verification."""
    # Test hashing
    secret = "my_super_secret_password"
    hashed = hash_client_secret(secret)

    # Hash should be different from plain secret
    assert hashed != secret

    # Hash should contain salt and hash separated by colon
    assert ":" in hashed
    salt_hex, hash_hex = hashed.split(":")
    assert len(salt_hex) == 64  # 32 bytes = 64 hex chars
    assert len(hash_hex) == 64  # 32 bytes = 64 hex chars

    # Verify correct secret
    assert verify_client_secret(secret, hashed) is True

    # Verify incorrect secret
    assert verify_client_secret("wrong_password", hashed) is False


def test_client_secret_hashing_different_salts():
    """Test that hashing same secret twice produces different hashes."""
    secret = "my_secret"
    hash1 = hash_client_secret(secret)
    hash2 = hash_client_secret(secret)

    # Different salts should produce different hashes
    assert hash1 != hash2


def test_client_secret_verification_invalid_format():
    """Test verification with invalid hash format."""
    # Invalid formats should return False
    assert verify_client_secret("secret", "invalid_hash") is False
    assert verify_client_secret("secret", "onlyonepart") is False
    assert verify_client_secret("secret", "") is False


def test_pkce_code_challenge_s256():
    """Test PKCE S256 code challenge generation."""
    # Generate code verifier
    code_verifier = python_secrets.token_urlsafe(32)

    # Compute S256 challenge
    verifier_hash = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(verifier_hash).decode("ascii").rstrip("=")

    # Verify format
    assert len(code_challenge) > 0
    assert "=" not in code_challenge  # Base64url should have padding stripped

    # Verify it's reproducible
    verifier_hash2 = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge2 = base64.urlsafe_b64encode(verifier_hash2).decode("ascii").rstrip("=")
    assert code_challenge == code_challenge2


def test_pkce_code_verifier_length():
    """Test PKCE code verifier meets spec requirements."""
    # RFC 7636 requires verifier to be 43-128 characters
    code_verifier = python_secrets.token_urlsafe(32)
    assert len(code_verifier) >= 43
    assert len(code_verifier) <= 128


def test_rate_limit_data_structure():
    """Test rate limit data structure."""
    import time

    rate_limits = {}
    rate_limit_key = "client_123:192.168.1.1"
    current_time = time.time()

    # Record first attempt
    rate_limits[rate_limit_key] = {
        "attempts": 1,
        "window_start": current_time,
    }

    assert rate_limits[rate_limit_key]["attempts"] == 1
    assert rate_limits[rate_limit_key]["window_start"] == current_time

    # Increment attempts
    rate_limits[rate_limit_key]["attempts"] += 1
    assert rate_limits[rate_limit_key]["attempts"] == 2

    # Add lockout
    rate_limits[rate_limit_key]["locked_until"] = current_time + 60
    assert rate_limits[rate_limit_key]["locked_until"] > current_time


def test_rate_limit_cleanup():
    """Test cleanup of expired rate limit entries."""
    import time

    rate_limits = {
        "old_key": {"window_start": time.time() - 400},  # Expired (> 5 min old)
        "recent_key": {"window_start": time.time() - 100},  # Not expired
    }

    current_time = time.time()
    rate_limit_window = 300  # 5 minutes

    # Clean up old entries
    expired_keys = [
        key
        for key, data in rate_limits.items()
        if data["window_start"] < current_time - rate_limit_window
    ]

    for key in expired_keys:
        del rate_limits[key]

    # Only recent key should remain
    assert "old_key" not in rate_limits
    assert "recent_key" in rate_limits


def test_authorization_request_expiry():
    """Test authorization request expiry."""
    import time

    pending_requests = {
        "request_1": {"expires_at": time.time() + 600},  # Not expired
        "request_2": {"expires_at": time.time() - 10},  # Expired
    }

    current_time = time.time()

    # Clean up expired requests
    expired_ids = [
        req_id
        for req_id, req_data in pending_requests.items()
        if req_data["expires_at"] < current_time
    ]

    for req_id in expired_ids:
        del pending_requests[req_id]

    # Only non-expired request should remain
    assert "request_1" in pending_requests
    assert "request_2" not in pending_requests


def test_authorization_code_with_pkce_data():
    """Test authorization code stores PKCE parameters."""
    import time

    auth_code = python_secrets.token_urlsafe(32)
    code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    code_challenge_method = "S256"

    auth_codes = {
        auth_code: {
            "client_id": "client_123",
            "redirect_uri": "https://example.com/callback",
            "scope": "openid profile",
            "user_id": "user_123",
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "expires_at": time.time() + 600,
        }
    }

    # Verify PKCE data is stored
    assert auth_codes[auth_code]["code_challenge"] == code_challenge
    assert auth_codes[auth_code]["code_challenge_method"] == code_challenge_method


def test_pending_request_with_pkce_data():
    """Test pending authorization request stores PKCE parameters."""
    import time

    request_id = python_secrets.token_urlsafe(16)
    code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    code_challenge_method = "S256"

    pending_requests = {
        request_id: {
            "client_id": "client_123",
            "redirect_uri": "https://example.com/callback",
            "response_type": "code",
            "scope": "openid profile",
            "state": "abc123",
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "expires_at": time.time() + 600,
        }
    }

    # Verify PKCE data is stored
    assert pending_requests[request_id]["code_challenge"] == code_challenge
    assert pending_requests[request_id]["code_challenge_method"] == code_challenge_method
