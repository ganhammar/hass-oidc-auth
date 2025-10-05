"""Integration tests for security module."""

import importlib.util
import sys
from pathlib import Path

# Add the custom_components path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

spec = importlib.util.spec_from_file_location(
    "security",
    project_root / "custom_components" / "oidc_provider" / "security.py",
)
security_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(security_module)

hash_client_secret = security_module.hash_client_secret
verify_client_secret = security_module.verify_client_secret


def test_hash_client_secret_returns_valid_format():
    """Test that hash_client_secret returns properly formatted hash."""
    secret = "my_test_secret"
    hashed = hash_client_secret(secret)

    # Should have salt:hash format
    assert ":" in hashed
    parts = hashed.split(":")
    assert len(parts) == 2

    # Both parts should be hex strings
    salt_hex, hash_hex = parts
    assert len(salt_hex) == 64  # 32 bytes = 64 hex chars
    assert len(hash_hex) == 64  # 32 bytes = 64 hex chars

    # Should be valid hex
    bytes.fromhex(salt_hex)
    bytes.fromhex(hash_hex)


def test_verify_client_secret_accepts_correct_secret():
    """Test that verify_client_secret accepts correct secret."""
    secret = "correct_password"
    hashed = hash_client_secret(secret)

    assert verify_client_secret(secret, hashed) is True


def test_verify_client_secret_rejects_incorrect_secret():
    """Test that verify_client_secret rejects incorrect secret."""
    secret = "correct_password"
    hashed = hash_client_secret(secret)

    assert verify_client_secret("wrong_password", hashed) is False


def test_verify_client_secret_with_different_hashes():
    """Test that same secret hashed twice produces different hashes but both verify."""
    secret = "my_secret"
    hash1 = hash_client_secret(secret)
    hash2 = hash_client_secret(secret)

    # Hashes should be different (different salts)
    assert hash1 != hash2

    # But both should verify correctly
    assert verify_client_secret(secret, hash1) is True
    assert verify_client_secret(secret, hash2) is True


def test_verify_client_secret_with_invalid_format():
    """Test that verify_client_secret handles invalid hash format."""
    assert verify_client_secret("secret", "invalid") is False
    assert verify_client_secret("secret", "no:colon:here") is False
    assert verify_client_secret("secret", "") is False
    assert verify_client_secret("secret", "not_hex:also_not_hex") is False


def test_verify_client_secret_constant_time():
    """Test that verification uses constant-time comparison."""
    import time

    secret = "test_secret"
    hashed = hash_client_secret(secret)

    iterations = 100

    # Time correct password
    start = time.perf_counter()
    for _ in range(iterations):
        verify_client_secret(secret, hashed)
    correct_time = time.perf_counter() - start

    # Time incorrect password
    start = time.perf_counter()
    for _ in range(iterations):
        verify_client_secret("wrong_secret", hashed)
    incorrect_time = time.perf_counter() - start

    # Times should be within 50% of each other (constant-time)
    # This is a rough test but should catch obvious timing attacks
    ratio = max(correct_time, incorrect_time) / min(correct_time, incorrect_time)
    assert ratio < 1.5, f"Timing ratio too high: {ratio}"


def test_hash_client_secret_deterministic_with_same_input():
    """Test that hashing is not deterministic (uses random salt)."""
    secret = "test"
    results = [hash_client_secret(secret) for _ in range(10)]

    # All results should be different
    assert len(set(results)) == 10


def test_verify_client_secret_empty_strings():
    """Test handling of empty strings."""
    # Empty secret
    hashed = hash_client_secret("")
    assert verify_client_secret("", hashed) is True
    assert verify_client_secret("not_empty", hashed) is False

    # Empty hash should fail
    assert verify_client_secret("secret", "") is False


def test_hash_client_secret_special_characters():
    """Test hashing secrets with special characters."""
    secrets_to_test = [
        "password!@#$%^&*()",
        "pāsswörd",
        "密码",
        "па́роль",
        "pass\nword",
        "pass\tword",
    ]

    for secret in secrets_to_test:
        hashed = hash_client_secret(secret)
        assert verify_client_secret(secret, hashed) is True
        assert verify_client_secret("wrong", hashed) is False


def test_hash_client_secret_long_input():
    """Test hashing very long secrets."""
    long_secret = "a" * 10000
    hashed = hash_client_secret(long_secret)

    assert verify_client_secret(long_secret, hashed) is True
    assert verify_client_secret("a" * 9999, hashed) is False


def test_verify_client_secret_truncated_hash():
    """Test that truncated hash fails verification."""
    secret = "test_secret"
    hashed = hash_client_secret(secret)

    # Remove last character
    truncated = hashed[:-1]
    assert verify_client_secret(secret, truncated) is False

    # Remove salt
    hash_only = hashed.split(":")[1]
    assert verify_client_secret(secret, hash_only) is False


def test_verify_client_secret_modified_hash():
    """Test that modified hash fails verification."""
    secret = "test_secret"
    hashed = hash_client_secret(secret)

    salt, hash_part = hashed.split(":")

    # Modify one character in hash (toggle last character)
    last_char = hash_part[-1]
    new_char = "0" if last_char != "0" else "f"
    modified_hash = salt + ":" + hash_part[:-1] + new_char
    assert verify_client_secret(secret, modified_hash) is False

    # Modify salt (toggle first character)
    first_char = salt[0]
    new_first = "0" if first_char != "0" else "f"
    modified_salt = new_first + salt[1:] + ":" + hash_part
    assert verify_client_secret(secret, modified_salt) is False
