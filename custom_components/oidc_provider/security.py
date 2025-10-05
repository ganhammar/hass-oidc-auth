"""Security utilities for OIDC Provider."""

import hashlib
import secrets


def hash_client_secret(secret: str) -> str:
    """Hash a client secret using SHA256 with a salt."""
    # Generate a random salt
    salt = secrets.token_bytes(32)
    # Hash the secret with the salt
    secret_hash = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 100000)
    # Store salt + hash as hex
    return salt.hex() + ":" + secret_hash.hex()


def verify_client_secret(secret: str, hashed: str) -> bool:
    """Verify a client secret against a hash."""
    try:
        salt_hex, hash_hex = hashed.split(":")
        salt = bytes.fromhex(salt_hex)
        stored_hash = bytes.fromhex(hash_hex)
        # Hash the provided secret with the same salt
        secret_hash = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 100000)
        # Compare in constant time
        return secrets.compare_digest(secret_hash, stored_hash)
    except (ValueError, AttributeError):
        return False
