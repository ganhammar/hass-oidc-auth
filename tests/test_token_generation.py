"""Test token generation and validation."""

import pytest
import jwt
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def test_jwt_token_generation():
    """Test JWT token can be generated and decoded."""
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    # Create token payload
    now = int(time.time())
    payload = {
        "sub": "test_user_id",
        "iat": now,
        "exp": now + 3600,
        "iss": "home-assistant",
        "aud": "test_client",
        "scope": "openid profile",
    }

    # Sign token
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    token = jwt.encode(payload, private_pem, algorithm="RS256")

    # Verify token
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    decoded = jwt.decode(token, public_pem, algorithms=["RS256"], audience="test_client")

    assert decoded["sub"] == "test_user_id"
    assert decoded["iss"] == "home-assistant"
    assert decoded["scope"] == "openid profile"


def test_token_expiry():
    """Test token expiry validation."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    # Create expired token
    now = int(time.time())
    payload = {
        "sub": "test_user_id",
        "iat": now - 7200,
        "exp": now - 3600,  # Expired 1 hour ago
        "iss": "home-assistant",
        "aud": "test_client",
    }

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    token = jwt.encode(payload, private_pem, algorithm="RS256")

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Verify that expired token raises exception
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, public_pem, algorithms=["RS256"], audience="test_client")
