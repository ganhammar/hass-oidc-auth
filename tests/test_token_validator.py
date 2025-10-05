"""Tests for token validator."""

import importlib.util
import time
from pathlib import Path
from unittest.mock import Mock

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DOMAIN = "oidc_provider"

# Import the function directly from the module file
token_validator_path = (
    Path(__file__).parent.parent / "custom_components" / "oidc_provider" / "token_validator.py"
)
spec = importlib.util.spec_from_file_location("token_validator", token_validator_path)
token_validator_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(token_validator_module)
validate_access_token = token_validator_module.validate_access_token


@pytest.fixture
def mock_hass_with_keys():
    """Create a mock Home Assistant instance with JWT keys."""
    hass = Mock()
    hass.data = {}

    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    # Initialize OIDC provider data
    hass.data[DOMAIN] = {
        "jwt_private_key": private_key,
        "jwt_public_key": public_key,
    }

    return hass, private_key


def test_validate_access_token_valid(mock_hass_with_keys):
    """Test validating a valid access token."""
    hass, private_key = mock_hass_with_keys

    # Create a valid token
    payload = {
        "sub": "test_user",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iss": "http://localhost",
    }

    # Convert private key to PEM for JWT library
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token = jwt.encode(payload, private_key_pem, algorithm="RS256")

    # Validate the token
    result = validate_access_token(hass, token)

    assert result is not None
    assert result["sub"] == "test_user"
    assert result["iss"] == "http://localhost"


def test_validate_access_token_expired(mock_hass_with_keys):
    """Test validating an expired token."""
    hass, private_key = mock_hass_with_keys

    # Create an expired token
    payload = {
        "sub": "test_user",
        "iat": int(time.time()) - 7200,
        "exp": int(time.time()) - 3600,  # Expired 1 hour ago
        "iss": "http://localhost",
    }

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token = jwt.encode(payload, private_key_pem, algorithm="RS256")

    # Validate the token
    result = validate_access_token(hass, token)

    assert result is None


def test_validate_access_token_invalid_signature(mock_hass_with_keys):
    """Test validating a token with invalid signature."""
    hass, _ = mock_hass_with_keys

    # Create a token with a different key
    different_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    payload = {
        "sub": "test_user",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iss": "http://localhost",
    }

    different_key_pem = different_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token = jwt.encode(payload, different_key_pem, algorithm="RS256")

    # Validate the token
    result = validate_access_token(hass, token)

    assert result is None


def test_validate_access_token_malformed(mock_hass_with_keys):
    """Test validating a malformed token."""
    hass, _ = mock_hass_with_keys

    # Validate a malformed token
    result = validate_access_token(hass, "not.a.valid.jwt.token")

    assert result is None


def test_validate_access_token_no_oidc_provider():
    """Test validating when OIDC provider is not loaded."""
    hass = Mock()
    hass.data = {}
    # Don't initialize OIDC provider data

    result = validate_access_token(hass, "any.token.here")

    assert result is None


def test_validate_access_token_no_public_key():
    """Test validating when public key is missing."""
    hass = Mock()
    hass.data = {DOMAIN: {}}  # OIDC provider loaded but no keys

    result = validate_access_token(hass, "any.token.here")

    assert result is None


def test_validate_access_token_with_custom_claims(mock_hass_with_keys):
    """Test validating a token with custom claims."""
    hass, private_key = mock_hass_with_keys

    # Create a token with custom claims
    payload = {
        "sub": "test_user",
        "name": "Test User",
        "email": "test@example.com",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iss": "http://localhost",
        "custom_claim": "custom_value",
    }

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token = jwt.encode(payload, private_key_pem, algorithm="RS256")

    # Validate the token
    result = validate_access_token(hass, token)

    assert result is not None
    assert result["sub"] == "test_user"
    assert result["name"] == "Test User"
    assert result["email"] == "test@example.com"
    assert result["custom_claim"] == "custom_value"
