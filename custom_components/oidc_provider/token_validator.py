"""Token validation helper for OIDC provider."""

import logging
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)
DOMAIN = "oidc_provider"


def validate_access_token(
    hass: HomeAssistant, token: str, expected_issuer: str
) -> dict[str, Any] | None:
    """
    Validate an OAuth access token issued by this OIDC provider.

    Args:
        hass: Home Assistant instance
        token: The access token to validate
        expected_issuer: Expected issuer URL

    Returns:
        Token payload if valid, None otherwise
    """
    try:
        if DOMAIN not in hass.data:
            _LOGGER.error("OIDC provider not loaded")
            return None

        public_key = hass.data[DOMAIN].get("jwt_public_key")
        if not public_key:
            _LOGGER.error("JWT public key not found")
            return None

        # Convert public key to PEM format for JWT library
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Verify and decode the token with issuer verification
        payload = jwt.decode(
            token,
            public_key_pem,
            algorithms=["RS256"],
            issuer=expected_issuer,
            options={
                "verify_aud": False,  # We verify manually below
            },
        )

        # Verify the audience claim exists and matches a registered client
        aud = payload.get("aud")
        if not aud:
            _LOGGER.warning("Token missing audience claim")
            return None

        clients = hass.data[DOMAIN].get("clients", {})
        if aud not in clients:
            # Token audience doesn't match any registered client
            _LOGGER.warning("Token with invalid audience: %s", aud)
            return None

        return payload
    except jwt.ExpiredSignatureError:
        _LOGGER.warning("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        _LOGGER.warning("Invalid token: %s", e)
        return None
    except Exception as e:
        _LOGGER.error("Error validating token: %s", e)
        return None
