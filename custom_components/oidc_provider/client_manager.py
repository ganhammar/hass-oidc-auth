"""Client management utilities for OIDC provider."""

import logging
import secrets
from typing import Any
from urllib.parse import urlparse

from homeassistant.core import HomeAssistant

from .security import hash_client_secret

_LOGGER = logging.getLogger(__name__)
DOMAIN = "oidc_provider"


async def create_client(
    hass: HomeAssistant,
    client_name: str = "OIDC Client",
    redirect_uris: list[str] = None,
    grant_types: list[str] = None,
    response_types: list[str] = None,
    token_endpoint_auth_method: str = "client_secret_basic",
) -> dict[str, Any]:
    """
    Create and register a new OAuth client.

    Args:
        hass: Home Assistant instance
        client_name: Human-readable client name
        redirect_uris: List of allowed redirect URIs
        grant_types: List of allowed grant types
        response_types: List of allowed response types
        token_endpoint_auth_method: Token endpoint authentication method

    Returns:
        Dictionary with client_id, client_secret, and other metadata

    Raises:
        ValueError: If redirect URIs are invalid
    """
    if redirect_uris is None:
        redirect_uris = []

    if grant_types is None:
        grant_types = ["authorization_code", "refresh_token"]

    if response_types is None:
        response_types = ["code"]

    # Validate each redirect URI is a valid URL
    for uri in redirect_uris:
        if not isinstance(uri, str):
            raise ValueError("Each redirect_uri must be a string")
        try:
            parsed = urlparse(uri)
            # Must have scheme and netloc (host)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError(f"Invalid redirect_uri: {uri}")
            # Only allow http/https schemes
            if parsed.scheme not in ["http", "https"]:
                raise ValueError(f"Redirect URI must use http or https: {uri}")
        except Exception as e:
            if isinstance(e, ValueError):
                raise
            raise ValueError(f"Invalid redirect_uri: {uri}") from e

    # Generate client credentials
    client_id = secrets.token_urlsafe(32)
    client_secret = secrets.token_urlsafe(48)
    client_secret_hash = hash_client_secret(client_secret)

    # Store client in hass.data
    if "clients" not in hass.data[DOMAIN]:
        hass.data[DOMAIN]["clients"] = {}

    hass.data[DOMAIN]["clients"][client_id] = {
        "client_name": client_name,
        "client_secret_hash": client_secret_hash,
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "response_types": response_types,
        "token_endpoint_auth_method": token_endpoint_auth_method,
    }

    # Persist to storage
    store = hass.data[DOMAIN]["store"]
    await store.async_save({"clients": hass.data[DOMAIN]["clients"]})

    _LOGGER.info("Registered client: %s (%s)", client_name, client_id)

    # Return client information including the plain text secret
    # (only time it's available)
    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "response_types": response_types,
        "token_endpoint_auth_method": token_endpoint_auth_method,
    }
