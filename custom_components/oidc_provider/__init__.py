"""OIDC Provider integration for Home Assistant."""

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

DOMAIN = "oidc_provider"


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the OIDC Provider component."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up OIDC Provider from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    # Store clients and tokens
    hass.data[DOMAIN]["clients"] = {}
    hass.data[DOMAIN]["authorization_codes"] = {}
    hass.data[DOMAIN]["refresh_tokens"] = {}

    # Register HTTP endpoints
    from .http import setup_http_endpoints

    setup_http_endpoints(hass)

    # Register services
    async def handle_register_client(call):
        """Handle register_client service."""
        import secrets

        client_name = call.data.get("client_name")
        redirect_uris = call.data.get("redirect_uris", "").split(",")
        redirect_uris = [uri.strip() for uri in redirect_uris if uri.strip()]

        client_id = f"client_{secrets.token_urlsafe(16)}"
        client_secret = secrets.token_urlsafe(32)

        hass.data[DOMAIN]["clients"][client_id] = {
            "client_name": client_name,
            "client_secret": client_secret,
            "redirect_uris": redirect_uris,
        }

        _LOGGER.info(
            f"Registered OIDC client: {client_name}\n"
            f"Client ID: {client_id}\n"
            f"Client Secret: {client_secret}\n"
            f"Redirect URIs: {redirect_uris}"
        )

    async def handle_revoke_client(call):
        """Handle revoke_client service."""
        client_id = call.data.get("client_id")

        if client_id in hass.data[DOMAIN]["clients"]:
            del hass.data[DOMAIN]["clients"][client_id]
            _LOGGER.info(f"Revoked OIDC client: {client_id}")
        else:
            _LOGGER.warning(f"Client ID not found: {client_id}")

    hass.services.async_register(DOMAIN, "register_client", handle_register_client)
    hass.services.async_register(DOMAIN, "revoke_client", handle_revoke_client)

    _LOGGER.info("OIDC Provider initialized")
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    hass.data[DOMAIN].clear()
    return True
