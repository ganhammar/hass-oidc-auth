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
        try:
            import secrets

            _LOGGER.debug("handle_register_client called with data: %s", call.data)

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

            # Create persistent notification with credentials
            hass.components.persistent_notification.async_create(
                f"**OIDC Client Registered: {client_name}**\n\n"
                f"**Client ID:** `{client_id}`\n\n"
                f"**Client Secret:** `{client_secret}`\n\n"
                f"**Redirect URIs:** {', '.join(redirect_uris)}\n\n"
                f"⚠️ **Important:** Save these credentials now. "
                f"The client secret cannot be retrieved later.",
                title="OIDC Client Registered",
                notification_id=f"oidc_client_{client_id}",
            )

            _LOGGER.info(
                "Registered OIDC client: %s | Client ID: %s | Client Secret: %s | Redirect URIs: %s",
                client_name,
                client_id,
                client_secret,
                redirect_uris,
            )
        except Exception as e:
            _LOGGER.error("Error registering OIDC client: %s", e, exc_info=True)

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
