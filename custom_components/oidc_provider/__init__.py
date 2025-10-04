"""OIDC Provider integration for Home Assistant."""

import logging

from homeassistant.components.frontend import async_register_built_in_panel
from homeassistant.components.http import StaticPathConfig
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .http import setup_http_endpoints

_LOGGER = logging.getLogger(__name__)

DOMAIN = "oidc_provider"
STORAGE_VERSION = 1
STORAGE_KEY = f"{DOMAIN}.clients"


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the OIDC Provider component."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up OIDC Provider from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    # Initialize storage
    store = Store(hass, STORAGE_VERSION, STORAGE_KEY)
    stored_data = await store.async_load()

    # Store clients and tokens
    hass.data[DOMAIN]["clients"] = stored_data.get("clients", {}) if stored_data else {}
    hass.data[DOMAIN]["authorization_codes"] = {}
    hass.data[DOMAIN]["refresh_tokens"] = {}
    hass.data[DOMAIN]["store"] = store

    # Register HTTP endpoints
    setup_http_endpoints(hass)

    # Register static path for panel JS
    await hass.http.async_register_static_paths(
        [
            StaticPathConfig(
                "/oidc_provider",
                str(hass.config.path(f"custom_components/{DOMAIN}/www")),
                cache_headers=False,
            )
        ]
    )

    # Register frontend panel for OIDC auth flow
    async_register_built_in_panel(
        hass,
        component_name="custom",
        sidebar_title="OIDC Login",
        sidebar_icon="mdi:login",
        frontend_url_path="oidc_login",
        config={
            "_panel_custom": {
                "name": "oidc-login-panel",
                "embed_iframe": False,
                "js_url": "/oidc_provider/oidc-login-panel.js",
            }
        },
        require_admin=False,
    )

    # Register services
    async def handle_register_client(call):
        """Handle register_client service."""
        try:
            import secrets

            _LOGGER.debug("handle_register_client called with data: %s", call.data)

            client_name = call.data.get("client_name")
            redirect_uris = call.data.get("redirect_uris", "").split(",")
            redirect_uris = [uri.strip() for uri in redirect_uris if uri.strip()]

            # Check if client with same name already exists
            existing_clients = hass.data[DOMAIN].get("clients", {})
            for existing_client in existing_clients.values():
                if existing_client["client_name"] == client_name:
                    error_msg = f"Client with name '{client_name}' already exists"
                    _LOGGER.error(error_msg)
                    await hass.services.async_call(
                        "persistent_notification",
                        "create",
                        {
                            "title": "OIDC Client Registration Failed",
                            "message": f"❌ {error_msg}\n\nPlease choose a different client name.",
                            "notification_id": f"oidc_client_error_{client_name}",
                        },
                    )
                    return

            client_id = f"client_{secrets.token_urlsafe(16)}"
            client_secret = secrets.token_urlsafe(32)

            hass.data[DOMAIN]["clients"][client_id] = {
                "client_name": client_name,
                "client_secret": client_secret,
                "redirect_uris": redirect_uris,
            }

            # Save to storage
            store = hass.data[DOMAIN]["store"]
            await store.async_save({"clients": hass.data[DOMAIN]["clients"]})

            # Create persistent notification with credentials
            try:
                await hass.services.async_call(
                    "persistent_notification",
                    "create",
                    {
                        "title": "OIDC Client Registered",
                        "message": (
                            f"**OIDC Client Registered: {client_name}**\n\n"
                            f"**Client ID:** `{client_id}`\n\n"
                            f"**Client Secret:** `{client_secret}`\n\n"
                            f"**Redirect URIs:** {', '.join(redirect_uris)}\n\n"
                            f"⚠️ **Important:** Save these credentials now. "
                            f"The client secret cannot be retrieved later."
                        ),
                        "notification_id": f"oidc_client_{client_id}",
                    },
                )
                _LOGGER.info("Notification created for client registration")
            except Exception as notif_error:
                _LOGGER.error("Failed to create notification: %s", notif_error)

            _LOGGER.info(
                "Registered OIDC client: %s | Client ID: %s | Client Secret: %s | "
                "Redirect URIs: %s",
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

            # Save to storage
            store = hass.data[DOMAIN]["store"]
            await store.async_save({"clients": hass.data[DOMAIN]["clients"]})

            _LOGGER.info(f"Revoked OIDC client: {client_id}")
        else:
            _LOGGER.warning(f"Client ID not found: {client_id}")

    async def handle_update_client(call):
        """Handle update_client service."""
        client_id = call.data.get("client_id")
        redirect_uris_input = call.data.get("redirect_uris", "")
        redirect_uris = [uri.strip() for uri in redirect_uris_input.split(",") if uri.strip()]

        if client_id not in hass.data[DOMAIN]["clients"]:
            error_msg = f"Client ID '{client_id}' not found"
            _LOGGER.error(error_msg)
            await hass.services.async_call(
                "persistent_notification",
                "create",
                {
                    "title": "OIDC Client Update Failed",
                    "message": f"❌ {error_msg}",
                    "notification_id": f"oidc_update_error_{client_id}",
                },
            )
            return

        # Update redirect URIs
        hass.data[DOMAIN]["clients"][client_id]["redirect_uris"] = redirect_uris

        # Save to storage
        store = hass.data[DOMAIN]["store"]
        await store.async_save({"clients": hass.data[DOMAIN]["clients"]})

        client_name = hass.data[DOMAIN]["clients"][client_id]["client_name"]

        await hass.services.async_call(
            "persistent_notification",
            "create",
            {
                "title": "OIDC Client Updated",
                "message": (
                    f"**Updated Client: {client_name}**\n\n"
                    f"**Client ID:** `{client_id}`\n\n"
                    f"**New Redirect URIs:** {', '.join(redirect_uris)}"
                ),
                "notification_id": f"oidc_update_{client_id}",
            },
        )
        _LOGGER.info("Updated OIDC client: %s with new redirect URIs: %s", client_id, redirect_uris)

    async def handle_list_clients(call):
        """Handle list_clients service."""
        clients = hass.data[DOMAIN].get("clients", {})

        if not clients:
            await hass.services.async_call(
                "persistent_notification",
                "create",
                {
                    "title": "OIDC Registered Clients",
                    "message": "No clients registered.",
                    "notification_id": "oidc_list_clients",
                },
            )
            return

        message_parts = ["**Registered OIDC Clients:**\n"]
        for client_id, client_data in clients.items():
            message_parts.append(
                f"\n**{client_data['client_name']}**\n"
                f"- Client ID: `{client_id}`\n"
                f"- Redirect URIs: {', '.join(client_data['redirect_uris'])}\n"
                f"- ⚠️ Client Secret: Hidden (cannot be retrieved)\n"
            )

        await hass.services.async_call(
            "persistent_notification",
            "create",
            {
                "title": "OIDC Registered Clients",
                "message": "\n".join(message_parts),
                "notification_id": "oidc_list_clients",
            },
        )
        _LOGGER.info("Listed %d OIDC clients", len(clients))

    hass.services.async_register(DOMAIN, "register_client", handle_register_client)
    hass.services.async_register(DOMAIN, "revoke_client", handle_revoke_client)
    hass.services.async_register(DOMAIN, "update_client", handle_update_client)
    hass.services.async_register(DOMAIN, "list_clients", handle_list_clients)

    _LOGGER.info("OIDC Provider initialized")
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    hass.data[DOMAIN].clear()
    return True
