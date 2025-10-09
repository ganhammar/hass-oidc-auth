"""Config flow for OIDC Provider integration."""

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback

from .const import CONF_REQUIRE_PKCE, DEFAULT_REQUIRE_PKCE, DOMAIN


class OIDCProviderConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for OIDC Provider."""

    VERSION = 1

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")

        if user_input is not None:
            return self.async_create_entry(
                title="OIDC Provider",
                data=user_input,
            )

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({}),
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Get the options flow for this handler."""
        return OIDCProviderOptionsFlow()


class OIDCProviderOptionsFlow(config_entries.OptionsFlow):
    """Handle options flow for OIDC Provider."""

    async def async_step_init(self, user_input=None):
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        # Get current options, defaulting to empty dict if None
        options = self.config_entry.options or {}

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_REQUIRE_PKCE,
                        default=options.get(CONF_REQUIRE_PKCE, DEFAULT_REQUIRE_PKCE),
                    ): bool,
                }
            ),
        )
