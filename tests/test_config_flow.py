"""Test config flow for OIDC Provider integration."""

from unittest.mock import Mock, patch

from homeassistant import data_entry_flow

from custom_components.oidc_provider.config_flow import (
    OIDCProviderConfigFlow,
    OIDCProviderOptionsFlow,
)


class TestOIDCProviderConfigFlow:
    """Test the OIDC Provider config flow."""

    async def test_user_flow_creates_entry(self):
        """Test user flow creates config entry."""
        # Create mock hass
        mock_hass = Mock()
        mock_hass.config_entries = Mock()
        mock_hass.config_entries.async_entries = Mock(return_value=[])

        flow = OIDCProviderConfigFlow()
        flow.hass = mock_hass

        result = await flow.async_step_user(user_input={})

        assert result["type"] == data_entry_flow.FlowResultType.CREATE_ENTRY
        assert result["title"] == "OIDC Provider"
        assert result["data"] == {}

    async def test_user_flow_shows_form_when_no_input(self):
        """Test user flow shows form when no input provided."""
        # Create mock hass
        mock_hass = Mock()
        mock_hass.config_entries = Mock()
        mock_hass.config_entries.async_entries = Mock(return_value=[])

        flow = OIDCProviderConfigFlow()
        flow.hass = mock_hass

        result = await flow.async_step_user(user_input=None)

        assert result["type"] == data_entry_flow.FlowResultType.FORM
        assert result["step_id"] == "user"
        assert result["data_schema"] is not None

    async def test_single_instance_allowed(self):
        """Test only single instance is allowed."""
        # Create mock hass with existing entry
        mock_hass = Mock()
        mock_entry = Mock()
        mock_hass.config_entries = Mock()
        mock_hass.config_entries.async_entries = Mock(return_value=[mock_entry])

        flow = OIDCProviderConfigFlow()
        flow.hass = mock_hass

        result = await flow.async_step_user(user_input={})

        assert result["type"] == data_entry_flow.FlowResultType.ABORT
        assert result["reason"] == "single_instance_allowed"

    async def test_version_is_set(self):
        """Test config flow version is set."""
        flow = OIDCProviderConfigFlow()
        assert flow.VERSION == 1

    def test_async_get_options_flow_returns_options_flow(self):
        """Test async_get_options_flow returns options flow instance."""
        with patch.object(OIDCProviderOptionsFlow, "__init__", return_value=None):
            mock_config_entry = Mock()
            options_flow = OIDCProviderConfigFlow.async_get_options_flow(mock_config_entry)

            assert isinstance(options_flow, OIDCProviderOptionsFlow)

    async def test_user_flow_form_has_empty_schema(self):
        """Test user flow form has empty data schema."""
        # Create mock hass
        mock_hass = Mock()
        mock_hass.config_entries = Mock()
        mock_hass.config_entries.async_entries = Mock(return_value=[])

        flow = OIDCProviderConfigFlow()
        flow.hass = mock_hass

        result = await flow.async_step_user(user_input=None)

        # Verify the schema is empty (no user input required)
        assert result["data_schema"].schema == {}


class TestOIDCProviderOptionsFlow:
    """Test the OIDC Provider options flow."""

    async def test_init_step_shows_form(self):
        """Test init step shows form."""
        mock_config_entry = Mock()
        # Use internal _config_entry attribute to avoid deprecated setter
        flow = OIDCProviderOptionsFlow.__new__(OIDCProviderOptionsFlow)
        flow._config_entry = mock_config_entry

        result = await flow.async_step_init(user_input=None)

        assert result["type"] == data_entry_flow.FlowResultType.FORM
        assert result["step_id"] == "init"

    async def test_init_step_with_user_input_shows_form(self):
        """Test init step with user input still shows form."""
        mock_config_entry = Mock()
        # Use internal _config_entry attribute to avoid deprecated setter
        flow = OIDCProviderOptionsFlow.__new__(OIDCProviderOptionsFlow)
        flow._config_entry = mock_config_entry

        result = await flow.async_step_init(user_input={})

        # The current implementation just shows the form regardless of input
        assert result["type"] == data_entry_flow.FlowResultType.FORM
        assert result["step_id"] == "init"

    async def test_init_step_does_not_update_options(self):
        """Test init step does not update config entry options."""
        mock_config_entry = Mock()
        mock_config_entry.options = {"existing": "option"}

        # Use internal _config_entry attribute to avoid deprecated setter
        flow = OIDCProviderOptionsFlow.__new__(OIDCProviderOptionsFlow)
        flow._config_entry = mock_config_entry

        result = await flow.async_step_init(user_input={"new": "value"})

        # Verify it shows form, not create_entry
        assert result["type"] == data_entry_flow.FlowResultType.FORM
        # Options should not be modified
        assert mock_config_entry.options == {"existing": "option"}
