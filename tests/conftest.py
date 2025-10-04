"""Pytest configuration and fixtures."""

import pytest
from unittest.mock import Mock, AsyncMock, MagicMock
from aiohttp.test_utils import TestClient


@pytest.fixture
def mock_hass():
    """Create a mock Home Assistant instance."""
    hass = Mock()
    hass.data = {}
    hass.http = Mock()
    hass.http.register_view = Mock()
    hass.services = Mock()
    hass.services.async_register = AsyncMock()
    return hass


@pytest.fixture
def mock_user():
    """Create a mock user."""
    user = Mock()
    user.id = "test_user_id"
    user.name = "Test User"
    return user


@pytest.fixture
def mock_config_entry():
    """Create a mock config entry."""
    entry = Mock()
    entry.data = {}
    return entry
