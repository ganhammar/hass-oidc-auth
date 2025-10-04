"""Test constants."""


def test_constants():
    """Test constants are defined correctly."""
    # Import constants directly to avoid HA dependency chain
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "const", Path(__file__).parent.parent / "custom_components" / "oidc_provider" / "const.py"
    )
    const = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(const)

    assert const.DOMAIN == "oidc_provider"
    assert const.ACCESS_TOKEN_EXPIRY == 3600
    assert const.REFRESH_TOKEN_EXPIRY == 2592000
    assert const.AUTHORIZATION_CODE_EXPIRY == 600
    assert const.SCOPE_OPENID in const.SUPPORTED_SCOPES
    assert const.SCOPE_PROFILE in const.SUPPORTED_SCOPES
    assert const.SCOPE_EMAIL in const.SUPPORTED_SCOPES
