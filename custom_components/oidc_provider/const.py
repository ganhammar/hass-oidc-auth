"""Constants for the OIDC Provider integration."""

DOMAIN = "oidc_provider"

# Token expiry times (in seconds)
ACCESS_TOKEN_EXPIRY = 3600  # 1 hour
REFRESH_TOKEN_EXPIRY = 2592000  # 30 days
AUTHORIZATION_CODE_EXPIRY = 600  # 10 minutes

# OIDC scopes
SCOPE_OPENID = "openid"
SCOPE_PROFILE = "profile"
SCOPE_EMAIL = "email"

SUPPORTED_SCOPES = [SCOPE_OPENID, SCOPE_PROFILE, SCOPE_EMAIL]

# Grant types
GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code"
GRANT_TYPE_REFRESH_TOKEN = "refresh_token"

# Response types
RESPONSE_TYPE_CODE = "code"
