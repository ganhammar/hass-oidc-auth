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

# PKCE code challenge methods
CODE_CHALLENGE_METHOD_S256 = "S256"
CODE_CHALLENGE_METHOD_PLAIN = "plain"
SUPPORTED_CODE_CHALLENGE_METHODS = [CODE_CHALLENGE_METHOD_S256]

# Rate limiting
MAX_TOKEN_ATTEMPTS = 5  # Maximum failed attempts before rate limiting
RATE_LIMIT_WINDOW = 300  # 5 minutes in seconds
RATE_LIMIT_PENALTY = 60  # Lockout period in seconds after max attempts

# PKCE enforcement
DEFAULT_REQUIRE_PKCE = True  # Default to required for security (OAuth 2.1 compliance)
CONF_REQUIRE_PKCE = "require_pkce"
