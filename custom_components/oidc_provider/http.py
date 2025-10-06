"""HTTP endpoints for OIDC Provider."""

import base64
import hashlib
import html
import logging
import secrets
import time
from typing import Any

import jwt
from aiohttp import web
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant

from .client_manager import create_client
from .const import (
    ACCESS_TOKEN_EXPIRY,
    AUTHORIZATION_CODE_EXPIRY,
    CODE_CHALLENGE_METHOD_S256,
    DOMAIN,
    GRANT_TYPE_AUTHORIZATION_CODE,
    GRANT_TYPE_REFRESH_TOKEN,
    MAX_TOKEN_ATTEMPTS,
    RATE_LIMIT_PENALTY,
    RATE_LIMIT_WINDOW,
    REFRESH_TOKEN_EXPIRY,
    RESPONSE_TYPE_CODE,
    SUPPORTED_CODE_CHALLENGE_METHODS,
    SUPPORTED_SCOPES,
)
from .security import verify_client_secret

_LOGGER = logging.getLogger(__name__)


def _get_base_url(request: web.Request) -> str:
    """Get base URL from request, respecting X-Forwarded headers if present."""
    # Check for X-Forwarded headers (proxy setup)
    forwarded_proto = request.headers.get("X-Forwarded-Proto")
    forwarded_host = request.headers.get("X-Forwarded-Host")

    if forwarded_proto and forwarded_host:
        # Use forwarded headers from proxy
        return f"{forwarded_proto}://{forwarded_host}"
    else:
        # Direct connection, use request URL
        return str(request.url.origin())


def setup_http_endpoints(hass: HomeAssistant) -> None:
    """Set up the OIDC HTTP endpoints."""
    # Generate RSA key pair for JWT signing
    if "jwt_private_key" not in hass.data[DOMAIN]:
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        hass.data[DOMAIN]["jwt_private_key"] = private_key
        hass.data[DOMAIN]["jwt_public_key"] = private_key.public_key()

    # Initialize rate limiting storage
    if "rate_limit_attempts" not in hass.data[DOMAIN]:
        hass.data[DOMAIN]["rate_limit_attempts"] = {}

    # Register views
    hass.http.register_view(OIDCDiscoveryView())
    hass.http.register_view(OAuth2AuthorizationServerMetadataView())
    hass.http.register_view(OIDCAuthorizationView())
    hass.http.register_view(OIDCContinueView())
    hass.http.register_view(OIDCTokenView())
    hass.http.register_view(OIDCUserInfoView())
    hass.http.register_view(OIDCJWKSView())
    hass.http.register_view(OIDCRegisterView())


class OIDCContinueView(HomeAssistantView):
    """OIDC Continue view - requires auth, retrieves stored request, generates code."""

    url = "/oidc/continue"
    name = "api:oidc:continue"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        """Handle continuation after authentication."""
        hass = request.app["hass"]
        user = request["hass_user"]

        # Get request ID from query or session storage will pass it
        request_id = request.query.get("request_id")
        if not request_id:
            return web.Response(text="Missing request_id", status=400)

        pending_requests = hass.data[DOMAIN].get("pending_auth_requests", {})
        if request_id not in pending_requests:
            return web.Response(text="Invalid or expired request", status=400)

        stored_request = pending_requests[request_id]
        if stored_request["expires_at"] < time.time():
            del pending_requests[request_id]
            return web.Response(text="Request expired", status=400)

        # Extract parameters
        client_id = stored_request["client_id"]
        redirect_uri = stored_request["redirect_uri"]
        scope = stored_request["scope"]
        state = stored_request["state"]
        code_challenge = stored_request.get("code_challenge")
        code_challenge_method = stored_request.get("code_challenge_method")

        # Clean up
        del pending_requests[request_id]

        # Generate authorization code
        auth_code = secrets.token_urlsafe(32)
        hass.data[DOMAIN]["authorization_codes"][auth_code] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "user_id": user.id,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "expires_at": time.time() + AUTHORIZATION_CODE_EXPIRY,
        }

        # Build redirect URL
        separator = "&" if "?" in redirect_uri else "?"
        redirect_url = f"{redirect_uri}{separator}code={auth_code}"
        if state:
            redirect_url += f"&state={state}"

        # Return JSON with redirect URL (since fetch can't follow external redirects)
        return web.json_response({"redirect_url": redirect_url})


class OIDCDiscoveryView(HomeAssistantView):
    """OIDC Discovery endpoint."""

    url = "/oidc/.well-known/openid-configuration"
    name = "api:oidc:discovery"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Handle discovery request."""
        base_url = _get_base_url(request)

        discovery = {
            "issuer": base_url,
            "authorization_endpoint": f"{base_url}/oidc/authorize",
            "token_endpoint": f"{base_url}/oidc/token",
            "userinfo_endpoint": f"{base_url}/oidc/userinfo",
            "jwks_uri": f"{base_url}/oidc/jwks",
            "registration_endpoint": f"{base_url}/oidc/register",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": SUPPORTED_SCOPES,
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
            ],
            "claims_supported": [
                "sub",
                "name",
                "email",
                "iss",
                "aud",
                "exp",
                "iat",
            ],
            "code_challenge_methods_supported": SUPPORTED_CODE_CHALLENGE_METHODS,
        }

        return web.json_response(discovery)


class OAuth2AuthorizationServerMetadataView(HomeAssistantView):
    """OAuth 2.0 Authorization Server Metadata endpoint (RFC 8414)."""

    url = "/.well-known/oauth-authorization-server/oidc"
    name = "api:oauth:as-metadata"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Handle OAuth 2.0 Authorization Server Metadata request."""
        base_url = _get_base_url(request)

        metadata = {
            "issuer": base_url,
            "authorization_endpoint": f"{base_url}/oidc/authorize",
            "token_endpoint": f"{base_url}/oidc/token",
            "registration_endpoint": f"{base_url}/oidc/register",
            "jwks_uri": f"{base_url}/oidc/jwks",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
            ],
            "code_challenge_methods_supported": SUPPORTED_CODE_CHALLENGE_METHODS,
            "scopes_supported": SUPPORTED_SCOPES,
        }

        return web.json_response(metadata)


class OIDCAuthorizationView(HomeAssistantView):
    """OIDC Authorization endpoint."""

    url = "/oidc/authorize"
    name = "api:oidc:authorize"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Handle authorization request."""
        hass = request.app["hass"]

        # Extract parameters from query string
        client_id = request.query.get("client_id")
        redirect_uri = request.query.get("redirect_uri")
        response_type = request.query.get("response_type")
        scope = request.query.get("scope", "")
        state = request.query.get("state", "")
        code_challenge = request.query.get("code_challenge")
        code_challenge_method = request.query.get(
            "code_challenge_method", CODE_CHALLENGE_METHOD_S256
        )

        # Validate parameters
        if not client_id or not redirect_uri or response_type != RESPONSE_TYPE_CODE:
            return web.Response(text="Invalid request", status=400)

        # Validate PKCE parameters
        if code_challenge:
            if code_challenge_method not in SUPPORTED_CODE_CHALLENGE_METHODS:
                supported = ", ".join(SUPPORTED_CODE_CHALLENGE_METHODS)
                return web.Response(
                    text=f"Unsupported code_challenge_method. Supported: {supported}",
                    status=400,
                )

        clients = hass.data[DOMAIN].get("clients", {})

        if client_id not in clients:
            return web.Response(text="Invalid client_id", status=400)

        client = clients[client_id]
        if redirect_uri not in client["redirect_uris"]:
            return web.Response(text="Invalid redirect_uri", status=400)

        # Store request and redirect to frontend panel (which requires auth)
        auth_request_id = secrets.token_urlsafe(16)

        # Store the authorization request parameters
        if "pending_auth_requests" not in hass.data[DOMAIN]:
            hass.data[DOMAIN]["pending_auth_requests"] = {}

        # Clean up expired pending requests
        current_time = time.time()
        expired_ids = [
            req_id
            for req_id, req_data in hass.data[DOMAIN]["pending_auth_requests"].items()
            if req_data["expires_at"] < current_time
        ]
        for req_id in expired_ids:
            del hass.data[DOMAIN]["pending_auth_requests"][req_id]

        hass.data[DOMAIN]["pending_auth_requests"][auth_request_id] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "expires_at": time.time() + 600,  # 10 minutes
        }

        # Return HTML that stores request ID in sessionStorage and redirects to panel
        # Note: auth_request_id is a cryptographically secure token, but we still escape it
        escaped_request_id = html.escape(auth_request_id)
        redirect_script = f"""
        <html>
        <head><title>OIDC Authorization</title></head>
        <body>
            <p>Redirecting to login...</p>
            <script>
                sessionStorage.setItem('oidc_request_id', '{escaped_request_id}');
                window.location.href = '/oidc_login';
            </script>
        </body>
        </html>
        """
        return web.Response(
            text=redirect_script,
            content_type="text/html",
        )


class OIDCTokenView(HomeAssistantView):
    """OIDC Token endpoint."""

    url = "/oidc/token"
    name = "api:oidc:token"
    requires_auth = False

    async def post(self, request: web.Request) -> web.Response:
        """Handle token request."""
        hass = request.app["hass"]
        data = await request.post()

        grant_type = data.get("grant_type")

        # Extract client credentials from either POST data or Authorization header
        client_id = data.get("client_id")
        client_secret = data.get("client_secret")

        # Check for HTTP Basic authentication
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Basic "):
            try:
                # Decode Basic auth credentials
                credentials = base64.b64decode(auth_header[6:]).decode("utf-8")
                client_id, client_secret = credentials.split(":", 1)
            except Exception as e:
                _LOGGER.warning("Invalid Basic auth header: %s", e)
                return web.json_response({"error": "invalid_client"}, status=401)

        # Check rate limiting
        rate_limit_key = f"{client_id}:{request.remote}"
        rate_limits = hass.data[DOMAIN]["rate_limit_attempts"]
        current_time = time.time()

        # Clean up old rate limit entries
        expired_keys = [
            key
            for key, data in rate_limits.items()
            if data["window_start"] < current_time - RATE_LIMIT_WINDOW
        ]
        for key in expired_keys:
            del rate_limits[key]

        # Check if client is rate limited
        if rate_limit_key in rate_limits:
            limit_data = rate_limits[rate_limit_key]
            if limit_data.get("locked_until", 0) > current_time:
                _LOGGER.warning(
                    "Rate limit active for client %s from %s", client_id, request.remote
                )
                return web.json_response(
                    {
                        "error": "invalid_client",
                        "error_description": "Too many failed attempts. Please try again later.",
                    },
                    status=429,
                )

        # Validate client
        clients = hass.data[DOMAIN].get("clients", {})
        if client_id not in clients:
            self._record_failed_attempt(hass, rate_limit_key, current_time)
            return web.json_response({"error": "invalid_client"}, status=401)

        client = clients[client_id]
        # Verify client secret using constant-time comparison
        # Support both old (plain) and new (hashed) client secrets for backward compatibility
        if "client_secret_hash" in client:
            # New hashed format
            if not verify_client_secret(client_secret, client["client_secret_hash"]):
                _LOGGER.warning("Invalid client secret for client %s", client_id)
                self._record_failed_attempt(hass, rate_limit_key, current_time)
                return web.json_response({"error": "invalid_client"}, status=401)
        elif "client_secret" in client:
            # Old plain text format (backward compatibility)
            if client["client_secret"] != client_secret:
                _LOGGER.warning("Invalid client secret for client %s (legacy)", client_id)
                self._record_failed_attempt(hass, rate_limit_key, current_time)
                return web.json_response({"error": "invalid_client"}, status=401)
        else:
            _LOGGER.error("Client %s has no secret configured", client_id)
            self._record_failed_attempt(hass, rate_limit_key, current_time)
            return web.json_response({"error": "invalid_client"}, status=401)

        # Successful authentication - clear rate limit
        if rate_limit_key in rate_limits:
            del rate_limits[rate_limit_key]

        if grant_type == GRANT_TYPE_AUTHORIZATION_CODE:
            return await self._handle_authorization_code(request, hass, data)
        elif grant_type == GRANT_TYPE_REFRESH_TOKEN:
            return await self._handle_refresh_token(request, hass, data)
        else:
            return web.json_response({"error": "unsupported_grant_type"}, status=400)

    def _record_failed_attempt(
        self, hass: HomeAssistant, rate_limit_key: str, current_time: float
    ) -> None:
        """Record a failed authentication attempt for rate limiting."""
        rate_limits = hass.data[DOMAIN]["rate_limit_attempts"]

        if rate_limit_key not in rate_limits:
            rate_limits[rate_limit_key] = {
                "attempts": 1,
                "window_start": current_time,
            }
        else:
            rate_limits[rate_limit_key]["attempts"] += 1

        # Check if we've exceeded max attempts
        if rate_limits[rate_limit_key]["attempts"] >= MAX_TOKEN_ATTEMPTS:
            rate_limits[rate_limit_key]["locked_until"] = current_time + RATE_LIMIT_PENALTY
            _LOGGER.warning(
                "Rate limit triggered for %s - locked for %d seconds",
                rate_limit_key,
                RATE_LIMIT_PENALTY,
            )

    async def _handle_authorization_code(
        self, _request: web.Request, hass: HomeAssistant, data: Any
    ) -> web.Response:
        """Handle authorization code grant."""
        code = data.get("code")
        redirect_uri = data.get("redirect_uri")
        code_verifier = data.get("code_verifier")

        auth_codes = hass.data[DOMAIN]["authorization_codes"]
        if code not in auth_codes:
            return web.json_response({"error": "invalid_grant"}, status=400)

        auth_data = auth_codes[code]

        # Validate authorization code
        if auth_data["expires_at"] < time.time():
            del auth_codes[code]
            return web.json_response({"error": "invalid_grant"}, status=400)

        if auth_data["redirect_uri"] != redirect_uri:
            return web.json_response({"error": "invalid_grant"}, status=400)

        # Validate PKCE code_verifier if code_challenge was provided
        code_challenge = auth_data.get("code_challenge")
        if code_challenge:
            if not code_verifier:
                del auth_codes[code]
                return web.json_response(
                    {"error": "invalid_grant", "error_description": "code_verifier required"},
                    status=400,
                )

            try:
                # Verify code_verifier matches code_challenge
                code_challenge_method = auth_data.get(
                    "code_challenge_method", CODE_CHALLENGE_METHOD_S256
                )
                if code_challenge_method == CODE_CHALLENGE_METHOD_S256:
                    # Compute SHA256 hash of code_verifier
                    verifier_hash = hashlib.sha256(code_verifier.encode("ascii")).digest()
                    computed_challenge = (
                        base64.urlsafe_b64encode(verifier_hash).decode("ascii").rstrip("=")
                    )
                else:
                    # Plain method (not recommended, but included for spec compliance)
                    computed_challenge = code_verifier

                if computed_challenge != code_challenge:
                    del auth_codes[code]
                    _LOGGER.warning(
                        "PKCE verification failed for client %s - expected %s, got %s",
                        auth_data["client_id"],
                        code_challenge,
                        computed_challenge,
                    )
                    return web.json_response(
                        {"error": "invalid_grant", "error_description": "Invalid code_verifier"},
                        status=400,
                    )
            except Exception as e:
                del auth_codes[code]
                _LOGGER.error("Error verifying PKCE: %s", str(e), exc_info=True)
                return web.json_response(
                    {"error": "invalid_grant", "error_description": "PKCE verification error"},
                    status=400,
                )

        # Generate tokens
        user_id = auth_data["user_id"]
        scope = auth_data["scope"]

        access_token = self._generate_access_token(hass, user_id, scope, data.get("client_id"))
        refresh_token = secrets.token_urlsafe(32)

        # Store refresh token
        hass.data[DOMAIN]["refresh_tokens"][refresh_token] = {
            "user_id": user_id,
            "client_id": data.get("client_id"),
            "scope": scope,
            "expires_at": time.time() + REFRESH_TOKEN_EXPIRY,
        }

        # Delete used authorization code
        del auth_codes[code]

        return web.json_response(
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_EXPIRY,
                "refresh_token": refresh_token,
                "scope": scope,
            }
        )

    async def _handle_refresh_token(
        self, _request: web.Request, hass: HomeAssistant, data: Any
    ) -> web.Response:
        """Handle refresh token grant."""
        refresh_token = data.get("refresh_token")

        refresh_tokens = hass.data[DOMAIN]["refresh_tokens"]
        if refresh_token not in refresh_tokens:
            return web.json_response({"error": "invalid_grant"}, status=400)

        token_data = refresh_tokens[refresh_token]

        # Validate refresh token
        if token_data["expires_at"] < time.time():
            del refresh_tokens[refresh_token]
            return web.json_response({"error": "invalid_grant"}, status=400)

        if token_data["client_id"] != data.get("client_id"):
            return web.json_response({"error": "invalid_grant"}, status=400)

        # Generate new access token
        access_token = self._generate_access_token(
            hass, token_data["user_id"], token_data["scope"], data.get("client_id")
        )

        return web.json_response(
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_EXPIRY,
                "scope": token_data["scope"],
            }
        )

    def _generate_access_token(
        self, hass: HomeAssistant, user_id: str, scope: str, client_id: str
    ) -> str:
        """Generate JWT access token."""
        now = int(time.time())

        payload = {
            "sub": user_id,
            "iat": now,
            "exp": now + ACCESS_TOKEN_EXPIRY,
            "iss": "home-assistant",
            "aud": client_id,
            "scope": scope,
        }

        private_key = hass.data[DOMAIN]["jwt_private_key"]
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return jwt.encode(payload, private_pem, algorithm="RS256")


class OIDCUserInfoView(HomeAssistantView):
    """OIDC UserInfo endpoint."""

    url = "/oidc/userinfo"
    name = "api:oidc:userinfo"
    requires_auth = False  # We'll validate the JWT ourselves

    async def get(self, request: web.Request) -> web.Response:
        """Handle userinfo request."""
        hass = request.app["hass"]

        # Get the access token from Authorization header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return web.json_response({"error": "unauthorized"}, status=401)

        access_token = auth_header[7:]  # Remove "Bearer " prefix

        try:
            # Verify and decode the JWT
            public_key = hass.data[DOMAIN]["jwt_public_key"]
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            # Decode and verify the JWT
            # We don't verify audience here because different clients may use the token
            # The audience is set to the client_id when the token is created
            payload = jwt.decode(
                access_token,
                public_pem,
                algorithms=["RS256"],
                options={
                    "verify_aud": False,  # We could verify but would need to know the client_id
                    "verify_signature": True,
                    "verify_exp": True,
                },
            )

            # Extract user info from JWT
            user_id = payload.get("sub")
            if not user_id:
                return web.json_response({"error": "invalid_token"}, status=401)

            # Get user from Home Assistant
            user = await hass.auth.async_get_user(user_id)
            if not user:
                return web.json_response({"error": "user_not_found"}, status=404)

            return web.json_response(
                {
                    "sub": user.id,
                    "name": user.name,
                    "email": user.id,  # HA doesn't store email, use ID as fallback
                }
            )
        except jwt.ExpiredSignatureError:
            _LOGGER.error("Token expired")
            return web.json_response({"error": "token_expired"}, status=401)
        except jwt.InvalidTokenError as e:
            _LOGGER.error("Invalid token: %s", str(e))
            return web.json_response({"error": "invalid_token", "detail": str(e)}, status=401)
        except Exception as e:
            _LOGGER.error("Unexpected error validating token: %s", str(e), exc_info=True)
            return web.json_response({"error": "internal_error"}, status=500)


class OIDCJWKSView(HomeAssistantView):
    """OIDC JWKS (JSON Web Key Set) endpoint."""

    url = "/oidc/jwks"
    name = "api:oidc:jwks"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Handle JWKS request."""
        hass = request.app["hass"]
        public_key = hass.data[DOMAIN]["jwt_public_key"]

        # Get the public key numbers
        public_numbers = public_key.public_numbers()

        # Convert modulus (n) and exponent (e) to base64url format
        def int_to_base64url(value: int) -> str:
            """Convert integer to base64url-encoded string."""
            # Convert to bytes (big-endian)
            value_bytes = value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")
            # Base64url encode (no padding)
            return base64.urlsafe_b64encode(value_bytes).decode("utf-8").rstrip("=")

        jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "1",
                    "alg": "RS256",
                    "n": int_to_base64url(public_numbers.n),  # Modulus
                    "e": int_to_base64url(public_numbers.e),  # Exponent
                }
            ]
        }

        return web.json_response(jwks)


class OIDCRegisterView(HomeAssistantView):
    """OAuth 2.0 Dynamic Client Registration endpoint (RFC 7591)."""

    url = "/oidc/register"
    name = "api:oidc:register"
    requires_auth = False

    async def post(self, request: web.Request) -> web.Response:
        """Handle client registration request."""
        hass = request.app["hass"]

        try:
            data = await request.json()
        except Exception:
            return web.json_response(
                {"error": "invalid_request", "error_description": "Invalid JSON"},
                status=400,
            )

        # Validate required fields
        redirect_uris = data.get("redirect_uris")
        if not redirect_uris or not isinstance(redirect_uris, list):
            return web.json_response(
                {
                    "error": "invalid_redirect_uri",
                    "error_description": "redirect_uris is required and must be an array",
                },
                status=400,
            )

        # Extract client metadata
        client_name = data.get("client_name", "Dynamically Registered Client")
        grant_types = data.get("grant_types", ["authorization_code", "refresh_token"])
        response_types = data.get("response_types", ["code"])
        token_endpoint_auth_method = data.get("token_endpoint_auth_method", "client_secret_basic")

        # Validate grant types
        supported_grant_types = ["authorization_code", "refresh_token"]
        if not all(gt in supported_grant_types for gt in grant_types):
            supported = ", ".join(supported_grant_types)
            return web.json_response(
                {
                    "error": "invalid_client_metadata",
                    "error_description": f"Unsupported grant types. Supported: {supported}",
                },
                status=400,
            )

        # Validate response types
        if not all(rt in ["code"] for rt in response_types):
            return web.json_response(
                {
                    "error": "invalid_client_metadata",
                    "error_description": "Only 'code' response type is supported",
                },
                status=400,
            )

        # Create client using shared client_manager
        try:
            client_info = await create_client(
                hass,
                client_name=client_name,
                redirect_uris=redirect_uris,
                grant_types=grant_types,
                response_types=response_types,
                token_endpoint_auth_method=token_endpoint_auth_method,
            )
        except ValueError as e:
            return web.json_response(
                {
                    "error": "invalid_redirect_uri",
                    "error_description": str(e),
                },
                status=400,
            )

        return web.json_response(client_info, status=201)
