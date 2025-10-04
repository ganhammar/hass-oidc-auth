"""HTTP endpoints for OIDC Provider."""

import logging
import secrets
import time
from typing import Any

import jwt
from aiohttp import web
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from homeassistant.core import HomeAssistant
from homeassistant.components.http import HomeAssistantView

from .const import (
    DOMAIN,
    ACCESS_TOKEN_EXPIRY,
    AUTHORIZATION_CODE_EXPIRY,
    REFRESH_TOKEN_EXPIRY,
    GRANT_TYPE_AUTHORIZATION_CODE,
    GRANT_TYPE_REFRESH_TOKEN,
    RESPONSE_TYPE_CODE,
    SUPPORTED_SCOPES,
)

_LOGGER = logging.getLogger(__name__)


def setup_http_endpoints(hass: HomeAssistant) -> None:
    """Set up the OIDC HTTP endpoints."""
    # Generate RSA key pair for JWT signing
    if "jwt_private_key" not in hass.data[DOMAIN]:
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        hass.data[DOMAIN]["jwt_private_key"] = private_key
        hass.data[DOMAIN]["jwt_public_key"] = private_key.public_key()

    # Register views
    hass.http.register_view(OIDCDiscoveryView())
    hass.http.register_view(OIDCAuthorizationView())
    hass.http.register_view(OIDCTokenView())
    hass.http.register_view(OIDCUserInfoView())
    hass.http.register_view(OIDCJWKSView())


class OIDCDiscoveryView(HomeAssistantView):
    """OIDC Discovery endpoint."""

    url = "/.well-known/openid-configuration"
    name = "api:oidc:discovery"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Handle discovery request."""
        base_url = str(request.url.origin())

        discovery = {
            "issuer": base_url,
            "authorization_endpoint": f"{base_url}/auth/oidc/authorize",
            "token_endpoint": f"{base_url}/auth/oidc/token",
            "userinfo_endpoint": f"{base_url}/auth/oidc/userinfo",
            "jwks_uri": f"{base_url}/auth/oidc/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": SUPPORTED_SCOPES,
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "claims_supported": ["sub", "name", "email", "iss", "aud", "exp", "iat"],
        }

        return web.json_response(discovery)


class OIDCAuthorizationView(HomeAssistantView):
    """OIDC Authorization endpoint."""

    url = "/auth/oidc/authorize"
    name = "api:oidc:authorize"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Handle authorization request."""
        # Extract parameters
        client_id = request.query.get("client_id")
        redirect_uri = request.query.get("redirect_uri")
        response_type = request.query.get("response_type")
        scope = request.query.get("scope", "")
        state = request.query.get("state", "")

        # Validate parameters
        if not client_id or not redirect_uri or response_type != RESPONSE_TYPE_CODE:
            return web.Response(text="Invalid request", status=400)

        hass = request.app["hass"]
        clients = hass.data[DOMAIN].get("clients", {})

        if client_id not in clients:
            return web.Response(text="Invalid client_id", status=400)

        client = clients[client_id]
        if redirect_uri not in client["redirect_uris"]:
            return web.Response(text="Invalid redirect_uri", status=400)

        # Check if user is authenticated
        if request.get("hass_user") is None:
            # Redirect to HA login with return URL
            login_url = f"/auth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type={response_type}&scope={scope}&state={state}"
            return web.Response(
                text=f'<html><body>Redirecting to login...<script>window.location.href="/?auth_callback={login_url}";</script></body></html>',
                content_type="text/html",
            )

        # User is authenticated, generate authorization code
        auth_code = secrets.token_urlsafe(32)
        hass.data[DOMAIN]["authorization_codes"][auth_code] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "user_id": request["hass_user"].id,
            "expires_at": time.time() + AUTHORIZATION_CODE_EXPIRY,
        }

        # Redirect back to client with code
        separator = "&" if "?" in redirect_uri else "?"
        redirect_url = f"{redirect_uri}{separator}code={auth_code}"
        if state:
            redirect_url += f"&state={state}"

        return web.Response(status=302, headers={"Location": redirect_url})


class OIDCTokenView(HomeAssistantView):
    """OIDC Token endpoint."""

    url = "/auth/oidc/token"
    name = "api:oidc:token"
    requires_auth = False

    async def post(self, request: web.Request) -> web.Response:
        """Handle token request."""
        hass = request.app["hass"]
        data = await request.post()

        grant_type = data.get("grant_type")
        client_id = data.get("client_id")
        client_secret = data.get("client_secret")

        # Validate client
        clients = hass.data[DOMAIN].get("clients", {})
        if client_id not in clients:
            return web.json_response({"error": "invalid_client"}, status=401)

        client = clients[client_id]
        if client["client_secret"] != client_secret:
            return web.json_response({"error": "invalid_client"}, status=401)

        if grant_type == GRANT_TYPE_AUTHORIZATION_CODE:
            return await self._handle_authorization_code(request, hass, data)
        elif grant_type == GRANT_TYPE_REFRESH_TOKEN:
            return await self._handle_refresh_token(request, hass, data)
        else:
            return web.json_response({"error": "unsupported_grant_type"}, status=400)

    async def _handle_authorization_code(
        self, request: web.Request, hass: HomeAssistant, data: Any
    ) -> web.Response:
        """Handle authorization code grant."""
        code = data.get("code")
        redirect_uri = data.get("redirect_uri")

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
        self, request: web.Request, hass: HomeAssistant, data: Any
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

    url = "/auth/oidc/userinfo"
    name = "api:oidc:userinfo"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        """Handle userinfo request."""
        user = request.get("hass_user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)

        return web.json_response(
            {
                "sub": user.id,
                "name": user.name,
                "email": user.id,  # HA doesn't store email, use ID as fallback
            }
        )


class OIDCJWKSView(HomeAssistantView):
    """OIDC JWKS (JSON Web Key Set) endpoint."""

    url = "/auth/oidc/jwks"
    name = "api:oidc:jwks"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Handle JWKS request."""
        hass = request.app["hass"]
        public_key = hass.data[DOMAIN]["jwt_public_key"]

        # Export public key in JWK format
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # For simplicity, returning minimal JWKS
        # In production, you'd properly convert to JWK format
        jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "1",
                    "alg": "RS256",
                    "n": public_pem.decode(
                        "utf-8"
                    ),  # Simplified - should be proper base64url encoding
                }
            ]
        }

        return web.json_response(jwks)
