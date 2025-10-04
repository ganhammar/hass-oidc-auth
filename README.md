# Home Assistant OIDC Provider

A Home Assistant custom component that turns your Home Assistant instance into a fully functional OpenID Connect (OIDC) provider, allowing external applications like Claude Connectors to authenticate against your Home Assistant users.

## Features

- **Standards-compliant OIDC provider** with discovery endpoint
- **Integrates with Home Assistant's native authentication** including TOTP/2FA
- **JWT-based access tokens** with RSA signing
- **Support for authorization code flow** with refresh tokens
- **Easy client registration** via Home Assistant services
- **No external dependencies** - runs entirely within Home Assistant

## Installation

### HACS (Recommended)

1. Add this repository as a custom repository in HACS
2. Search for "OIDC Provider" in HACS
3. Click "Install"
4. Restart Home Assistant

### Manual

1. Copy the `custom_components/oidc_provider` folder to your Home Assistant `config/custom_components/` directory
2. Restart Home Assistant

## Configuration

1. Go to **Settings** → **Devices & Services**
2. Click **Add Integration**
3. Search for "OIDC Provider"
4. Click to install

## Usage

### Registering a Client

To register a new OIDC client (e.g., for Claude Connectors):

1. Go to **Developer Tools** → **Actions**
2. In the action dropdown, select **"Register OIDC Client"** (or type `oidc_provider.register_client`)
3. Fill in the fields:
   - **Client Name**: A friendly name (e.g., "Claude Connector")
   - **Redirect URIs**: Comma-separated list of allowed redirect URIs
4. Click **"Perform Action"**
5. Check the Home Assistant logs for the generated **Client ID** and **Client Secret**

Example action call:

```yaml
action: oidc_provider.register_client
data:
  client_name: "Claude Connector"
  redirect_uris: "https://claude.ai/callback,https://app.claude.com/callback"
```

The logs will display:

```
Registered OIDC client: Claude Connector
Client ID: client_xxxxxxxxxxxxx
Client Secret: yyyyyyyyyyyyyyyyyyyyyyyy
Redirect URIs: ['https://claude.ai/callback', 'https://app.claude.com/callback']
```

**Important**: Save these credentials securely. The client secret cannot be retrieved later.

### Updating a Client

To update redirect URIs for an existing client:

1. Use **"List OIDC Clients"** to find the client ID
2. Go to **Developer Tools** → **Actions**
3. Select **"Update OIDC Client"**
4. Enter the client ID and new redirect URIs

```yaml
action: oidc_provider.update_client
data:
  client_id: "client_xxxxxxxxxxxxx"
  redirect_uris: "https://new-app.example.com/callback,http://localhost:8080/auth"
```

### Revoking a Client

To revoke an existing client:

1. Use **"List OIDC Clients"** to find the client ID
2. Go to **Developer Tools** → **Actions**
3. Select **"Revoke OIDC Client"**
4. Enter the client ID

```yaml
action: oidc_provider.revoke_client
data:
  client_id: "client_xxxxxxxxxxxxx"
```

### OIDC Endpoints

Once installed, your Home Assistant instance exposes the following OIDC endpoints:

- **Discovery**: `https://your-ha-instance/.well-known/openid-configuration`
- **Authorization**: `https://your-ha-instance/auth/oidc/authorize`
- **Token**: `https://your-ha-instance/auth/oidc/token`
- **UserInfo**: `https://your-ha-instance/auth/oidc/userinfo`
- **JWKS**: `https://your-ha-instance/auth/oidc/jwks`

### Using with Claude Connectors

1. Register a client as described above
2. In Claude, configure a custom connector with:
   - **OIDC Discovery URL**: `https://your-ha-instance/.well-known/openid-configuration`
   - **Client ID**: The generated client ID
   - **Client Secret**: The generated client secret
3. When prompted, log in with your Home Assistant credentials (TOTP/2FA supported)

## Security Considerations

- **HTTPS Required**: Your Home Assistant instance must be accessible via HTTPS with a valid certificate for OIDC to work with external services
- **Client Secrets**: Store client secrets securely and never commit them to version control
- **Token Storage**: Tokens are stored in memory only and will be lost on restart. Clients should be prepared to re-authenticate.
- **Refresh Tokens**: Valid for 30 days by default
- **Access Tokens**: Valid for 1 hour by default

## Supported Scopes

- `openid` - Required for OIDC
- `profile` - User profile information
- `email` - User email (uses HA user ID as fallback)

## Troubleshooting

### Client registration not appearing in logs

Check that you have the log level set appropriately in your `configuration.yaml`:

```yaml
logger:
  default: info
  logs:
    custom_components.oidc_provider: debug
```

### Authentication not working

1. Verify your Home Assistant instance is accessible via HTTPS
2. Check that the redirect URI matches exactly what the client is sending
3. Ensure the user has valid permissions in Home Assistant

### Tokens not being issued

Check the Home Assistant logs for detailed error messages. Common issues:
- Invalid client credentials
- Expired authorization codes (10 minute timeout)
- Mismatched redirect URIs

## Development

### Setup

```bash
poetry install
```

### Running Tests

```bash
poetry run pytest tests/ -v
```

### Running Tests with Coverage

```bash
poetry run pytest tests/ --cov=custom_components/oidc_provider --cov-report=term-missing
```

### Code Formatting

```bash
poetry run black custom_components/ tests/
```

### Linting

```bash
poetry run ruff check custom_components/ tests/
```

To auto-fix issues:

```bash
poetry run ruff check custom_components/ tests/ --fix
```

## License

MIT

## Contributing

Contributions are welcome! Please open an issue or pull request on GitHub.
