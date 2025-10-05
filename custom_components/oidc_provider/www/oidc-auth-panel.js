// OIDC Login Panel - handles redirect after authentication
class OidcLoginPanel extends HTMLElement {
  async connectedCallback() {
    // Wait a bit for hass to be available
    await new Promise(resolve => setTimeout(resolve, 100));

    // Get the auth request ID from sessionStorage
    const requestId = sessionStorage.getItem('oidc_request_id');

    if (!requestId) {
      this.innerHTML = `
        <div style="padding: 20px; font-family: sans-serif;">
          <h2>No Pending Authorization Request</h2>
          <p>There is no pending OIDC authorization request.</p>
        </div>
      `;
      return;
    }

    // The panel runs in authenticated HA frontend context
    // We have access to hass object which has auth tokens
    try {
      this.innerHTML = `
        <div style="padding: 20px; font-family: sans-serif;">
          <h2>Completing Authorization...</h2>
          <p>Please wait while we complete the authorization process.</p>
        </div>
      `;

      // Wait for hass to be available
      let attempts = 0;
      while (!this.hass && attempts < 50) {
        await new Promise(resolve => setTimeout(resolve, 100));
        attempts++;
      }

      if (!this.hass) {
        throw new Error('Home Assistant connection not available');
      }

      // Get access token - different HA versions have different ways
      let accessToken;
      if (this.hass.auth && typeof this.hass.auth.data?.access_token === 'string') {
        accessToken = this.hass.auth.data.access_token;
      } else if (this.hass.connection?.auth?.data?.access_token) {
        accessToken = this.hass.connection.auth.data.access_token;
      } else if (this.hass.auth?.accessToken) {
        accessToken = this.hass.auth.accessToken;
      } else {
        throw new Error('Cannot find access token in hass object');
      }

      // Call the continue endpoint with Bearer token
      const response = await fetch(`/auth/oidc/continue?request_id=${requestId}`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`
        },
        redirect: 'manual'
      });

      if (response.type === 'opaqueredirect' || response.status === 0) {
        // Manual redirect was blocked, get location from headers
        const location = response.headers.get('Location');
        if (location) {
          window.location.href = location;
        }
      } else if (response.redirected) {
        window.location.href = response.url;
      } else if (response.ok) {
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
          const data = await response.json();
          if (data.redirect_url) {
            window.location.href = data.redirect_url;
          }
        } else {
          // Assume it's a redirect in HTML
          window.location.reload();
        }
      } else {
        const text = await response.text();
        throw new Error(`Failed: ${response.status} - ${text}`);
      }
    } catch (error) {
      this.innerHTML = `
        <div style="padding: 20px; font-family: sans-serif;">
          <h2>Error</h2>
          <p>Failed to complete authorization: ${error.message}</p>
          <p style="font-size: 0.9em; color: #666;">Debug: hass=${!!this.hass}, auth=${!!this.hass?.auth}</p>
        </div>
      `;
    }
  }

  setConfig(config) {
    // Required method for custom panels
  }

  set hass(hass) {
    this._hass = hass;
  }

  get hass() {
    return this._hass;
  }
}

customElements.define('oidc-auth-panel', OidcLoginPanel);
