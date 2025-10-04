// OIDC Login Panel - handles redirect after authentication
class OidcLoginPanel extends HTMLElement {
  async connectedCallback() {
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
      // Get auth token from HA
      const auth = this.hass?.auth;
      if (!auth) {
        throw new Error('No authentication available');
      }

      const accessToken = await auth.getAccessToken();

      // Call the continue endpoint with Bearer token
      const response = await fetch(`/auth/oidc/continue?request_id=${requestId}`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      });

      if (response.redirected) {
        window.location.href = response.url;
      } else if (response.ok) {
        const data = await response.json();
        if (data.redirect_url) {
          window.location.href = data.redirect_url;
        }
      } else {
        throw new Error(`Failed: ${response.status}`);
      }
    } catch (error) {
      this.innerHTML = `
        <div style="padding: 20px; font-family: sans-serif;">
          <h2>Error</h2>
          <p>Failed to complete authorization: ${error.message}</p>
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

customElements.define('oidc-login-panel', OidcLoginPanel);
