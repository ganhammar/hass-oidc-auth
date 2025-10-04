// OIDC Login Panel - handles redirect after authentication
class OidcLoginPanel extends HTMLElement {
  connectedCallback() {
    // Get the auth request ID from sessionStorage
    const requestId = sessionStorage.getItem('oidc_request_id');

    if (requestId) {
      // Redirect to authorize endpoint with the request ID
      const url = `/auth/oidc/authorize?request_id=${requestId}`;
      window.location.href = url;
    } else {
      // No pending request
      this.innerHTML = `
        <div style="padding: 20px; font-family: sans-serif;">
          <h2>No Pending Authorization Request</h2>
          <p>There is no pending OIDC authorization request.</p>
        </div>
      `;
    }
  }
}

customElements.define('oidc-login-panel', OidcLoginPanel);
