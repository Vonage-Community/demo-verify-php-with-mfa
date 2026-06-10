/**
 * mfa-demo.js
 *
 * Fetch wrappers for every PHP router endpoint, plus the
 * interactive demo-panel initialisation for the presentation.
 *
 * All paths use the /api/ prefix which Vite proxies to the
 * PHP application (see vite.config.js → server.proxy).
 * Set PHP_API_URL env var to point at your running PHP server.
 */

const API = '/api';

/* ------------------------------------------------------------------ */
/*  Low-level helpers                                                   */
/* ------------------------------------------------------------------ */

function showResult(el, type, message) {
  el.className = `demo-response demo-response--${type} visible`;
  el.textContent = message;
}

function showJSON(el, data) {
  el.className = 'demo-response demo-response--json visible';
  el.textContent = JSON.stringify(data, null, 2);
}

/** Base64url → ArrayBuffer (for WebAuthn) */
function b64urlDecode(base64) {
  let converted = base64.replace(/-/g, '+').replace(/_/g, '/');
  switch (converted.length % 4) {
    case 2: converted += '=='; break;
    case 3: converted += '='; break;
    case 1: throw new Error('Invalid base64url string: length modulo 4 cannot be 1');
  }
  const bin = atob(converted);
  const buffer = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buffer[i] = bin.charCodeAt(i);
  return buffer;
}

/** ArrayBuffer → Base64url (for WebAuthn) */
function b64urlEncode(arrayBuffer) {
  const buffer = new Uint8Array(arrayBuffer);
  let binary = '';
  for (let i = 0; i < buffer.length; i++) binary += String.fromCharCode(buffer[i]);
  let encoded = btoa(binary);
  // strip trailing = and convert to url-safe chars
  encoded = encoded.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  return encoded;
}

/* ------------------------------------------------------------------ */
/*  PHP Route wrappers                                                  */
/* ------------------------------------------------------------------ */

/**
 * POST /register
 * Body: application/x-www-form-urlencoded  { username, password, phone }
 * Success: 302 → /login?success=…
 * Failure: 302 → /register?msg=…
 */
export async function registerUser(username, password, phone) {
  const body = new URLSearchParams({ username, password, phone });
  const response = await fetch(`${API}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
    credentials: 'include',
    redirect: 'follow',
  });
  const finalUrl = new URL(response.url);
  if (finalUrl.pathname.startsWith('/login')) {
    return { success: true, message: finalUrl.searchParams.get('success') ?? 'User registered!' };
  }
  return { success: false, message: finalUrl.searchParams.get('msg') ?? 'Registration failed' };
}

/**
 * DELETE /register
 * Deletes the currently registered user (204 response).
 */
export async function deleteUser() {
  const response = await fetch(`${API}/register`, {
    method: 'DELETE',
    credentials: 'include',
  });
  return { success: response.status === 204 };
}

/**
 * POST /login
 * Body: application/x-www-form-urlencoded  { username, password }
 * Success: 302 → /mfa
 * Failure: 302 → /login?msg=… or /register?msg=…
 */
export async function loginUser(username, password) {
  const body = new URLSearchParams({ username, password });
  const response = await fetch(`${API}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
    credentials: 'include',
    redirect: 'follow',
  });
  const finalUrl = new URL(response.url);
  if (finalUrl.pathname === '/mfa') {
    return { success: true, message: 'Login successful — MFA required.' };
  }
  if (finalUrl.pathname.startsWith('/register')) {
    return { success: false, message: finalUrl.searchParams.get('msg') ?? 'No registered user found' };
  }
  return { success: false, message: finalUrl.searchParams.get('msg') ?? 'Invalid credentials' };
}

/**
 * POST /start-verify
 * Starts a Vonage Verify v2 SMS code request.
 * Returns JSON: { request_id: "…" }
 */
export async function startVerify() {
  const response = await fetch(`${API}/start-verify`, {
    method: 'POST',
    credentials: 'include',
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    return { success: false, ...err };
  }
  const data = await response.json();
  return { success: true, ...data };
}

/**
 * POST /verify-code
 * Body: JSON  { requestId, code }
 * Returns 200 on success, 400 with { error } on failure.
 */
export async function verifyCode(requestId, code) {
  const response = await fetch(`${API}/verify-code`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ requestId, code }),
    credentials: 'include',
  });
  if (response.status === 200) return { success: true, message: 'Code verified!' };
  const err = await response.json().catch(() => ({}));
  return { success: false, ...err };
}

/**
 * GET /register-totp
 * Returns the HTML registration page; extracts the QR code data-URI
 * embedded as <img src="data:…"> by the Twig template.
 */
export async function getTOTPQRCode() {
  const response = await fetch(`${API}/register-totp`, {
    credentials: 'include',
    redirect: 'follow',
  });
  if (!response.ok) {
    const finalUrl = new URL(response.url);
    const msg = finalUrl.searchParams.get('msg') ?? 'Failed — are you logged in and verified?';
    return { success: false, message: msg };
  }
  const html = await response.text();
  const doc = new DOMParser().parseFromString(html, 'text/html');
  // The Twig template renders the QR code as a data: URI in the img src
  const img = doc.querySelector('img[src^="data:"]');
  if (img) return { success: true, imgSrc: img.getAttribute('src') };
  return { success: false, message: 'QR code not found in response' };
}

/**
 * POST /verify-totp
 * Body: JSON  { code }
 * Returns 200 { msg } on success, 400/401 { error } on failure.
 */
export async function verifyTOTP(code) {
  const response = await fetch(`${API}/verify-totp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
    credentials: 'include',
  });
  const data = await response.json().catch(() => ({}));
  return { success: response.status === 200, ...data };
}

/**
 * GET /web-auth-register
 * Returns PublicKeyCredentialCreationOptions JSON for WebAuthn registration.
 */
export async function startWebAuthnRegistration() {
  const response = await fetch(`${API}/web-auth-register`, {
    credentials: 'include',
  });
  if (!response.ok) return { success: false, message: 'Failed to start WebAuthn registration' };
  const options = await response.json();
  // Decode base64url fields required by the browser WebAuthn API
  options.user.id = b64urlDecode(options.user.id);
  options.challenge = b64urlDecode(options.challenge);
  return { success: true, options };
}

/**
 * POST /web-auth-register
 * Body: JSON attestation response from navigator.credentials.create()
 * Returns 200 on success.
 */
export async function completeWebAuthnRegistration(creds) {
  const body = {
    type: creds.type,
    id: creds.id,
    rawId: b64urlEncode(creds.rawId),
    extensions: creds.getClientExtensionResults(),
    response: {
      attestationObject: b64urlEncode(creds.response.attestationObject),
      clientDataJSON: b64urlEncode(creds.response.clientDataJSON),
      transports: creds.response.getTransports ? creds.response.getTransports() : [],
    },
  };
  const response = await fetch(`${API}/web-auth-register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    credentials: 'include',
  });
  return { success: response.status === 200 };
}

/**
 * GET /auth-web-auth
 * Returns PublicKeyCredentialRequestOptions JSON for WebAuthn authentication.
 */
export async function startWebAuthnAuthentication() {
  const response = await fetch(`${API}/auth-web-auth`, {
    credentials: 'include',
    cache: 'no-cache',
  });
  if (!response.ok) return { success: false, message: 'Failed to start WebAuthn authentication' };
  const options = await response.json();
  options.challenge = b64urlDecode(options.challenge);
  options.allowCredentials = (options.allowCredentials ?? []).map((c) => ({
    type: c.type,
    transports: c.transports,
    id: b64urlDecode(c.id),
  }));
  return { success: true, options };
}

/**
 * POST /auth-web-auth
 * Body: JSON assertion response from navigator.credentials.get()
 * Returns 200 { msg } on success, 401/500 { error } on failure.
 */
export async function completeWebAuthnAuthentication(challenge) {
  const body = {
    id: challenge.id,
    rawId: b64urlEncode(challenge.rawId),
    type: challenge.type,
    response: {
      clientDataJSON: b64urlEncode(challenge.response.clientDataJSON),
      authenticatorData: b64urlEncode(challenge.response.authenticatorData),
      signature: b64urlEncode(challenge.response.signature),
      userHandle: challenge.response.userHandle ? b64urlEncode(challenge.response.userHandle) : null,
    },
  };
  const response = await fetch(`${API}/auth-web-auth`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    credentials: 'include',
  });
  if (response.ok) return { success: true, message: 'Key verified!' };
  const data = await response.json().catch(() => ({}));
  return { success: false, ...data };
}

/* ------------------------------------------------------------------ */
/*  Demo panel initialisers                                             */
/* ------------------------------------------------------------------ */

function initRegisterDemo() {
  const form = document.getElementById('demo-register-form');
  if (!form) return;
  const resultEl = document.getElementById('demo-register-result');
  const submitBtn = form.querySelector('button[type="submit"]');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    e.stopPropagation();
    const username = form.querySelector('[name="username"]').value.trim();
    const password = form.querySelector('[name="password"]').value.trim();
    const phone = form.querySelector('[name="phone"]').value.trim();
    if (!username || !password || !phone) {
      showResult(resultEl, 'error', 'All fields are required.');
      return;
    }
    submitBtn.disabled = true;
    showResult(resultEl, 'loading', '⏳ Registering user…');
    try {
      const result = await registerUser(username, password, phone);
      if (result.success) {
        showResult(resultEl, 'success', `✅ ${result.message}`);
      } else {
        showResult(resultEl, 'error', `❌ ${result.message}`);
      }
    } catch (err) {
      showResult(resultEl, 'error', `❌ Network error: ${err.message}`);
    } finally {
      submitBtn.disabled = false;
    }
  });
}

function initLoginDemo() {
  const form = document.getElementById('demo-login-form');
  if (!form) return;
  const resultEl = document.getElementById('demo-login-result');
  const submitBtn = form.querySelector('button[type="submit"]');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    e.stopPropagation();
    const username = form.querySelector('[name="username"]').value.trim();
    const password = form.querySelector('[name="password"]').value.trim();
    if (!username || !password) {
      showResult(resultEl, 'error', 'Username and password are required.');
      return;
    }
    submitBtn.disabled = true;
    showResult(resultEl, 'loading', '⏳ Logging in…');
    try {
      const result = await loginUser(username, password);
      if (result.success) {
        showResult(resultEl, 'success', `✅ ${result.message}`);
      } else {
        showResult(resultEl, 'error', `❌ ${result.message}`);
      }
    } catch (err) {
      showResult(resultEl, 'error', `❌ Network error: ${err.message}`);
    } finally {
      submitBtn.disabled = false;
    }
  });
}

function initVerifyDemo() {
  const startBtn = document.getElementById('demo-verify-start');
  const codeInput = document.getElementById('demo-verify-code');
  const checkBtn = document.getElementById('demo-verify-check');
  const resultEl = document.getElementById('demo-verify-result');
  if (!startBtn) return;

  let currentRequestId = null;

  startBtn.addEventListener('click', async () => {
    startBtn.disabled = true;
    showResult(resultEl, 'loading', '⏳ Sending verification SMS…');
    try {
      const result = await startVerify();
      if (result.success && result.request_id) {
        currentRequestId = result.request_id;
        codeInput.disabled = false;
        checkBtn.disabled = false;
        showJSON(resultEl, { request_id: result.request_id });
      } else {
        showResult(resultEl, 'error', `❌ ${result.error ?? 'Failed to start verification'}`);
        startBtn.disabled = false;
      }
    } catch (err) {
      showResult(resultEl, 'error', `❌ Network error: ${err.message}`);
      startBtn.disabled = false;
    }
  });

  checkBtn.addEventListener('click', async () => {
    const code = codeInput.value.trim();
    if (!code) {
      showResult(resultEl, 'error', 'Enter the code from your SMS.');
      return;
    }
    checkBtn.disabled = true;
    showResult(resultEl, 'loading', '⏳ Checking code…');
    try {
      const result = await verifyCode(currentRequestId, code);
      if (result.success) {
        showResult(resultEl, 'success', '✅ Code verified! MFA complete.');
      } else {
        showResult(resultEl, 'error', `❌ ${result.error ?? 'Verification failed'}`);
        checkBtn.disabled = false;
      }
    } catch (err) {
      showResult(resultEl, 'error', `❌ Network error: ${err.message}`);
      checkBtn.disabled = false;
    }
  });
}

function initTOTPDemo() {
  const qrBtn = document.getElementById('demo-totp-qr');
  const verifyBtn = document.getElementById('demo-totp-verify');
  const codeInput = document.getElementById('demo-totp-code');
  const qrEl = document.getElementById('demo-totp-qr-display');
  const qrImg = document.getElementById('demo-totp-qr-img');
  const resultEl = document.getElementById('demo-totp-result');
  if (!qrBtn) return;

  qrBtn.addEventListener('click', async () => {
    qrBtn.disabled = true;
    showResult(resultEl, 'loading', '⏳ Fetching QR code…');
    try {
      const result = await getTOTPQRCode();
      if (result.success) {
        qrImg.src = result.imgSrc;
        qrEl.classList.add('visible');
        codeInput.disabled = false;
        verifyBtn.disabled = false;
        resultEl.className = 'demo-response';
      } else {
        showResult(resultEl, 'error', `❌ ${result.message}`);
        qrBtn.disabled = false;
      }
    } catch (err) {
      showResult(resultEl, 'error', `❌ Network error: ${err.message}`);
      qrBtn.disabled = false;
    }
  });

  verifyBtn.addEventListener('click', async () => {
    const code = codeInput.value.trim();
    if (!code) {
      showResult(resultEl, 'error', 'Enter the 6-digit code from your authenticator.');
      return;
    }
    verifyBtn.disabled = true;
    showResult(resultEl, 'loading', '⏳ Verifying TOTP code…');
    try {
      const result = await verifyTOTP(code);
      if (result.success) {
        showResult(resultEl, 'success', `✅ ${result.msg ?? 'Code verified!'}`);
      } else {
        showResult(resultEl, 'error', `❌ ${result.error ?? 'Verification failed'}`);
        verifyBtn.disabled = false;
      }
    } catch (err) {
      showResult(resultEl, 'error', `❌ Network error: ${err.message}`);
      verifyBtn.disabled = false;
    }
  });
}

function initWebAuthnDemo() {
  const registerBtn = document.getElementById('demo-webauthn-register');
  const authBtn = document.getElementById('demo-webauthn-auth');
  const resultEl = document.getElementById('demo-webauthn-result');
  if (!registerBtn) return;

  registerBtn.addEventListener('click', async () => {
    if (!navigator.credentials) {
      showResult(resultEl, 'error', '❌ WebAuthn is not supported in this browser.');
      return;
    }
    registerBtn.disabled = true;
    showResult(resultEl, 'loading', '⏳ Starting WebAuthn registration…');
    try {
      const startResult = await startWebAuthnRegistration();
      if (!startResult.success) {
        showResult(resultEl, 'error', `❌ ${startResult.message}`);
        registerBtn.disabled = false;
        return;
      }
      showResult(resultEl, 'loading', '⏳ Waiting for security key / passkey…');
      const creds = await navigator.credentials.create({ publicKey: startResult.options });
      showResult(resultEl, 'loading', '⏳ Completing registration…');
      const finishResult = await completeWebAuthnRegistration(creds);
      if (finishResult.success) {
        showResult(resultEl, 'success', '✅ Security key registered!');
        authBtn.disabled = false;
      } else {
        showResult(resultEl, 'error', '❌ Registration failed on server');
        registerBtn.disabled = false;
      }
    } catch (err) {
      showResult(resultEl, 'error', `❌ ${err.message}`);
      registerBtn.disabled = false;
    }
  });

  authBtn.addEventListener('click', async () => {
    authBtn.disabled = true;
    showResult(resultEl, 'loading', '⏳ Starting WebAuthn authentication…');
    try {
      const startResult = await startWebAuthnAuthentication();
      if (!startResult.success) {
        showResult(resultEl, 'error', `❌ ${startResult.message}`);
        authBtn.disabled = false;
        return;
      }
      showResult(resultEl, 'loading', '⏳ Waiting for security key / passkey…');
      const assertion = await navigator.credentials.get({ publicKey: startResult.options });
      showResult(resultEl, 'loading', '⏳ Completing authentication…');
      const finishResult = await completeWebAuthnAuthentication(assertion);
      if (finishResult.success) {
        showResult(resultEl, 'success', `✅ ${finishResult.message ?? 'Authenticated!'}`);
      } else {
        showResult(resultEl, 'error', `❌ ${finishResult.error ?? 'Authentication failed'}`);
        authBtn.disabled = false;
      }
    } catch (err) {
      showResult(resultEl, 'error', `❌ ${err.message}`);
      authBtn.disabled = false;
    }
  });
}

/* ------------------------------------------------------------------ */
/*  Bootstrap all demo panels when the DOM is ready                    */
/* ------------------------------------------------------------------ */

document.addEventListener('DOMContentLoaded', () => {
  initRegisterDemo();
  initLoginDemo();
  initVerifyDemo();
  initTOTPDemo();
  initWebAuthnDemo();
});
