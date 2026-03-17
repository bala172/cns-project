/**
 * auth.js — shared authentication helpers
 * Handles JWT storage, validation, and logout.
 */

const API = ''; // same origin

function getToken() { return localStorage.getItem('clab_token'); }
function getUser()  { return localStorage.getItem('clab_user'); }
function setSession(token, username) {
  localStorage.setItem('clab_token', token);
  localStorage.setItem('clab_user', username);
}
function clearSession() {
  localStorage.removeItem('clab_token');
  localStorage.removeItem('clab_user');
}

/** Redirect to login if no token present */
function requireAuth() {
  if (!getToken()) { window.location.href = '/'; }
}

/** Attach auth header to fetch options */
function authFetch(url, options = {}) {
  return fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${getToken()}`,
      ...(options.headers || {})
    }
  });
}

/** Logout: clear session and redirect */
function logout() {
  clearSession();
  window.location.href = '/';
}

/** Wire up logout button if present */
document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('logoutBtn');
  if (btn) btn.addEventListener('click', logout);

  const userEl = document.getElementById('navUser');
  if (userEl && getUser()) userEl.textContent = getUser();
});
