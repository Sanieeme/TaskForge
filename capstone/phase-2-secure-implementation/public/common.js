// common.js — shared by every page.
// Anything used by more than one page (DOM helpers, API calls, the toast,
// the top navigation bar) lives here once instead of being copy-pasted
// into each page's inline <script>.

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  Object.entries(props).forEach(([k, v]) => {
    if (k === 'class') node.className = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  });
  children.forEach((c) => node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c));
  return node;
}

function showToast(message, isError = true) {
  const existing = document.getElementById('toast');
  if (existing) existing.remove();
  const toast = el('div', {
    id: 'toast',
    style: `position:fixed; bottom:20px; right:20px; z-index:1000; padding:12px 16px; border-radius:8px; font-size:13px; box-shadow:0 4px 12px rgba(0,0,0,0.2); color:#fff; background:${isError ? '#de350b' : '#00875a'};`,
  }, [message]);
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 3500);
}

// One fetch wrapper for every page: always sends the session cookie,
// always parses JSON, always throws a consistent error with .status and
// .data so every caller handles failures the same way instead of each
// page re-implementing try/catch + res.ok + err.error.
async function apiFetch(url, options = {}) {
  const res = await fetch(url, { credentials: 'include', ...options });
  let data = null;
  try { data = await res.json(); } catch (e) { /* empty body, fine */ }
  if (!res.ok) {
    const err = new Error((data && data.error) || `Request failed (${res.status})`);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

async function logout() {
  try { await apiFetch('/api/logout', { method: 'POST' }); } catch (e) { /* ignore */ }
  window.location = '/login.html';
}

// Builds the top bar into <div id="topbar-root">, which every page includes
// instead of hand-writing the nav markup. Also owns the /api/me call and
// the "not logged in -> back to login" redirect, so no page needs its own
// copy of that check. Returns the current user (or null if redirected).
async function initTopbar() {
  const root = document.getElementById('topbar-root');
  if (!root) return null;

  let me;
  try {
    me = await apiFetch('/api/me');
  } catch (e) {
    window.location = '/login.html';
    return null;
  }

  const initials = me.username.slice(0, 2).toUpperCase();
  root.appendChild(el('div', { class: 'who' }, [
    el('div', { class: 'logo', style: 'width:26px;height:26px;font-size:12px;' }, ['TF']),
    el('span', { class: 'avatar-fallback', style: 'margin-right:2px' }, [initials]),
    el('span', {}, ['Logged in as ', el('b', {}, [me.username])]),
    el('span', { class: 'role-pill' }, [me.role]),
  ]));

  const actions = el('div', { class: 'actions' });
  if (location.pathname === '/dashboard.html') {
    actions.appendChild(el('button', { class: 'secondary', onclick: () => (location.href = '/profile.html') }, ['Profile']));
    if (me.role === 'admin') {
      actions.appendChild(el('button', { class: 'secondary', onclick: () => (location.href = '/users.html') }, ['Users']));
    }
  } else {
    actions.appendChild(el('button', { class: 'secondary', onclick: () => (location.href = '/dashboard.html') }, ['← Back to tasks']));
  }
  actions.appendChild(el('button', { class: 'secondary', onclick: logout }, ['Log out']));
  root.appendChild(actions);

  return me;
}
