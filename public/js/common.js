(function () {
  const OUTBOX_KEY = 'erp_outbox';
  const USER_KEY = 'erp_user';

  function getToken() {
    return localStorage.getItem('erp_token') || '';
  }

  function setToken(token) {
    localStorage.setItem('erp_token', token);
  }

  function clearToken() {
    localStorage.removeItem('erp_token');
  }

  function setUser(user) {
    localStorage.setItem(USER_KEY, JSON.stringify(user || null));
  }

  function getUser() {
    try {
      return JSON.parse(localStorage.getItem(USER_KEY) || 'null');
    } catch {
      return null;
    }
  }

  function clearUser() {
    localStorage.removeItem(USER_KEY);
  }

  function isOnline() {
    return navigator.onLine;
  }

  async function api(url, options = {}) {
    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    const token = getToken();
    if (token) headers.Authorization = `Bearer ${token}`;

    let res;
    try {
      res = await fetch(url, { ...options, headers });
    } catch {
      throw new Error('Offline mode: data will sync when internet is back.');
    }

    if (res.status === 401) {
      clearToken();
      clearUser();
      if (!location.pathname.endsWith('/index.html') && location.pathname !== '/') {
        location.href = '/index.html';
      }
      throw new Error('Unauthorized');
    }

    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Request failed');
    return data;
  }

  function formToObject(form) {
    const fd = new FormData(form);
    return Object.fromEntries(fd.entries());
  }

  function fillTable(id, headers, rows) {
    const table = document.getElementById(id);
    table.innerHTML = '';
    const thead = document.createElement('thead');
    thead.innerHTML = `<tr>${headers.map((h) => `<th>${h}</th>`).join('')}</tr>`;
    const tbody = document.createElement('tbody');
    rows.forEach((r) => {
      const tr = document.createElement('tr');
      tr.innerHTML = r;
      tbody.appendChild(tr);
    });
    table.append(thead, tbody);
  }

  function getCache(key, fallback) {
    try {
      const raw = localStorage.getItem(key);
      if (!raw) return fallback;
      return JSON.parse(raw);
    } catch {
      return fallback;
    }
  }

  function setCache(key, value) {
    localStorage.setItem(key, JSON.stringify(value));
  }

  function getOutbox() {
    return getCache(OUTBOX_KEY, []);
  }

  function setOutbox(items) {
    setCache(OUTBOX_KEY, items);
  }

  function queueAction(action) {
    const outbox = getOutbox();
    outbox.push({
      id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
      created_at: new Date().toISOString(),
      ...action,
    });
    setOutbox(outbox);
    updateNetStatus();
  }

  async function flushOutbox() {
    if (!isOnline()) return;
    const outbox = getOutbox();
    if (!outbox.length) return;

    const remaining = [];
    for (const item of outbox) {
      try {
        await api(item.url, { method: item.method || 'POST', body: JSON.stringify(item.body || {}) });
      } catch (err) {
        const msg = String(err.message || '');
        if (msg.includes('Offline mode')) {
          remaining.push(item);
          break;
        }
        if (msg.includes('Unauthorized')) {
          remaining.push(item);
          break;
        }
        remaining.push(item);
      }
    }
    setOutbox(remaining);
    updateNetStatus();
  }

  async function requireLogin() {
    const token = getToken();
    if (!token) {
      location.href = '/index.html';
      return null;
    }

    if (!isOnline()) {
      const cachedUser = getUser();
      if (cachedUser) return cachedUser;
      location.href = '/index.html';
      return null;
    }

    const me = await api('/api/auth/me');
    setUser(me.user);
    return me.user;
  }

  async function logout() {
    try {
      if (isOnline()) {
        await api('/api/auth/logout', { method: 'POST' });
      }
    } catch {
      // no-op
    }
    clearToken();
    clearUser();
    location.href = '/index.html';
  }

  function ensureNetStatus() {
    let el = document.getElementById('netStatus');
    if (!el) {
      el = document.createElement('div');
      el.id = 'netStatus';
      el.style.position = 'fixed';
      el.style.right = '14px';
      el.style.bottom = '14px';
      el.style.padding = '8px 12px';
      el.style.borderRadius = '999px';
      el.style.zIndex = '9999';
      el.style.fontSize = '12px';
      el.style.fontWeight = '700';
      el.style.border = '1px solid rgba(118,166,204,0.35)';
      document.body.appendChild(el);
    }
    return el;
  }

  function updateNetStatus() {
    const el = ensureNetStatus();
    const pending = getOutbox().length;
    if (isOnline()) {
      el.textContent = pending ? `Online | Sync pending: ${pending}` : 'Online | Synced';
      el.style.background = 'rgba(14, 55, 39, 0.92)';
      el.style.color = '#c8ffe9';
    } else {
      el.textContent = pending ? `Offline | Queued: ${pending}` : 'Offline';
      el.style.background = 'rgba(79, 38, 18, 0.92)';
      el.style.color = '#ffd8bf';
    }
  }

  window.addEventListener('online', async () => {
    updateNetStatus();
    await flushOutbox();
  });
  window.addEventListener('offline', updateNetStatus);
  setInterval(flushOutbox, 10000);
  document.addEventListener('DOMContentLoaded', updateNetStatus);

  // App shell caching for offline page loads.
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('/sw.js').catch(() => {});
    });
  }

  window.ERP = {
    api,
    getToken,
    setToken,
    clearToken,
    setUser,
    getUser,
    formToObject,
    fillTable,
    requireLogin,
    logout,
    isOnline,
    getCache,
    setCache,
    queueAction,
    flushOutbox,
    updateNetStatus,
  };
})();
