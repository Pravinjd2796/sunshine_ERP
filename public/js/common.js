(function () {
  function getToken() {
    return localStorage.getItem('erp_token') || '';
  }

  function setToken(token) {
    localStorage.setItem('erp_token', token);
  }

  function clearToken() {
    localStorage.removeItem('erp_token');
  }

  async function api(url, options = {}) {
    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    const token = getToken();
    if (token) headers.Authorization = `Bearer ${token}`;

    const res = await fetch(url, { ...options, headers });
    if (res.status === 401) {
      clearToken();
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

  async function requireLogin() {
    const token = getToken();
    if (!token) {
      location.href = '/index.html';
      return null;
    }
    const me = await api('/api/auth/me');
    return me.user;
  }

  async function logout() {
    try {
      await api('/api/auth/logout', { method: 'POST' });
    } catch {
      // no-op
    }
    clearToken();
    location.href = '/index.html';
  }

  window.ERP = { api, getToken, setToken, clearToken, formToObject, fillTable, requireLogin, logout };
})();
