(async function () {
  const user = await ERP.requireLogin();
  if (!user) return;
  if (user.role !== 'ADMIN') {
    alert('Only admin can access this page.');
    location.href = '/home.html';
    return;
  }

  document.getElementById('logoutBtn').addEventListener('click', ERP.logout);
  const form = document.getElementById('userForm');
  const downloadDbBtn = document.getElementById('downloadDbBtn');
  const restoreDbBtn = document.getElementById('restoreDbBtn');
  const restoreDbFile = document.getElementById('restoreDbFile');
  const dbActionStatus = document.getElementById('dbActionStatus');
  const usersTable = document.getElementById('usersTable');

  async function loadUsers() {
    const users = await ERP.api('/api/users');
    ERP.fillTable(
      'usersTable',
      ['ID', 'Username', 'Name', 'Email', 'Mobile', 'Role', 'Status', 'Has Login', 'Actions'],
      users.map((u) => {
        const toggleLabel = u.status === 'ACTIVE' ? 'Disable' : 'Enable';
        const nextStatus = u.status === 'ACTIVE' ? 'INACTIVE' : 'ACTIVE';
        return `<td>${u.id}</td><td>${u.username || ''}</td><td>${u.name}</td><td>${u.email || ''}</td><td>${u.mobile || ''}</td><td>${u.role}</td><td>${u.status}</td><td>${u.has_password ? 'Yes' : 'No'}</td><td><button data-action=\"reset\" data-id=\"${u.id}\" data-username=\"${encodeURIComponent(u.username || '')}\">Reset Login</button> <button data-action=\"toggle\" data-id=\"${u.id}\" data-status=\"${nextStatus}\">${toggleLabel}</button> <button data-action=\"delete\" data-id=\"${u.id}\">Delete</button></td>`;
      })
    );
  }

  async function toggleUserStatus(id, status) {
    try {
      await ERP.api(`/api/users/${id}`, { method: 'PATCH', body: JSON.stringify({ status }) });
      await loadUsers();
    } catch (e) {
      alert(e.message);
    }
  }

  async function deleteUser(id) {
    if (!confirm('Delete this user?')) return;
    try {
      await ERP.api(`/api/users/${id}`, { method: 'DELETE' });
      await loadUsers();
    } catch (e) {
      alert(e.message);
    }
  }

  async function resetCredentials(id, encodedUsername) {
    const currentUsername = decodeURIComponent(encodedUsername || '');
    const username = (prompt('Enter new username', currentUsername || '') || '').trim().toLowerCase();
    if (!username) {
      alert('Username is required.');
      return;
    }
    const password = prompt('Enter new password (min 6 chars)');
    if (!password || password.length < 6) {
      alert('Password must be at least 6 characters.');
      return;
    }
    try {
      await ERP.api(`/api/users/${id}/credentials`, {
        method: 'PATCH',
        body: JSON.stringify({ username, password }),
      });
      alert('Login credentials updated.');
      await loadUsers();
    } catch (e) {
      alert(e.message || 'Failed to reset credentials');
    }
  }

  usersTable.addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;
    const action = btn.getAttribute('data-action');
    const id = Number(btn.getAttribute('data-id'));
    if (!id) return;

    if (action === 'reset') {
      await resetCredentials(id, btn.getAttribute('data-username') || '');
      return;
    }
    if (action === 'toggle') {
      await toggleUserStatus(id, btn.getAttribute('data-status') || 'INACTIVE');
      return;
    }
    if (action === 'delete') {
      await deleteUser(id);
    }
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const data = ERP.formToObject(form);
      await ERP.api('/api/users', { method: 'POST', body: JSON.stringify(data) });
      form.reset();
      await loadUsers();
      alert('User created successfully.');
    } catch (e) {
      alert(e.message || 'Failed to create user');
    }
  });

  downloadDbBtn.addEventListener('click', async () => {
    try {
      dbActionStatus.textContent = 'Preparing backup download...';
      const token = ERP.getToken();
      const res = await fetch('/api/admin/db/download', {
        method: 'GET',
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || 'Failed to download DB');
      }

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `sunshine-erp-backup-${new Date().toISOString().replace(/[:.]/g, '-')}.sqlite`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      dbActionStatus.textContent = 'Backup downloaded successfully.';
    } catch (e) {
      dbActionStatus.textContent = e.message || 'Failed to download backup.';
    }
  });

  restoreDbBtn.addEventListener('click', async () => {
    const file = restoreDbFile.files && restoreDbFile.files[0];
    if (!file) {
      dbActionStatus.textContent = 'Please choose a .sqlite file first.';
      return;
    }
    if (!file.name.toLowerCase().endsWith('.sqlite')) {
      dbActionStatus.textContent = 'Please upload a valid .sqlite file.';
      return;
    }
    if (!confirm('Restore database from selected file? This will overwrite current DB data.')) return;

    try {
      dbActionStatus.textContent = 'Uploading and restoring database...';
      const token = ERP.getToken();
      const fd = new FormData();
      fd.append('file', file);
      const res = await fetch('/api/admin/db/restore', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: fd,
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || 'Restore failed');

      dbActionStatus.textContent = data.message || 'Database restored successfully.';
      restoreDbFile.value = '';
      await loadUsers();
      alert('Database restored. Please refresh the app pages.');
    } catch (e) {
      dbActionStatus.textContent = e.message || 'Restore failed.';
    }
  });

  await loadUsers();
})();
