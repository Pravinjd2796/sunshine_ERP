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

  async function loadUsers() {
    const users = await ERP.api('/api/users');
    ERP.fillTable(
      'usersTable',
      ['ID', 'Username', 'Name', 'Email', 'Mobile', 'Role', 'Status', 'Has Login', 'Actions'],
      users.map((u) => {
        const toggleLabel = u.status === 'ACTIVE' ? 'Disable' : 'Enable';
        const nextStatus = u.status === 'ACTIVE' ? 'INACTIVE' : 'ACTIVE';
        return `<td>${u.id}</td><td>${u.username || ''}</td><td>${u.name}</td><td>${u.email || ''}</td><td>${u.mobile || ''}</td><td>${u.role}</td><td>${u.status}</td><td>${u.has_password ? 'Yes' : 'No'}</td><td><button onclick="resetCredentials(${u.id}, '${u.username || ''}')">Reset Login</button> <button onclick="toggleUserStatus(${u.id}, '${nextStatus}')">${toggleLabel}</button> <button onclick="deleteUser(${u.id})">Delete</button></td>`;
      })
    );
  }

  window.toggleUserStatus = async (id, status) => {
    try {
      await ERP.api(`/api/users/${id}`, { method: 'PATCH', body: JSON.stringify({ status }) });
      await loadUsers();
    } catch (e) {
      alert(e.message);
    }
  };

  window.deleteUser = async (id) => {
    if (!confirm('Delete this user?')) return;
    try {
      await ERP.api(`/api/users/${id}`, { method: 'DELETE' });
      await loadUsers();
    } catch (e) {
      alert(e.message);
    }
  };

  window.resetCredentials = async (id, currentUsername) => {
    const username = prompt('Enter new username', currentUsername || '');
    if (!username) return;
    const password = prompt('Enter new password (min 6 chars)');
    if (!password) return;
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
  };

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

  await loadUsers();
})();
