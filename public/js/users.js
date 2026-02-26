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
      ['ID', 'Name', 'Email', 'Mobile', 'Role', 'Status', 'Actions'],
      users.map((u) => {
        const toggleLabel = u.status === 'ACTIVE' ? 'Disable' : 'Enable';
        const nextStatus = u.status === 'ACTIVE' ? 'INACTIVE' : 'ACTIVE';
        return `<td>${u.id}</td><td>${u.name}</td><td>${u.email || ''}</td><td>${u.mobile || ''}</td><td>${u.role}</td><td>${u.status}</td><td><button onclick="toggleUserStatus(${u.id}, '${nextStatus}')">${toggleLabel}</button> <button onclick="deleteUser(${u.id})">Delete</button></td>`;
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

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = ERP.formToObject(form);
    if (!data.email && !data.mobile) {
      alert('Provide email or mobile');
      return;
    }
    await ERP.api('/api/users', { method: 'POST', body: JSON.stringify(data) });
    form.reset();
    await loadUsers();
  });

  await loadUsers();
})();
