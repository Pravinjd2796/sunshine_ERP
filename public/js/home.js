(async function () {
  const user = await ERP.requireLogin();
  if (!user) return;

  document.getElementById('userBadge').textContent = `${user.name} (${user.role})`;
  if (user.role === 'ADMIN') {
    document.getElementById('adminUsersOption').classList.remove('hidden');
  }
  document.getElementById('logoutBtn').addEventListener('click', ERP.logout);
})();
