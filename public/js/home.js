(async function () {
  const user = await ERP.requireLogin();
  if (!user) return;

  document.getElementById('userBadge').textContent = `${user.name} (${user.role})`;
  const adminCard = document.getElementById('adminUsersOption');
  const adminBtn = document.getElementById('adminPanelBtn');
  if (user.role === 'ADMIN') {
    adminCard.classList.remove('hidden');
    adminBtn.addEventListener('click', () => { location.href = '/users.html'; });
  }
  document.getElementById('logoutBtn').addEventListener('click', ERP.logout);
})();
