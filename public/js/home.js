(async function () {
  const user = await ERP.requireLogin();
  if (!user) return;

  document.getElementById('userBadge').textContent = `${user.name} (${user.role})`;
  const adminBtn = document.getElementById('adminPanelBtn');
  const adminHelpText = document.getElementById('adminHelpText');
  if (user.role === 'ADMIN') {
    adminBtn.addEventListener('click', () => { location.href = '/users.html'; });
  } else {
    adminHelpText.textContent = 'Admin access required. Contact admin to get permission.';
    adminBtn.addEventListener('click', () => { alert('Only admin can access Admin Panel.'); });
  }
  document.getElementById('logoutBtn').addEventListener('click', ERP.logout);
})();
