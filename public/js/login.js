(async function () {
  const setupCard = document.getElementById('setupCard');
  const loginCard = document.getElementById('loginCard');

  try {
    const me = await ERP.api('/api/auth/me');
    if (me.user) {
      location.href = '/home.html';
      return;
    }
  } catch {
    // not logged in
  }

  const setup = await ERP.api('/api/auth/setup-status');
  setupCard.classList.toggle('hidden', !setup.needs_admin);
  loginCard.classList.toggle('hidden', setup.needs_admin);

  document.getElementById('setupForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const data = ERP.formToObject(e.target);
      await ERP.api('/api/auth/bootstrap-admin', { method: 'POST', body: JSON.stringify(data) });
      alert('Admin created. Now login with username and password.');
      e.target.reset();
      setupCard.classList.add('hidden');
      loginCard.classList.remove('hidden');
    } catch (err) {
      alert(err.message || 'Failed to create admin');
    }
  });

  document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const data = ERP.formToObject(e.target);
      const result = await ERP.api('/api/auth/login', { method: 'POST', body: JSON.stringify(data) });
      ERP.setToken(result.token);
      location.href = '/home.html';
    } catch (err) {
      alert(err.message || 'Login failed');
    }
  });
})();
