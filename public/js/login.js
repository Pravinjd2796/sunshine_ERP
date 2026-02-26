(async function () {
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

  loginCard.classList.remove('hidden');

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
