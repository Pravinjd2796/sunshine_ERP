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

  document.getElementById('resetRequestForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const data = ERP.formToObject(e.target);
      const result = await ERP.api('/api/auth/request-password-reset', {
        method: 'POST',
        body: JSON.stringify(data),
      });
      document.getElementById('resetVerifyMobileInput').value = data.mobile;
      document.getElementById('resetHint').textContent = result.dev_otp
        ? `DEV OTP: ${result.dev_otp}`
        : result.message;
    } catch (err) {
      alert(err.message || 'Failed to send OTP');
    }
  });

  document.getElementById('resetVerifyForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const data = ERP.formToObject(e.target);
      const result = await ERP.api('/api/auth/reset-password', {
        method: 'POST',
        body: JSON.stringify(data),
      });
      alert(result.message || 'Password reset successful');
      e.target.reset();
    } catch (err) {
      alert(err.message || 'Password reset failed');
    }
  });
})();
