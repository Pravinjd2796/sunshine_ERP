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
    const data = ERP.formToObject(e.target);
    if (!data.email && !data.mobile) {
      alert('Provide email or mobile for admin login.');
      return;
    }
    await ERP.api('/api/auth/bootstrap-admin', { method: 'POST', body: JSON.stringify(data) });
    alert('Admin created. Now login with OTP.');
    e.target.reset();
    setupCard.classList.add('hidden');
    loginCard.classList.remove('hidden');
  });

  document.getElementById('requestOtpForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = ERP.formToObject(e.target);
    const result = await ERP.api('/api/auth/request-otp', { method: 'POST', body: JSON.stringify(data) });
    document.getElementById('verifyIdentifierInput').value = data.identifier;
    document.getElementById('otpHint').textContent = result.dev_otp
      ? `DEV OTP: ${result.dev_otp}`
      : result.message;
  });

  document.getElementById('verifyOtpForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = ERP.formToObject(e.target);
    const result = await ERP.api('/api/auth/verify-otp', { method: 'POST', body: JSON.stringify(data) });
    ERP.setToken(result.token);
    location.href = '/home.html';
  });
})();
