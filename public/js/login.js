(async function () {
  const adminInitCard = document.getElementById('adminInitCard');
  try {
    const me = await ERP.api('/api/auth/me');
    if (me.user) {
      ERP.setUser(me.user);
      location.href = '/home.html';
      return;
    }
  } catch {
    // not logged in
  }

  try {
    const setup = await ERP.api('/api/auth/setup-status');
    if (setup.needs_admin) {
      adminInitCard.classList.remove('hidden');
    }
  } catch {
    // ignore
  }

  const tabLogin = document.getElementById('tabLogin');
  const tabRegister = document.getElementById('tabRegister');
  const loginPanel = document.getElementById('loginPanel');
  const registerPanel = document.getElementById('registerPanel');

  function showLoginTab() {
    tabLogin.classList.add('active');
    tabRegister.classList.remove('active');
    loginPanel.classList.remove('hidden');
    registerPanel.classList.add('hidden');
  }

  function showRegisterTab() {
    tabRegister.classList.add('active');
    tabLogin.classList.remove('active');
    registerPanel.classList.remove('hidden');
    loginPanel.classList.add('hidden');
  }

  tabLogin.addEventListener('click', showLoginTab);
  tabRegister.addEventListener('click', showRegisterTab);
  showLoginTab();

  const loginError = document.getElementById('loginError');
  const showResetBtn = document.getElementById('showResetBtn');
  const resetPanel = document.getElementById('resetPanel');

  document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    loginError.classList.add('hidden');
    showResetBtn.classList.add('hidden');
    try {
      const data = ERP.formToObject(e.target);
      const result = await ERP.api('/api/auth/login', { method: 'POST', body: JSON.stringify(data) });
      ERP.setToken(result.token);
      ERP.setUser(result.user);
      location.href = '/home.html';
    } catch (err) {
      const msg = err.message || 'Login failed';
      loginError.textContent = msg;
      loginError.classList.remove('hidden');
      if (msg.toLowerCase().includes('incorrect username/password')) {
        showResetBtn.classList.remove('hidden');
      }
    }
  });

  showResetBtn.addEventListener('click', () => {
    resetPanel.classList.remove('hidden');
  });

  document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const data = ERP.formToObject(e.target);
      const result = await ERP.api('/api/auth/register', { method: 'POST', body: JSON.stringify(data) });
      document.getElementById('registerHint').textContent = result.message || 'Registration successful. You can login now.';
      e.target.reset();
      showLoginTab();
    } catch (err) {
      alert(err.message || 'Registration failed');
    }
  });

  document.getElementById('adminInitForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const data = ERP.formToObject(e.target);
      const result = await ERP.api('/api/auth/bootstrap-admin', { method: 'POST', body: JSON.stringify(data) });
      document.getElementById('adminInitHint').textContent = result.message || 'Admin initialized. Please login.';
      e.target.reset();
    } catch (err) {
      document.getElementById('adminInitHint').textContent = err.message || 'Failed to initialize admin.';
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
      resetPanel.classList.add('hidden');
      showResetBtn.classList.add('hidden');
    } catch (err) {
      alert(err.message || 'Password reset failed');
    }
  });
})();
