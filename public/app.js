let authToken = localStorage.getItem('erp_token') || '';
let currentUser = null;
let syncIntervalStarted = false;

function setVisible(id, show) {
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.toggle('hidden', !show);
}

async function api(url, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (authToken) headers.Authorization = `Bearer ${authToken}`;

  const res = await fetch(url, { ...options, headers });
  if (res.status === 401) {
    authToken = '';
    currentUser = null;
    localStorage.removeItem('erp_token');
    showAuthOnly();
    throw new Error('Please login again');
  }

  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.error || 'Request failed');
  }
  return res.json();
}

function money(v) {
  return `Rs ${Number(v || 0).toFixed(2)}`;
}

function fillTable(id, headers, rows) {
  const table = document.getElementById(id);
  table.innerHTML = '';
  const thead = document.createElement('thead');
  thead.innerHTML = `<tr>${headers.map((h) => `<th>${h}</th>`).join('')}</tr>`;
  const tbody = document.createElement('tbody');
  rows.forEach((row) => {
    const tr = document.createElement('tr');
    tr.innerHTML = row;
    tbody.appendChild(tr);
  });
  table.append(thead, tbody);
}

function formToObject(form) {
  const fd = new FormData(form);
  return Object.fromEntries(fd.entries());
}

function showAuthOnly() {
  setVisible('appContent', false);
  setVisible('authInfo', false);
  setVisible('setupCard', false);
  setVisible('loginCard', true);
}

function showApp() {
  setVisible('setupCard', false);
  setVisible('loginCard', false);
  setVisible('appContent', true);
  setVisible('authInfo', true);

  document.getElementById('userBadge').textContent = `${currentUser.name} (${currentUser.role})`;
  setVisible('userMgmtCard', currentUser.role === 'ADMIN');
}

function ensureSyncPolling() {
  if (syncIntervalStarted) return;
  setInterval(refreshSyncLog, 30000);
  syncIntervalStarted = true;
}

async function refreshDashboard() {
  const d = await api('/api/dashboard');
  document.getElementById('dashboard').innerHTML = `
    <h2>Dashboard</h2>
    <div class="kpi">
      <div class="box"><div class="label">Total Vehicles</div><div class="value">${d.total_vehicles}</div></div>
      <div class="box"><div class="label">On Rent</div><div class="value">${d.on_rent}</div></div>
      <div class="box"><div class="label">Total Clients</div><div class="value">${d.total_clients}</div></div>
      <div class="box"><div class="label">Active Rentals</div><div class="value">${d.active_rentals}</div></div>
      <div class="box"><div class="label">Client Outstanding</div><div class="value">${money(d.client_outstanding)}</div></div>
      <div class="box"><div class="label">Staff Outstanding</div><div class="value">${money(d.staff_outstanding)}</div></div>
    </div>
  `;
}

let clients = [];
let vehicles = [];
let rentals = [];

async function refreshClients() {
  clients = await api('/api/clients');

  fillTable(
    'clientsTable',
    ['ID', 'Name', 'Phone', 'Email', 'Address'],
    clients.map(
      (c) => `<td>${c.id}</td><td>${c.name}</td><td>${c.phone || ''}</td><td>${c.email || ''}</td><td>${c.address || ''}</td>`
    )
  );

  const clientOptions = ['<option value="">Select Client</option>']
    .concat(clients.map((c) => `<option value="${c.id}">${c.name}</option>`))
    .join('');

  document.getElementById('clientSelect').innerHTML = clientOptions;
  document.getElementById('payClientSelect').innerHTML = clientOptions;
}

async function refreshVehicles() {
  vehicles = await api('/api/vehicles');

  fillTable(
    'vehiclesTable',
    ['ID', 'Vehicle', 'Driver', 'Driver Phone', 'Operator', 'Operator Phone', 'Location', 'Status'],
    vehicles.map(
      (v) => `<td>${v.id}</td><td>${v.vehicle_number}</td><td>${v.driver_name || ''}</td><td>${v.driver_phone || ''}</td><td>${v.operator_name || ''}</td><td>${v.operator_phone || ''}</td><td>${v.current_location || ''}</td><td>${v.status}</td>`
    )
  );

  const vehicleOptions = ['<option value="">Select Vehicle</option>']
    .concat(
      vehicles
        .filter((v) => v.status !== 'ON_RENT')
        .map((v) => `<option value="${v.id}">${v.vehicle_number}</option>`)
    )
    .join('');

  document.getElementById('vehicleSelect').innerHTML = vehicleOptions;
}

async function refreshRentals() {
  rentals = await api('/api/rentals');

  fillTable(
    'rentalsTable',
    [
      'ID',
      'Client',
      'Vehicle',
      'Dates',
      'Days',
      'Client Charges',
      'Client Received',
      'Client Pending',
      'Driver Pending',
      'Operator Pending',
      'Status',
      'Action',
    ],
    rentals.map((r) => {
      const statusClass = r.contract_status === 'ACTIVE' ? 'active' : 'closed';
      const closeBtn =
        r.contract_status === 'ACTIVE'
          ? `<button onclick="closeRental(${r.id})">Close</button>`
          : '';

      return `
        <td>${r.id}</td>
        <td>${r.client_name}</td>
        <td>${r.vehicle_number}</td>
        <td>${r.start_date} to ${r.end_date}</td>
        <td>${r.total_days}</td>
        <td>${money(r.client_finalized_charge)}</td>
        <td>${money(Number(r.client_advance) + Number(r.client_paid || 0))}</td>
        <td>${money(r.client_remaining)}</td>
        <td>${money(r.driver_remaining)}</td>
        <td>${money(r.operator_remaining)}</td>
        <td><span class="badge ${statusClass}">${r.contract_status}</span></td>
        <td>${closeBtn}</td>
      `;
    })
  );

  const rentalOptions = ['<option value="">General (No Rental)</option>']
    .concat(
      rentals
        .filter((r) => r.contract_status === 'ACTIVE')
        .map((r) => `<option value="${r.id}">#${r.id} - ${r.client_name} (${r.vehicle_number})</option>`)
    )
    .join('');

  document.getElementById('payRentalSelect').innerHTML = rentalOptions;
}

async function refreshPayments() {
  const payments = await api('/api/payments');

  fillTable(
    'paymentsTable',
    ['ID', 'Client', 'Rental', 'Vehicle', 'Amount', 'Type', 'Date', 'Reference'],
    payments.map(
      (p) => `<td>${p.id}</td><td>${p.client_name}</td><td>${p.rental_id || ''}</td><td>${p.vehicle_number || ''}</td><td>${money(p.amount)}</td><td>${p.payment_type}</td><td>${p.payment_date}</td><td>${p.reference_no || ''}</td>`
    )
  );
}

async function refreshSyncLog() {
  const logs = await api('/api/sync-log');
  fillTable(
    'syncTable',
    ['Time', 'Event', 'Status', 'Message'],
    logs.map((l) => `<td>${l.created_at}</td><td>${l.event_type}</td><td>${l.status}</td><td>${l.message || ''}</td>`)
  );
}

async function refreshUsers() {
  if (!currentUser || currentUser.role !== 'ADMIN') return;
  const users = await api('/api/users');
  fillTable(
    'usersTable',
    ['ID', 'Name', 'Email', 'Mobile', 'Role', 'Status'],
    users.map(
      (u) => `<td>${u.id}</td><td>${u.name}</td><td>${u.email || ''}</td><td>${u.mobile || ''}</td><td>${u.role}</td><td>${u.status}</td>`
    )
  );
}

async function refreshAll() {
  await refreshDashboard();
  await refreshClients();
  await refreshVehicles();
  await refreshRentals();
  await refreshPayments();
  await refreshSyncLog();
  await refreshUsers();
}

document.getElementById('setupForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const data = formToObject(e.target);
  if (!data.email && !data.mobile) {
    alert('Provide email or mobile for admin login.');
    return;
  }

  await api('/api/auth/bootstrap-admin', { method: 'POST', body: JSON.stringify(data) });
  e.target.reset();
  setVisible('setupCard', false);
  setVisible('loginCard', true);
  alert('Admin created. Now request OTP to login.');
});

document.getElementById('requestOtpForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const data = formToObject(e.target);
  const result = await api('/api/auth/request-otp', { method: 'POST', body: JSON.stringify(data) });

  document.getElementById('verifyIdentifierInput').value = data.identifier;
  const hint = document.getElementById('otpHint');
  if (result.dev_otp) {
    hint.textContent = `DEV OTP: ${result.dev_otp} (Set DEV_OTP_BYPASS=false in production)`;
  } else {
    hint.textContent = 'OTP sent successfully.';
  }
});

document.getElementById('verifyOtpForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const data = formToObject(e.target);
  const result = await api('/api/auth/verify-otp', { method: 'POST', body: JSON.stringify(data) });
  authToken = result.token;
  currentUser = result.user;
  localStorage.setItem('erp_token', authToken);
  showApp();
  await refreshAll();
  ensureSyncPolling();
  e.target.reset();
});

document.getElementById('logoutBtn').addEventListener('click', async () => {
  try {
    await api('/api/auth/logout', { method: 'POST' });
  } catch (err) {
    // ignore
  }
  authToken = '';
  currentUser = null;
  localStorage.removeItem('erp_token');
  showAuthOnly();
});

document.getElementById('userForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const data = formToObject(e.target);
  if (!data.email && !data.mobile) {
    alert('Provide email or mobile for user login.');
    return;
  }
  await api('/api/users', { method: 'POST', body: JSON.stringify(data) });
  e.target.reset();
  await refreshUsers();
});

document.getElementById('clientForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  await api('/api/clients', { method: 'POST', body: JSON.stringify(formToObject(e.target)) });
  e.target.reset();
  await refreshAll();
});

document.getElementById('vehicleForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api('/api/vehicles', { method: 'POST', body: JSON.stringify(formToObject(e.target)) });
    e.target.reset();
    await refreshAll();
  } catch (err) {
    alert(err.message);
  }
});

document.getElementById('rentalForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api('/api/rentals', { method: 'POST', body: JSON.stringify(formToObject(e.target)) });
    e.target.reset();
    await refreshAll();
  } catch (err) {
    alert(err.message);
  }
});

document.getElementById('paymentForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api('/api/payments', { method: 'POST', body: JSON.stringify(formToObject(e.target)) });
    e.target.reset();
    await refreshAll();
  } catch (err) {
    alert(err.message);
  }
});

window.closeRental = async (id) => {
  if (!confirm('Close this rental and mark vehicle AVAILABLE?')) return;
  await api(`/api/rentals/${id}/close`, { method: 'POST' });
  await refreshAll();
};

async function init() {
  const setup = await api('/api/auth/setup-status');
  if (setup.needs_admin) {
    setVisible('setupCard', true);
    setVisible('loginCard', false);
    setVisible('appContent', false);
    setVisible('authInfo', false);
    return;
  }

  if (!authToken) {
    showAuthOnly();
    return;
  }

  try {
    const me = await api('/api/auth/me');
    currentUser = me.user;
    showApp();
    await refreshAll();
    ensureSyncPolling();
  } catch (err) {
    showAuthOnly();
  }
}

init();
