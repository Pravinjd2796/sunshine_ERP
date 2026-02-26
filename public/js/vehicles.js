(async function () {
  const user = await ERP.requireLogin();
  if (!user) return;

  const form = document.getElementById('vehicleForm');
  const clientSelect = form.querySelector('#clientSelect');
  const driverFinalizedInput = form.querySelector('[name="driver_finalized_amount"]');
  const driverAdvanceInput = form.querySelector('[name="driver_advance_amount"]');
  const driverRemainingInput = form.querySelector('[name="driver_remaining_amount"]');
  const operatorFinalizedInput = form.querySelector('[name="operator_finalized_amount"]');
  const operatorAdvanceInput = form.querySelector('[name="operator_advance_amount"]');
  const operatorRemainingInput = form.querySelector('[name="operator_remaining_amount"]');
  document.getElementById('logoutBtn').addEventListener('click', ERP.logout);

  async function loadClients() {
    const clients = await ERP.api('/api/clients');
    clientSelect.innerHTML = ['<option value="">Select Client</option>']
      .concat(clients.map((c) => `<option value="${c.id}">${c.name}</option>`))
      .join('');
  }

  function calcDriverRemaining() {
    const finalized = Number(driverFinalizedInput.value || 0);
    const advance = Number(driverAdvanceInput.value || 0);
    driverRemainingInput.value = Math.max(finalized - advance, 0).toFixed(2);
  }

  function calcOperatorRemaining() {
    const finalized = Number(operatorFinalizedInput.value || 0);
    const advance = Number(operatorAdvanceInput.value || 0);
    operatorRemainingInput.value = Math.max(finalized - advance, 0).toFixed(2);
  }

  async function loadVehicles() {
    const vehicles = await ERP.api('/api/vehicles');
    ERP.fillTable(
      'vehiclesTable',
      [
        'ID',
        'Client',
        'Vehicle',
        'Driver',
        'Driver Phone',
        'Operator',
        'Operator Phone',
        'Location',
        'Rent Days',
        'Driver Finalized',
        'Driver Advance',
        'Driver Advance Mode',
        'Driver Remaining',
        'Driver Remaining Mode',
        'Operator Finalized',
        'Operator Advance',
        'Operator Advance Mode',
        'Operator Remaining',
        'Operator Remaining Mode',
        'Status',
      ],
      vehicles.map(
        (v) =>
          `<td>${v.id}</td><td>${v.client_name || ''}</td><td>${v.vehicle_number}</td><td>${v.driver_name || ''}</td><td>${v.driver_phone || ''}</td><td>${v.operator_name || ''}</td><td>${v.operator_phone || ''}</td><td>${v.current_location || ''}</td><td>${v.rent_days ?? 0}</td><td>${Number(v.driver_finalized_amount || 0).toFixed(2)}</td><td>${Number(v.driver_advance_amount || 0).toFixed(2)}</td><td>${v.driver_advance_mode || ''}</td><td>${Number(v.driver_remaining_amount || 0).toFixed(2)}</td><td>${v.driver_remaining_mode || ''}</td><td>${Number(v.operator_finalized_amount || 0).toFixed(2)}</td><td>${Number(v.operator_advance_amount || 0).toFixed(2)}</td><td>${v.operator_advance_mode || ''}</td><td>${Number(v.operator_remaining_amount || 0).toFixed(2)}</td><td>${v.operator_remaining_mode || ''}</td><td>${v.status}</td>`
      )
    );
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      calcDriverRemaining();
      calcOperatorRemaining();
      const data = ERP.formToObject(form);
      await ERP.api('/api/vehicles', { method: 'POST', body: JSON.stringify(data) });
      form.reset();
      calcDriverRemaining();
      calcOperatorRemaining();
      await loadVehicles();
      alert('Vehicle details saved successfully.');
    } catch (err) {
      alert(err.message || 'Failed to save vehicle details.');
    }
  });

  driverFinalizedInput.addEventListener('input', calcDriverRemaining);
  driverAdvanceInput.addEventListener('input', calcDriverRemaining);
  operatorFinalizedInput.addEventListener('input', calcOperatorRemaining);
  operatorAdvanceInput.addEventListener('input', calcOperatorRemaining);
  calcDriverRemaining();
  calcOperatorRemaining();

  await loadClients();
  await loadVehicles();
})();
