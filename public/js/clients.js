(async function () {
  const user = await ERP.requireLogin();
  if (!user) return;

  const form = document.getElementById('clientForm');
  const finalizedInput = form.querySelector('[name="finalized_amount"]');
  const advanceInput = form.querySelector('[name="advance_amount"]');
  const remainingInput = form.querySelector('[name="remaining_amount"]');
  document.getElementById('logoutBtn').addEventListener('click', ERP.logout);

  function calcRemaining() {
    const finalized = Number(finalizedInput.value || 0);
    const advance = Number(advanceInput.value || 0);
    const remaining = Math.max(finalized - advance, 0);
    remainingInput.value = remaining.toFixed(2);
  }

  async function loadClients() {
    const clients = await ERP.api('/api/clients');
    ERP.fillTable(
      'clientsTable',
      [
        'ID',
        'Name',
        'Phone',
        'Email',
        'Address',
        'No. of Vehicles',
        'Rent Days',
        'Finalized Amount',
        'Advance Payment',
        'Advance Mode',
        'Remaining Payment',
        'Remaining Mode',
      ],
      clients.map(
        (c) =>
          `<td>${c.id}</td><td>${c.name}</td><td>${c.phone || ''}</td><td>${c.email || ''}</td><td>${c.address || ''}</td><td>${c.vehicle_quantity ?? 0}</td><td>${c.rent_days ?? 0}</td><td>${Number(c.finalized_amount || 0).toFixed(2)}</td><td>${Number(c.advance_amount || 0).toFixed(2)}</td><td>${c.advance_mode || ''}</td><td>${Number(c.remaining_amount || 0).toFixed(2)}</td><td>${c.remaining_mode || ''}</td>`
      )
    );
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      calcRemaining();
      const data = ERP.formToObject(form);
      await ERP.api('/api/clients', { method: 'POST', body: JSON.stringify(data) });
      form.reset();
      calcRemaining();
      await loadClients();
      alert('Client details saved successfully.');
    } catch (err) {
      alert(err.message || 'Failed to save client details.');
    }
  });

  finalizedInput.addEventListener('input', calcRemaining);
  advanceInput.addEventListener('input', calcRemaining);
  calcRemaining();

  await loadClients();
})();
