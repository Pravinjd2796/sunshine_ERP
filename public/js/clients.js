(async function () {
  const user = await ERP.requireLogin();
  if (!user) return;

  const CACHE_KEY = 'erp_clients_cache';
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

  function renderClients(clients) {
    ERP.fillTable(
      'clientsTable',
      [
        'ID', 'Name', 'Phone', 'Email', 'Address', 'No. of Vehicles', 'Rent Days',
        'Finalized Amount', 'Advance Payment', 'Advance Mode', 'Remaining Payment', 'Remaining Mode'
      ],
      (clients || []).map(
        (c) =>
          `<td>${c.id ?? 'PENDING'}</td><td>${c.name}</td><td>${c.phone || ''}</td><td>${c.email || ''}</td><td>${c.address || ''}</td><td>${c.vehicle_quantity ?? 0}</td><td>${c.rent_days ?? 0}</td><td>${Number(c.finalized_amount || 0).toFixed(2)}</td><td>${Number(c.advance_amount || 0).toFixed(2)}</td><td>${c.advance_mode || ''}</td><td>${Number(c.remaining_amount || 0).toFixed(2)}</td><td>${c.remaining_mode || ''}</td>`
      )
    );
  }

  async function loadClients() {
    const cached = ERP.getCache(CACHE_KEY, []);
    if (cached.length) renderClients(cached);

    if (!ERP.isOnline()) return;
    const clients = await ERP.api('/api/clients');
    ERP.setCache(CACHE_KEY, clients);
    renderClients(clients);
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    calcRemaining();
    const data = ERP.formToObject(form);

    try {
      if (!ERP.isOnline()) throw new Error('offline');
      await ERP.api('/api/clients', { method: 'POST', body: JSON.stringify(data) });
      form.reset();
      calcRemaining();
      await loadClients();
      alert('Client details saved successfully.');
    } catch {
      ERP.queueAction({ url: '/api/clients', method: 'POST', body: data });
      const cached = ERP.getCache(CACHE_KEY, []);
      cached.unshift({ id: `PENDING-${Date.now()}`, ...data });
      ERP.setCache(CACHE_KEY, cached);
      renderClients(cached);
      form.reset();
      calcRemaining();
      alert('Saved offline. It will sync automatically when internet is back.');
    }
  });

  finalizedInput.addEventListener('input', calcRemaining);
  advanceInput.addEventListener('input', calcRemaining);
  calcRemaining();

  await ERP.flushOutbox();
  await loadClients();
  setInterval(async () => {
    await ERP.flushOutbox();
    await loadClients();
  }, 15000);
})();
