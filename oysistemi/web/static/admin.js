(function () {
  'use strict';
  // Oy türüne göre ilgili yapılandırma alanlarını göster.
  const sel = document.getElementById('f-type');
  if (sel) {
    const sync = () => {
      document.querySelectorAll('[data-types]').forEach((el) => {
        el.classList.toggle('hidden', !el.dataset.types.split(' ').includes(sel.value));
      });
    };
    sel.addEventListener('change', sync);
    sync();
  }
  // Geri alınamaz işlemlerde onay iste.
  document.querySelectorAll('form[data-confirm]').forEach((f) => {
    f.addEventListener('submit', (ev) => { if (!confirm(f.dataset.confirm)) ev.preventDefault(); });
  });
  // Kurulum anahtarını panoya kopyala (TOTP elle giriş).
  document.querySelectorAll('[data-copy]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const status = btn.parentElement.querySelector('[data-copy-status]');
      try {
        await navigator.clipboard.writeText(btn.dataset.copy);
        if (status) status.textContent = 'Kopyalandı.';
      } catch (e) {
        if (status) status.textContent = 'Kopyalanamadı; anahtarı elle seçin.';
      }
    });
  });
  const printBtn = document.getElementById('print');
  if (printBtn) printBtn.addEventListener('click', () => window.print());
})();
