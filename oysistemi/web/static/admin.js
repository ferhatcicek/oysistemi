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
  const printBtn = document.getElementById('print');
  if (printBtn) printBtn.addEventListener('click', () => window.print());
})();
