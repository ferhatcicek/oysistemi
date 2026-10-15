(function () {
  'use strict';
  const btn = document.getElementById('receipt-check');
  if (!btn) return;
  const eid = btn.dataset.election;
  const input = document.getElementById('receipt-input');
  const out = document.getElementById('receipt-result');
  try {
    const saved = JSON.parse(localStorage.getItem('oys:receipt:' + eid));
    if (saved) input.value = saved;
  } catch (e) { /* yok */ }
  let board = null;
  btn.addEventListener('click', async () => {
    const q = input.value.trim().toLowerCase();
    if (!q) return;
    // Tüm ilan panosu indirilir, arama yerelde yapılır: sunucu hangi makbuzun sorgulandığını bilmez.
    if (!board) board = await (await fetch('/api/e/' + eid + '/bulletin.json', { credentials: 'omit' })).json();
    out.textContent = board.receipts.includes(q)
      ? '✅ Makbuzunuz sandıkta ve sayıma dahil.'
      : '❌ Bu makbuz listede yok. Numarayı kontrol edin; sorun sürerse yöneticilere bildirin.';
  });
})();
