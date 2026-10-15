/*
 * Oy verme akışı (tarayıcı):
 *   1. Pusula doldurulur ve tarayıcıda doğrulanır.
 *   2. Rastgele token üretilir, KÖRLENİR, oturum çereziyle /issue'ya gönderilir.
 *   3. Kör imza çözülür (finalize) ve WebCrypto ile doğrulanır.
 *   4. Oturum kapatılır, rastgele süre beklenir.
 *   5. token + imza + pusula ÇEREZSİZ olarak /cast'e gönderilir.
 *
 * Token/körleme bilgisi oy atılana kadar localStorage'da tutulur: bağlantı koparsa aynı
 * körlenmiş mesajla tekrar denenir ve sunucu aynı imzayı verir (ikinci oy hakkı doğmaz).
 */
(function () {
  'use strict';
  const form = document.getElementById('ballot');
  if (!form) return;
  const eid = form.dataset.election, type = form.dataset.type, csrf = form.dataset.csrf;
  const credKey = 'oys:cred:' + eid, receiptKey = 'oys:receipt:' + eid;
  const B = window.BlindSig;
  const $ = (id) => document.getElementById(id);

  function store(key, value) {
    try { value === null ? localStorage.removeItem(key) : localStorage.setItem(key, JSON.stringify(value)); }
    catch (e) { /* özel pencere: yalnızca bellekte devam */ }
  }
  function load(key) {
    try { return JSON.parse(localStorage.getItem(key)); } catch (e) { return null; }
  }

  function readBallot() {
    if (type === 'single' || type === 'yes_no') {
      const c = form.querySelector('input[name=choice]:checked');
      if (!c) throw new Error('Lütfen bir seçenek işaretleyin.');
      return { choice: c.value === '' ? null : c.value };
    }
    if (type === 'multi' || type === 'approval') {
      return { choices: [...form.querySelectorAll('input[name=choices]:checked')].map((x) => x.value) };
    }
    const ranks = [...form.querySelectorAll('select[name=rank]')]
      .filter((s) => s.value !== '')
      .map((s) => ({ option: s.dataset.option, rank: Number(s.value) }));
    const nums = ranks.map((r) => r.rank).sort((a, b) => a - b);
    if (!nums.length) throw new Error('En az bir seçeneği sıralayın.');
    if (nums.some((n, i) => n !== i + 1)) {
      throw new Error('Sıra numaraları 1\'den başlamalı, tekrarsız ve boşluksuz olmalı.');
    }
    return { ranking: ranks.sort((a, b) => a.rank - b.rank).map((r) => r.option) };
  }

  async function postJSON(url, body, withCookies, headers) {
    const r = await fetch(url, {
      method: 'POST', credentials: withCookies ? 'same-origin' : 'omit', cache: 'no-store',
      headers: Object.assign({ 'Content-Type': 'application/json' }, headers || {}),
      body: JSON.stringify(body),
    });
    let data = {};
    try { data = await r.json(); } catch (e) { /* boş yanıt */ }
    return { status: r.status, data };
  }

  function mark(id) { $(id).style.fontWeight = '700'; }

  async function getCredential(pk) {
    let cred = load(credKey);
    if (cred && cred.sig) return cred;
    if (!cred) {
      const prepared = B.prepare();
      const { blinded, inv } = await B.blind(pk, prepared);
      cred = { prepared: B.b64encode(prepared), blinded: B.b64encode(blinded), inv: B.b64encode(inv) };
      store(credKey, cred);  // istek yanıtsız kalırsa aynı körlenmiş mesajla yeniden denenir
    }
    const r = await postJSON('/api/e/' + eid + '/issue', { blinded: cred.blinded }, true,
      { 'X-CSRF-Token': csrf });
    if (r.status === 409) {
      throw new Error('Bu oylama için oy hakkınız daha önce başka bir cihazda/tarayıcıda alınmış. ' +
        'Oyunuzu oradan verebilirsiniz.');
    }
    if (r.status === 401) throw new Error('Oturumunuz sona ermiş. Lütfen tekrar giriş yapın.');
    if (r.status !== 200) throw new Error('Oy hakkı alınamadı: ' + (r.data.detail || r.status));
    const sig = await B.finalize(pk, B.b64decode(cred.prepared), B.b64decode(r.data.blind_sig),
      B.b64decode(cred.inv));
    cred.sig = B.b64encode(sig);
    store(credKey, cred);
    return cred;
  }

  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const errBox = $('form-error');
    errBox.classList.add('hidden');
    let ballot;
    try { ballot = readBallot(); } catch (e) {
      errBox.textContent = e.message; errBox.classList.remove('hidden'); return;
    }
    if (!confirm('Oyunuz gönderildikten sonra değiştirilemez. Onaylıyor musunuz?')) return;
    $('submit').disabled = true;
    form.classList.add('hidden');
    $('progress').classList.remove('hidden');
    try {
      const pkRes = await fetch('/api/e/' + eid + '/key', { credentials: 'omit' });
      const pk = await pkRes.json();
      mark('st-issue');
      const cred = await getCredential(pk);

      mark('st-logout');
      await fetch('/voter/logout', { method: 'POST', credentials: 'same-origin' });

      mark('st-wait');
      const wait = 3 + Math.floor(Math.random() * 8);
      for (let s = wait; s > 0; s--) {
        $('wait-left').textContent = '(' + s + ' sn)';
        await new Promise((res) => setTimeout(res, 1000));
      }
      $('wait-left').textContent = '';

      mark('st-cast');
      const r = await postJSON('/api/e/' + eid + '/cast',
        { token: cred.prepared, sig: cred.sig, ballot: ballot }, false);
      if (r.status === 409) throw new Error('Bu oy hakkı zaten kullanılmış.');
      if (r.status !== 200) throw new Error('Oy sandığa atılamadı: ' + (r.data.detail || r.status));
      store(credKey, null);
      store(receiptKey, r.data.receipt);
      $('receipt').textContent = r.data.receipt;
      $('progress').classList.add('hidden');
      $('done').classList.remove('hidden');
    } catch (e) {
      $('progress').classList.add('hidden');
      form.classList.remove('hidden');
      $('submit').disabled = false;
      errBox.textContent = e.message;
      errBox.classList.remove('hidden');
    }
  });
})();
