/*
 * RFC 9474 RSABSSA-SHA384-PSS-Randomized — istemci tarafı (körleme ve körlemeyi kaldırma).
 * Bağımlılık yok: BigInt + WebCrypto. Tarayıcıda ve Node (>=19) üzerinde çalışır.
 *
 * Gizlilik bu dosyaya dayanır: token ve körleme faktörü r YALNIZCA burada üretilir,
 * sunucuya yalnızca körlenmiş mesaj gider.
 */
(function (root) {
  'use strict';
  const webcrypto = root.crypto || globalThis.crypto;
  const subtle = webcrypto.subtle;
  const H_LEN = 48, SALT_LEN = 48, PREFIX_LEN = 32, TOKEN_LEN = 32;

  function random(n) { const b = new Uint8Array(n); webcrypto.getRandomValues(b); return b; }

  function concat(...parts) {
    const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }

  function os2ip(b) { let x = 0n; for (const v of b) x = (x << 8n) | BigInt(v); return x; }

  function i2osp(x, len) {
    const out = new Uint8Array(len);
    for (let i = len - 1; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
    if (x !== 0n) throw new Error('integer too large');
    return out;
  }

  function modPow(b, e, m) {
    let r = 1n; b %= m;
    while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
    return r;
  }

  function gcd(a, b) { while (b) [a, b] = [b, a % b]; return a; }

  function modInv(a, m) {
    let [r0, r1, s0, s1] = [a % m, m, 1n, 0n];
    while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
    if (r0 !== 1n) throw new Error('not invertible');
    return ((s0 % m) + m) % m;
  }

  async function sha384(data) { return new Uint8Array(await subtle.digest('SHA-384', data)); }

  async function mgf1(seed, len) {
    let out = new Uint8Array(0);
    for (let c = 0; out.length < len; c++) {
      out = concat(out, await sha384(concat(seed, i2osp(BigInt(c), 4))));
    }
    return out.slice(0, len);
  }

  // RFC 8017 §9.1.1
  async function emsaPssEncode(msg, emBits, salt) {
    const mHash = await sha384(msg);
    const emLen = Math.ceil(emBits / 8);
    if (emLen < H_LEN + salt.length + 2) throw new Error('encoding error');
    const h = await sha384(concat(new Uint8Array(8), mHash, salt));
    const db = concat(new Uint8Array(emLen - salt.length - H_LEN - 2), Uint8Array.of(1), salt);
    const mask = await mgf1(h, emLen - H_LEN - 1);
    const masked = db.map((v, i) => v ^ mask[i]);
    masked[0] &= 0xff >> (8 * emLen - emBits);
    return concat(masked, h, Uint8Array.of(0xbc));
  }

  function pubFromJson(pk) {
    return { n: BigInt('0x' + pk.n), e: BigInt('0x' + pk.e), bits: pk.bits,
             k: Math.ceil(pk.bits / 8), spki: b64decode(pk.spki) };
  }

  /** 32 bayt rastgele önek + 32 bayt rastgele token (RFC 9474 §4.1). */
  function prepare() { return concat(random(PREFIX_LEN), random(TOKEN_LEN)); }

  async function blind(pkJson, prepared) {
    const pk = pubFromJson(pkJson);
    const m = os2ip(await emsaPssEncode(prepared, pk.bits - 1, random(SALT_LEN)));
    if (gcd(m, pk.n) !== 1n) throw new Error('invalid input');
    let r;
    do { r = os2ip(random(pk.k)) % pk.n; } while (r < 2n || gcd(r, pk.n) !== 1n);
    const z = (m * modPow(r, pk.e, pk.n)) % pk.n;
    return { blinded: i2osp(z, pk.k), inv: i2osp(modInv(r, pk.n), pk.k) };
  }

  async function verify(pkJson, prepared, sig) {
    const key = await subtle.importKey('spki', b64decode(pkJson.spki),
      { name: 'RSA-PSS', hash: 'SHA-384' }, false, ['verify']);
    return subtle.verify({ name: 'RSA-PSS', saltLength: SALT_LEN }, key, sig, prepared);
  }

  async function finalize(pkJson, prepared, blindSig, inv) {
    const pk = pubFromJson(pkJson);
    if (blindSig.length !== pk.k) throw new Error('unexpected input size');
    const sig = i2osp((os2ip(blindSig) * os2ip(inv)) % pk.n, pk.k);
    // Sunucunun verdiği imza bağımsız (WebCrypto) doğrulayıcıdan geçmeli.
    if (!(await verify(pkJson, prepared, sig))) throw new Error('invalid signature');
    return sig;
  }

  function b64encode(bytes) {
    let s = ''; for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s);
  }
  function b64decode(str) { return Uint8Array.from(atob(str), (c) => c.charCodeAt(0)); }

  const api = { prepare, blind, finalize, verify, b64encode, b64decode };
  root.BlindSig = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
