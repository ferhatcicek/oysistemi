// blindsig.js'i Python sunucu kodu ile çapraz test etmek için sürücü.
// Kullanım: node js_driver.js <blindsig.js yolu>   (stdin: JSON komut, stdout: JSON sonuç)
const BlindSig = require(process.argv[2]);
let input = '';
process.stdin.on('data', (d) => { input += d; });
process.stdin.on('end', async () => {
  const req = JSON.parse(input);
  const b = BlindSig.b64decode, e = BlindSig.b64encode;
  if (req.op === 'blind') {
    const prepared = BlindSig.prepare();
    const { blinded, inv } = await BlindSig.blind(req.pk, prepared);
    console.log(JSON.stringify({ prepared: e(prepared), blinded: e(blinded), inv: e(inv) }));
  } else if (req.op === 'finalize') {
    const sig = await BlindSig.finalize(req.pk, b(req.prepared), b(req.blind_sig), b(req.inv));
    console.log(JSON.stringify({ sig: e(sig) }));
  } else if (req.op === 'verify') {
    console.log(JSON.stringify({ ok: await BlindSig.verify(req.pk, b(req.prepared), b(req.sig)) }));
  }
});
