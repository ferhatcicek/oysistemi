# Geliştirme

## Ortam

```bash
git clone <depo-adresi> oysistemi && cd oysistemi
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux: source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Node.js 18+ isteğe bağlıdır. Kurulu değilse `blindsig.js` ↔ Python çapraz testleri atlanır.

## Testler ve denetimler

```bash
python -m pytest                       # tüm testler (~2 dk)
python -m pytest tests/test_time.py -q # tek dosya
ruff check oysistemi tests scripts
bandit -q -c pyproject.toml -r oysistemi
pip-audit .
```

CI aynı denetimleri Windows ve Linux'ta, Python 3.12 ve 3.13 ile çalıştırır
(`.github/workflows/ci.yml`).

| Dosya | Kapsam |
|---|---|
| `test_voting.py` | Tek oy, yalnızca listedekiler, bağlanamazlık, eşzamanlı yarışlar |
| `test_tamper.py` | Doğrudan SQL ile kurcalama, tetikleyici silme, geçmişin yeniden yazılması |
| `test_governance.py` | İki kişi kuralı, durum makinesi |
| `test_time.py` | Saat manipülasyonu, mühür, otomatik kapanış, seçmen zinciri |
| `test_storage.py` | Alan şifreleme, DPAPI, kurtarma, yedek, ACL |
| `test_web.py` | HTTP üzerinden uçtan uca akış, CSRF/Origin, TOTP |
| `test_blindsig_js.py` | Tarayıcı kör imza kodunun Python ile uyumu (Node) |
| `test_ballot_types.py` | Oy türleri ve sayım |

Testler gerçek saat yerine `conftest.FakeClock` kullanır (`clock.advance(sn)`,
`clock.system_offset`). Zamana bağlı her yeni test bu fixture'ı kullanmalıdır.

## Yerel çalıştırma

```bash
python scripts/demo_setup.py demo
python -m oysistemi.cli --home demo serve --insecure-http
```

## Kurallar (güvenlik açısından kritik)

1. **Zaman:** `time.time()` ya da `datetime.now()` kullanmayın. Duvar saati için
   `timekeeping.get_clock()`, süre ölçümü için `time.monotonic()` kullanın.
2. **Sandık tarafı:** `ballots` tablosuna ya da `/cast` yoluna seçmen kimliği, zaman, IP, sıra
   numarası veya log eklemeyin.
3. **Mühür:** Oylama sürerken katılımı açığa çıkarabilecek yeni bir sayı, liste, sıra numarası
   ya da log satırı eklemeyin. Seçmen olayları `chain.record_voter_event` ile yazılır, ana
   zincire değil.
4. **Değişiklikler:** Seçmen/liste/yönetici/oylama durumu değişiklikleri `governance.propose`
   üzerinden geçmelidir. Hassas tablolara `insert_row`/`update_row` ile yazın (row MAC). Her
   değişiklikten önce `chain.record` çağrılmalıdır, aksi halde gölge log "bant dışı" alarmı verir.
5. **Şifreleme:** Kişisel veri ya da oy içeren yeni alanlar `fieldenc.encrypt` ile ve satıra
   özgü bir AAD ile yazılmalıdır.
6. **Şema:** `schema.sql` değişirse mevcut kurulumların şema parmak izi değişir ve uygulama
   açılmaz. Değişikliği CHANGELOG'da "şema değişikliği" olarak işaretleyin ve geçiş adımlarını
   yazın.
7. **Kriptografi:** Yeni bir ilkel eklemeyin; `cryptography` kütüphanesini ve mevcut
   yardımcıları kullanın.

## Yeni bir oy türü eklemek

1. `oysistemi/elections/ballot_types/` altında `BallotType`'tan türetin:
   `validate_config`, `validate` (yalnızca beklenen alanlar: `require_exact_keys`), `tally`.
   Sayım deterministik olmalıdır; rastgelelik gerekiyorsa yayımlanan pusulalardan tohum türetin.
2. `ballot_types/__init__.py` içindeki `REGISTRY`'ye ekleyin.
3. Yönetici formu için `web/routes_admin.py::parse_election_form` ve
   `templates/admin/_election_fields.html`; pusula için `templates/vote.html` ve
   `static/vote.js::readBallot`; sonuç için `templates/results.html`.
4. `tests/test_ballot_types.py` dosyasına testler ekleyin.

## Sürüm yayımlama

1. `oysistemi/__init__.py` içindeki `__version__` değerini artırın.
2. `CHANGELOG.md` dosyasını güncelleyin.
3. `git tag v0.x.y && git push --tags`
