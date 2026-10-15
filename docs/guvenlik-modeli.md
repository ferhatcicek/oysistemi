# Güvenlik modeli

Bu belge OySistemi'nin neyi, kime karşı, nasıl koruduğunu ve neyi **korumadığını** anlatır.
Denetçiler ve güvenlik araştırmacıları için yazılmıştır.

## Korunan varlıklar ve hedefler

| # | Hedef | Tanım |
|---|---|---|
| H1 | Oy gizliliği | Hiç kimse, sunucu işletmecisi ve veritabanının tamamına sahip biri dahil, bir oyu bir seçmene bağlayamaz. |
| H2 | Uygunluk | Yalnızca mühürlü listedeki, kimliği doğrulanmış seçmenler oy kullanabilir. |
| H3 | Tekillik | Her seçmen en fazla bir oy kullanır. |
| H4 | Bütünlük | Oylar ve seçmen listesi değiştirilemez, silinemez, eklenemez; denenirse tespit edilir. |
| H5 | Mühür | Bitiş zamanından önce katılım ve sonuç hiç kimseye görünmez. |
| H6 | Doğrulanabilirlik | Seçmen oyunun sayıldığını doğrulayabilir; herkes sonucu yeniden sayabilir. |
| H7 | Gizlilik (veri) | Kişisel veriler ve oylar, dosya düzeyinde ele geçirilse bile okunamaz. |

## Tehdit aktörleri

| Aktör | Yetenek |
|---|---|
| Dış saldırgan | HTTP isteklerini gönderebilir, ağ trafiğini (HTTPS dışında) gözleyebilir |
| Kötü niyetli seçmen | Kendi kimlik bilgileri; çift oy, başkası adına oy, oy satışı dener |
| Kötü niyetli tek yönetici | Panelde her şeyi yapabilir; tek başına onay veremez |
| Sunucuda dosya erişimi olan kişi | DB dosyasını okuyabilir/değiştirebilir, `sqlite3` ile doğrudan SQL çalıştırabilir, tetikleyicileri silebilir, sistem saatini değiştirebilir; **ana anahtarı açamaz** (DPAPI/parola) |
| Yedek ortamını çalan kişi | `.oysbak` ve checkpoint dosyalarına sahip |

## Mekanizmalar

### Kör imza ile oy hakkı (H1, H2, H3)

- **RFC 9474 RSABSSA-SHA384-PSS-Randomized**, oylama başına RSA-3072 anahtarı.
- Tarayıcı 32 bayt rastgele önek + 32 bayt rastgele belirteç üretir, körler (`web/static/blindsig.js`).
- Issuer, kimliği doğrulanmış seçmene **en fazla bir** kör imza verir:
  `credential_issuance (election_id, voter_id)` birincil anahtardır. Aynı körlenmiş mesajla
  yapılan tekrar istek aynı imzayı döner (bağlantı kopmasına karşı); farklı mesaj reddedilir.
- Sandık (`/api/e/{id}/cast`) kimlik sormaz, çerez okumaz, IP kullanmaz. Geçerli imza ve
  kullanılmamış belirteç ister: `ballots (election_id, token_hash)` birincil anahtardır.
- `ballots` tablosu `WITHOUT ROWID`'dir; fiziksel sıra `token_hash`'e göredir ve ekleme sırası
  saklanmaz. Zaman damgası tutulmaz. Sunucu erişim logu kapalıdır.
- Tarayıcı oturumu kapatıp 3–10 sn rastgele bekledikten sonra oyu gönderir.
- Kapanışta özel anahtar imha edilir (`privkey_wrapped = NULL`, `secure_delete`, `VACUUM`).

### Pusula biçimi (oy satışına karşı)

Pusula yalnızca beklenen alanları içerebilir (`require_exact_keys`). Serbest alan olsaydı
seçmen oyuna kendine özgü bir işaret koyup oyunu kanıtlayabilirdi. İlan panosu, makbuz
listesini ve oy içeriklerini birbirinden bağımsız sıralanmış iki ayrı liste olarak yayımlar.
Böylece makbuz oyun sayıldığını kanıtlar ama içeriğini kanıtlamaz.

### İki kişi kuralı (H4)

`admin/governance.py`: kritik değişiklikler `change_requests` olarak önerilir ve öneren dışındaki
`OYS_REQUIRED_APPROVALS` yöneticinin onayıyla, onayla **aynı işlemde** uygulanır.

### Veritabanı düzeyi korumalar (H4)

`db/schema.sql`:

- **Salt ekleme:** `audit_log`, `voter_log`, `shadow_log`, `approvals`, `checkpoints`, `ballots`,
  `credential_issuance` tablolarında UPDATE/DELETE tetikleyiciyle reddedilir.
- **Silme yasağı:** `voters`, `admins` ve `elections` silinemez.
- **Dondurma:** Oylama açıldıktan sonra seçmen listesi, yapılandırma ve mühürler değişemez.
  Durum geçişleri yalnızca ileri yönlüdür.
- **Zaman:** Denetim ve seçmen kaydı zaman damgası geriye gidemez.
- **Gölge log:** `voters`, `admins`, `elections`, `election_voters` ve `change_requests`
  tablolarındaki her değişiklik, o anki denetim sıra numarasıyla (`_ctx`) kaydedilir. Numara
  NULL ise değişiklik uygulama dışından yapılmıştır.

### Kriptografik tespit (tetikleyiciler silinse bile; H4)

Ana anahtardan HKDF-SHA256 ile türetilen alt anahtarlar (`oysistemi/rowmac`, `audit`, `wrap`,
`checkpoint`, `session`, `field`):

- **Satır MAC'i:** Hassas tablolardaki her satır HMAC-SHA256 ile imzalanır. Uygulama dışından
  eklenen ya da değiştirilen satır tespit edilir.
- **Denetim zinciri:** `entry_hash = SHA256(prev_hash ‖ kanonik(kayıt))`, `entry_mac = HMAC(entry_hash)`.
- **Seçmen olay zinciri:** Her oylama için ayrı bir zincir tutulur. Kapanışta zincirin başı ana
  zincire mühürlenir.
- **Harici checkpoint:** Tablo özetleri ve sayımlar HMAC ile imzalanıp DB dışındaki dosyaya
  eklenir. Satır silindiğinde tespit edilir.
- **Şema parmak izi:** `sqlite_master` paketteki şemayla karşılaştırılır; farklıysa uygulama
  açılmaz ya da çalışırken bir sonraki istekte kilitlenir.

### Mühür ve güvenilir zaman (H5)

- Bitiş zamanı (`closes_at`) zorunludur ve açılışta `config_hash` içinde mühürlenir.
- Kapanış ve sayım yalnızca `güvenilir_zaman ≥ closes_at` iken yapılır; erken kapanış
  `ElectionStateError` ile reddedilir.
- Katılım sızıntı kanalları kapatılmıştır:
  - yönetici ekranında sayı yok,
  - seçmen olayları ana zincirde değil (sıra boşluğu oluşmaz, checkpoint'teki `audit_seq` değişmez),
  - doğrulayıcı mesajlarında sayı yok,
  - sonuç ve ilan panosu yok.
- **Güvenilir saat** (`timekeeping.py`):
  - En az 2 bağımsız NTP kaynağı medyana 30 sn içinde uymalıdır.
  - Uygulama zamanı = çapa + monotonik sayaç, yani çalışırken sistem saatinin değişmesi uygulamayı etkilemez.
  - Denetim kayıtlarındaki en büyük zaman alt sınırdır; saat bunun gerisine düşerse işlem durur.
  - Doğrulanamayan zamanda oy verme sürer, kapanış bekler.
- Oturum çerezlerinin süresi ve TOTP de güvenilir saati kullanır. Kilitleme sayaçları
  monotonik saati kullanır.

### Kimlik doğrulama

- **Yeni yönetici:** Hesap parolasız oluşturulur ve iki parçalı kayıt belirteciyle sahibi
  tarafından etkinleştirilir. A parçası yalnızca önerene, B parçası yalnızca onaylayana bir kez
  gösterilir (`admin/enrollment.py`). Öneren kimlik bilgisi belirleyemez; aksi halde onaydan
  sonra hesaba girip TOTP'yi kendine kaydederek tek başına iki hesabı kontrol edebilirdi.
- **Yönetici:** argon2id parola ve **zorunlu** TOTP. TOTP sırrı AES-GCM ile şifrelidir ve aynı
  kod tekrar kullanılamaz. 5 hatadan sonra 15 dakika kilit. Oturum çerezi HMAC ile imzalıdır,
  `HttpOnly`, `SameSite=Strict`, `Secure`.
- **Seçmen:** basılı kod (~60 bit) ya da e-posta kodu (8 hane, 10 dk, tek kullanım). İkisi de
  argon2 ile özetlenir, kod başına 5 deneme hakkı vardır. Bilinmeyen seçmende de sabit süre
  harcanır; e-posta isteğine her durumda aynı yanıt verilir, böylece kimin listede olduğu
  dışarıdan anlaşılamaz.
- **Web:**
  - Katı CSP (`script-src 'self'`, satır içi betik ya da stil yok), `X-Frame-Options: DENY`,
    `Referrer-Policy: same-origin`.
  - Durum değiştiren isteklerde `Sec-Fetch-Site`/`Origin` denetimi ve form CSRF belirteci.

### Durağan veri (H7)

- **AES-256-GCM alan şifreleme** (`crypto/fieldenc.py`) şu alanlara uygulanır: `voters.display_name`,
  `voters.email`, `ballots.ballot`, `audit_log.payload`, `voter_log.payload`,
  `change_requests.payload`. AAD değeri `tablo.sütun/<satır anahtarı>` biçimindedir, bu yüzden
  şifreli bir değer başka satıra taşınırsa açılmaz.
- **Ana anahtar:** Windows'ta DPAPI (hesaba ve makineye bağlı) ya da scrypt (N=2¹⁶, r=8, p=1)
  ile korunur; ikisinde de AES-GCM kullanılır.
- **Kurtarma anahtarı ve yedekler:** parola tabanlı (scrypt + AES-256-GCM). Yedek ana anahtarı
  içermez.
- **Klasör izinleri:** Windows ACL'leri (devralma kesilir, yalnızca servis hesabı ve SYSTEM
  erişir; denetim SID ile yapılır) ya da POSIX `700/600` ve `umask 077`.
- **SQLite:** `secure_delete`, `temp_store=MEMORY`, `trusted_schema=OFF`, rollback journal
  (WAL yok).

## Kalan riskler (bilinçli olarak kapsam dışı)

| Risk | Açıklama | Azaltma |
|---|---|---|
| Kod dağıtım zinciri | Basılı kodu gören kişi o seçmen adına oy hakkı alabilir | Kapalı zarf; seçmen "oy hakkınız alınmış" uyarısını bildirir; sayımdan sonra seçmen olay kaydı incelenir |
| Zorlama | Seçmenin yanında durup ekranına bakan kişi | Makbuz içeriği kanıtlamaz; tekrar oy verme (Estonya modeli) desteklenmez |
| Uç nokta güvenliği | Seçmenin cihazındaki zararlı yazılım oyu değiştirebilir | Kapsam dışı |
| Ağ zaman bağıntısı | Issuer ile sandık aynı sunucuda çalışır. HTTPS'i sonlandıran ve trafiği **canlı** izleyen biri, oy hakkı isteği ile oy isteği arasında zamanlama bağıntısı arayabilir. | Tarayıcıda 3–10 sn rastgele bekleme ve erişim logu kapalı. Daha güçlü koruma için issuer ve sandık ayrı sunuculara/kurumlara ayrılabilir. |
| Yerel yönetici | Makinede tam yönetici yetkisi olan biri, servis oturumu açıkken bellekten ya da DPAPI üzerinden anahtara ulaşabilir; dosyalardaki satırları sayıp katılımı tahmin edebilir | Yönetici sayısını en aza indirin, Windows güvenlik denetimini açın; içerikler yine şifrelidir |
| Şifrelenmeyen alanlar | Seçmen kimlikleri (üye no) ve aday listesi şifrelenmez (arama ve gösterim için) | Aday listesi zaten herkese açıktır |
| NTP sahteciliği | NTP kimlik doğrulamasızdır | Çoklu kaynak uzlaşması; ileride NTS (RFC 8915) |
| Kilitleme sayaçları | Bellekte tutulur; tek süreçli kurulum içindir | Çok süreçli dağıtımda paylaşılan depoya taşınmalıdır |

## Test kanıtları

Her hedef için saldırı senaryoları `tests/` altında otomatik olarak sınanır:

| Hedef | Testler |
|---|---|
| H1 | `test_voting.py`: bağlanamazlık, şema |
| H2, H3 | `test_voting.py`: 20 ve 10 iş parçacıklı yarış testleri, sahte ve yabancı imza |
| H4 | `test_tamper.py`: doğrudan SQL, tetikleyici silme, geçmişin yeniden yazılması |
| H5 | `test_time.py`: saat ileri/geri alma, erken kapanış, sıra boşluğu |
| H6 | `test_web.py`, `test_blindsig_js.py` |
| H7 | `test_storage.py`: ham dosyada düz metin taraması, şifreli değer takası, DPAPI, kurtarma, yedek, ACL |
