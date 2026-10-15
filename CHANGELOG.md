# Değişiklik günlüğü

Biçim [Keep a Changelog](https://keepachangelog.com/tr-TR/1.1.0/) esas alır; sürümler
[Anlamsal Sürümleme](https://semver.org/lang/tr/) kurallarına uyar.

## [Yayımlanmamış]

## [0.1.0] - 2026-10-15

İlk yayım.

### Oylama
- RFC 9474 RSA kör imza (RSABSSA-SHA384-PSS-Randomized, RSA-3072). Körleme tarayıcıda
  (`blindsig.js`, WebCrypto) yapılır.
- Kimlikli issuer ile kimliksiz sandık birbirinden ayrıdır. Oy çerezsiz gönderilir; sandıkta
  seçmen, zaman ve sıra bilgisi yoktur.
- Oy türleri: tek seçim, evet/hayır/çekimser, çoklu seçim, onay oylaması, Borda, IRV
  (doğrulanabilir eşitlik bozma ile).
- Dahil edilme makbuzu ve içerikten ayrılmış ilan panosu.
- Asgari katılım eşiğinin altında sonuç dökümü gizlenir.

### Yönetişim ve bütünlük
- İki kişi kuralı (öneri + bağımsız onay).
- Veritabanı tetikleyicileri: salt ekleme, silme yasağı, açılışta dondurma, ileri yönlü durum
  makinesi.
- HMAC'li denetim zinciri, oylama başına seçmen olay zinciri, satır MAC'leri, gölge log, harici
  checkpoint'ler, şema parmak izi ve `oysistemi verify`.

### Zaman
- Zorunlu bitiş zamanı; bitişe kadar katılım ve sonuç mühürlü. Bitişte otomatik kapanış.
- Güvenilir saat: NTP uzlaşması, monotonik çapa, denetim zinciri üzerinden geri alma tespiti.

### Kimlik doğrulama
- Seçmen: basılı tek kullanımlık kod ve e-posta kodu.
- Yönetici: argon2id parola + zorunlu TOTP (tekrar kullanım koruması, kilitleme).

### Depolama güvenliği
- Adlar, e-postalar, oylar ve kayıt ayrıntıları için AES-256-GCM alan şifreleme (AAD ile satıra
  bağlı).
- Ana anahtar: Windows DPAPI veya parola (scrypt). Parola korumalı kurtarma anahtarı.
- Windows ACL ve POSIX izin sertleştirmesi, denetimi.
- Şifreli yedek/geri yükleme.

### Windows
- PowerShell kurulum, başlatma ve Zamanlanmış Görev betikleri.
- `tzdata` bağımlılığı, konsol kodlaması ve SQLite kilit dayanıklılığı düzeltmeleri.

[Yayımlanmamış]: ../../compare/v0.1.0...HEAD
[0.1.0]: ../../releases/tag/v0.1.0
