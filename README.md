# OySistemi

[![Lisans: AGPL-3.0](https://img.shields.io/badge/lisans-AGPL--3.0-blue.svg)](LICENSE)
![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)
![Windows | Linux](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)

Küçük organizasyonlar (dernek, kooperatif, oda, kurul, öğrenci topluluğu) için **gizli,
denetlenebilir ve kurcalamaya dayanıklı** çevrimiçi oylama sistemi. Python + SQLite ile
yazılmıştır, Windows'ta ek yazılım gerektirmeden çalışır.

> **English summary.** OySistemi is a self-hosted online voting system for small
> organisations. Ballot secrecy relies on RFC 9474 RSA blind signatures computed in the
> voter's browser, so even the server operator cannot link a ballot to a voter. Each eligible
> voter gets exactly one credential and each credential casts exactly one ballot; both rules
> are enforced by database constraints. Roll changes require two-person approval. Every change
> is recorded in an HMAC hash-chained audit log, with row MACs and external checkpoints that
> expose out-of-band edits. Turnout and results stay sealed until the scheduled end time,
> which is enforced by a clock that resists manipulation (NTP quorum, monotonic anchor,
> audit-log high-water mark). Personal data and ballots are AES-256-GCM encrypted at rest.
> On Windows the master key is bound to the service account with DPAPI. Documentation is in
> Turkish; please report security issues privately (see [SECURITY.md](SECURITY.md)).
> Licensed under AGPL-3.0-or-later.

## Neleri garanti eder?

| Garanti | Nasıl sağlanır |
|---|---|
| **Tek kişi, tek oy** | Seçmen başına tek kör imza, imza başına tek oy. İkisi de veritabanı kısıtıdır; eşzamanlı denemeler sıralanır. |
| **Yalnızca listedekiler** | İmza yalnızca mühürlenmiş seçmen listesindeki ve kimliği doğrulanmış kişiye verilir. Sahte ya da başka seçimin imzası reddedilir. |
| **Oy gizliliği** | RFC 9474 RSA kör imza kullanılır ve körleme **tarayıcıda** yapılır. Oy, oturum kapatıldıktan sonra çerezsiz gönderilir. Sandıkta seçmen, zaman ve sıra bilgisi bulunmaz. |
| **Yetkisiz ekleme/silme yok** | Değişiklikler iki kişi onayıyla yapılır. Seçmenler silinmez, devre dışı bırakılır. Oylama açılınca liste DB tetikleyicileriyle donar. |
| **Bitişe kadar mühür** | Bitiş zamanından önce katılım ve sonuç hiçbir ekranda, API'de, raporda ya da kayıtta görünmez; yöneticiler de göremez. Erken kapanış mümkün değildir. |
| **Saat manipülasyonuna dayanıklılık** | Zaman, birden çok NTP sunucusunun uzlaşmasından alınır ve monotonik sayaçla ilerler. Denetim zincirinin son zaman damgası alt sınırdır. |
| **Veritabanı gizliliği** | Adlar, e-postalar ve oylar AES-256-GCM ile şifrelenir. Anahtar DPAPI ile servis hesabına bağlıdır. Klasörlere yalnızca o hesap erişebilir. |
| **Ayak izi** | Hash zincirli ve HMAC'li denetim kaydı, satır imzaları, gölge log, harici checkpoint ve şema parmak izi kullanılır. `oysistemi verify` uygulama dışından yapılan değişikliği yakalar. |

## Hızlı başlangıç

### Windows (önerilen)

```powershell
git clone <depo-adresi> oysistemi
cd oysistemi
powershell -ExecutionPolicy Bypass -File scripts\windows\kurulum.ps1 -VeriKlasoru C:\OySistemi
powershell -ExecutionPolicy Bypass -File scripts\windows\baslat.ps1 -VeriKlasoru C:\OySistemi -YerelTest
```

Ayrıntılar: [docs/kurulum-windows.md](docs/kurulum-windows.md)

### Deneme kurulumu (her platform)

```bash
python -m pip install -e ".[dev]"
python scripts/demo_setup.py demo
python -m oysistemi.cli --home demo serve --insecure-http
```

Giriş bilgileri `demo/DENEME_GIRIS.txt` dosyasındadır. Seçmen ekranı
http://127.0.0.1:8000/e/yonetim-2026, yönetici paneli http://127.0.0.1:8000/admin adresindedir.

## Belgeler

| Belge | Kimin için |
|---|---|
| [Windows kurulumu](docs/kurulum-windows.md) | Sunucuyu kuracak kişi |
| [Linux kurulumu](docs/kurulum-linux.md) | Sunucuyu kuracak kişi |
| [Yönetici kılavuzu](docs/yonetici-kilavuzu.md) | Seçim kurulu / yöneticiler |
| [Seçmen kılavuzu](docs/secmen-kilavuzu.md) | Seçmenler (dağıtılabilir) |
| [İşletim ve olay müdahalesi](docs/isletim.md) | Sistem sorumlusu |
| [Yapılandırma ve komut başvurusu](docs/yapilandirma.md) | Sistem sorumlusu |
| [Güvenlik modeli](docs/guvenlik-modeli.md) | Denetçiler, güvenlik araştırmacıları |
| [Mimari](docs/mimari.md) | Geliştiriciler, denetçiler |
| [Geliştirme](docs/gelistirme.md) | Katkıda bulunanlar |

Ayrıca: [SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md) ·
[CHANGELOG.md](CHANGELOG.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## Proje yapısı

```
oysistemi/
├── oysistemi/            Uygulama paketi
│   ├── admin/            İki kişi onayı (governance)
│   ├── audit/            Denetim zinciri, checkpoint, bütünlük doğrulayıcı
│   ├── auth/             Seçmen girişi (basılı kod, e-posta), yönetici girişi (parola + TOTP)
│   ├── crypto/           Kör imza (RFC 9474), alan şifreleme, anahtar dosyası, DPAPI, satır MAC
│   ├── db/               SQLite bağlantısı ve şema + tetikleyiciler (schema.sql)
│   ├── elections/        Oylama yaşam döngüsü, oy türleri, sayım
│   ├── voting/           Issuer (kör imza veren) ve sandık
│   ├── web/              FastAPI uygulaması, şablonlar, tarayıcı kör imza kodu
│   ├── timekeeping.py    Güvenilir saat
│   ├── osprotect.py      Windows ACL / POSIX izinleri
│   ├── backup.py         Şifreli yedek
│   └── cli.py            `oysistemi` komutu
├── scripts/              Deneme kurulumu ve Windows betikleri
├── tests/                Testler (pytest; JS çapraz testi için Node)
└── docs/                 Belgeler
```

## Lisans

Copyright © 2026 Ferhat Çiçek.

Bu program özgür yazılımdır: [GNU Affero Genel Kamu Lisansı](LICENSE) sürüm 3 veya (tercihinize
göre) daha sonraki bir sürümü kapsamında dağıtabilir ve/veya değiştirebilirsiniz.

AGPL gereği, değiştirilmiş bir sürümü ağ üzerinden kullanıcılara sunuyorsanız onlara kaynak
koduna erişim sağlamalısınız. `OYS_SOURCE_URL` ayarlanırsa her sayfanın altında bir "Kaynak
kodu" bağlantısı gösterilir.
