# Yapılandırma ve komut başvurusu

## Ortam değişkenleri

Tüm yollar `--home` (ya da `OYS_HOME`) klasörüne göredir.

### Yerleşim

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `OYS_HOME` | `.` | Kurulum klasörü (`--home` ile de verilebilir) |
| `OYS_DB` | `<home>/data/oysistemi.db` | SQLite veritabanı |
| `OYS_MASTER_KEY` | `<home>/secrets/master.key` | Ana anahtar dosyası (kurtarma anahtarı da aynı klasöre yazılır) |
| `OYS_CHECKPOINTS` | `<home>/checkpoints/checkpoints.jsonl` | Harici checkpoint dosyası |
| `OYS_OUTBOX` | `<home>/outbox` | SMTP yoksa e-postaların yazıldığı klasör (yalnızca deneme) |

### Anahtar ve şifreleme

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `OYS_KEY_PROTECTION` | Windows: `dpapi`, diğer: `file` | `init` sırasında ana anahtarın korunma biçimi: `dpapi`, `passphrase`, `file` |
| `OYS_PASSPHRASE` | — | `passphrase` modunda ana anahtar parolası (yoksa etkileşimli sorulur) |
| `OYS_RECOVERY_PASSPHRASE` | — | `key recover` için kurtarma parolası (otomasyon) |
| `OYS_BACKUP_PASSPHRASE` | — | `backup` / `restore` için yedek parolası (zamanlanmış yedek) |
| `OYS_RSA_BITS` | `3072` | Oylama başına kör imza anahtarı boyu (en az 2048) |

### Zaman

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `OYS_TIME_MODE` | `ntp` | `ntp`: birden çok NTP sunucusunun uzlaşması. `system`: yalnızca sistem saati (internetsiz kurulum; sonuçlarda belirtilir) |
| `OYS_TIME_SOURCES` | `time.cloudflare.com,time.google.com,pool.ntp.org,time.windows.com` | Virgülle ayrılmış NTP sunucuları |
| `OYS_TIME_QUORUM` | `2` | Uyuşması gereken en az kaynak sayısı |
| `OYS_TIME_TOLERANCE` | `30` | Saniye; uyuşma ve sıçrama/geri alma eşiği |
| `OYS_TZ` | `Europe/Istanbul` | Ekranlarda ve formlarda kullanılan saat dilimi. Kayıtlar her zaman UTC'dir. |

### Web ve e-posta

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `OYS_COOKIE_SECURE` | `1` | `0` yalnızca HTTPS'siz yerel deneme içindir (`serve --insecure-http` aynı işi yapar) |
| `OYS_SOURCE_URL` | — | Sayfa altbilgisindeki "Kaynak kodu" bağlantısı (AGPL §13) |
| `OYS_REQUIRED_APPROVALS` | `1` | Bir öneri için gereken onay sayısı. Öneren hariç tutulur; `2` ise üç yönetici gerekir. |
| `OYS_SMTP_HOST` | — | Boşsa e-postalar `outbox` klasörüne yazılır |
| `OYS_SMTP_PORT` | `587` | STARTTLS zorunludur |
| `OYS_SMTP_USER` / `OYS_SMTP_PASSWORD` | — | SMTP kimlik bilgileri |
| `OYS_SMTP_FROM` | `oysistemi@localhost` | Gönderen adresi |

## Komutlar

Hepsi `oysistemi [--home KLASÖR] <komut>` biçimindedir (`python -m oysistemi.cli` ile de
çalışır).

| Komut | Açıklama |
|---|---|
| `init [--recovery-passphrase-env DEĞ] [--passphrase-env DEĞ]` | Yeni kurulum: klasör izinlerini kilitler, korumalı ana anahtarı, kurtarma anahtarını ve boş şemayı oluşturur |
| `bootstrap-admins ID:KULLANICI ...` | İlk yöneticiler (en az iki; yalnızca hiç yönetici yokken, aksi halde parola sormadan çıkış kodu 3) |
| `serve [--host 127.0.0.1] [--port 8000] [--forwarded-allow-ips 127.0.0.1] [--insecure-http]` | Web sunucusu. Erişim logu kapalıdır; açılışta izinleri yeniden kilitler; zamanlayıcıyı çalıştırır. |
| `tick` | Bitiş zamanı gelen oylamaları kapatır ve sayar (cron/Görev Zamanlayıcı) |
| `clock` | Güvenilir saatin güvence seviyesi, sistem saati sapması ve alarmlar. Sorun varsa çıkış kodu 1. |
| `status [--json]` | Kurulum durumu: anahtar bu hesapta açılıyor mu, yöneticiler ve iki adımlı doğrulama durumu, oylama sayıları |
| `verify` | Tüm bütünlük denetimleri. Kritik bulgu varsa çıkış kodu 1. |
| `checkpoint` | Harici checkpoint yazar |
| `harden` | Klasör izinlerini kilitler ve denetler |
| `key status` | Ana anahtar koruma modu, kurtarma anahtarının sunucuda olup olmadığı |
| `key protect --mode dpapi\|passphrase\|file` | Ana anahtarın koruma biçimini değiştirir |
| `key export-recovery [DOSYA]` | Yeni bir kurtarma anahtarı üretir |
| `key recover [DOSYA]` | Kurtarma anahtarından bu hesap/makine için ana anahtarı yeniden oluşturur |
| `backup DOSYA` | Şifreli yedek. Dosya adındaki `{tarih}` zaman damgasıyla değiştirilir. |
| `restore DOSYA` | Şifreli yedekten geri yükler (var olan veritabanının üzerine yazmaz) |

## Sabit güvenlik parametreleri

| Parametre | Değer | Yer |
|---|---|---|
| Yönetici oturumu | 2 saat | `web/security.py` |
| Seçmen oturumu | 30 dakika (yalnızca oy hakkı almak için) | `web/security.py` |
| Yönetici kilitleme | 5 hatalı deneme → 15 dakika | `auth/admin_auth.py` |
| Basılı kod | 12 karakter, 32 harfli alfabe (~60 bit), en çok 5 hatalı deneme | `auth/voter_auth.py` |
| E-posta kodu | 8 hane, 10 dakika, tek kullanımlık, 60 sn yeniden gönderim aralığı | `auth/voter_auth.py` |
| Hız sınırları | Seçmen girişi 20/10 dk/IP · e-posta 5/10 dk/IP · yönetici girişi 20/10 dk/IP · oy atma 120/dk (genel, IP'siz) | `web/routes_*.py` |
| Pusula boyutu | En çok 8 KB | `voting/ballot_box.py` |
