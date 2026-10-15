# Linux kurulumu

Debian 12 / Ubuntu 22.04+ için örnek. Diğer dağıtımlarda paket adları değişebilir.

## 1. Kullanıcı ve kod

```bash
sudo apt install python3 python3-venv git
sudo useradd --system --create-home --home-dir /srv/oysistemi --shell /usr/sbin/nologin oysistemi
sudo -u oysistemi git clone https://github.com/ferhatcicek/oysistemi.git /srv/oysistemi/kod
cd /srv/oysistemi/kod
sudo -u oysistemi python3 -m venv .venv
sudo -u oysistemi .venv/bin/pip install -e .
```

## 2. Ana anahtar koruması

Linux'ta DPAPI yoktur. İki seçenek var:

| Mod | Ayar | Artı | Eksi |
|---|---|---|---|
| `passphrase` (önerilen) | `OYS_KEY_PROTECTION=passphrase` | Disk kopyalansa bile anahtar açılmaz | Her başlangıçta `OYS_PASSPHRASE` gerekir |
| `file` | varsayılan | Gözetimsiz başlar | Anahtar yalnızca `chmod 600` ile korunur; `verify` uyarır |

`passphrase` modunda parolayı systemd'nin şifreli kimlik bilgisi mekanizmasıyla
(`systemd-creds`) vermeniz önerilir.

## 3. Kurulum

```bash
sudo -u oysistemi env OYS_KEY_PROTECTION=passphrase \
    .venv/bin/oysistemi --home /srv/oysistemi/veri init
sudo -u oysistemi .venv/bin/oysistemi --home /srv/oysistemi/veri bootstrap-admins ayse:ayse mehmet:mehmet
```

Kurtarma anahtarını (`/srv/oysistemi/veri/secrets/KURTARMA_ANAHTARI.oyskey`) çevrimdışı bir
ortama taşıyın ve sunucudan silin.

İzinler otomatik ayarlanır: klasörler `700`, dosyalar `600`, süreç `umask 077` ile çalışır.

## 4. systemd servisi

`/etc/systemd/system/oysistemi.service`:

```ini
[Unit]
Description=OySistemi
After=network-online.target
Wants=network-online.target

[Service]
User=oysistemi
WorkingDirectory=/srv/oysistemi/kod
Environment=OYS_KEY_PROTECTION=passphrase
LoadCredentialEncrypted=oys-passphrase:/etc/oysistemi/passphrase.cred
ExecStart=/bin/sh -c 'OYS_PASSPHRASE="$(cat $CREDENTIALS_DIRECTORY/oys-passphrase)" exec .venv/bin/oysistemi --home /srv/oysistemi/veri serve --port 8000'
Restart=always
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/srv/oysistemi/veri
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```bash
sudo mkdir -p /etc/oysistemi
sudo systemd-creds encrypt --name=oys-passphrase - /etc/oysistemi/passphrase.cred   # parolayı yazıp Ctrl+D
sudo systemctl enable --now oysistemi
```

Kapanış yedeği ve gece yedeği (`crontab -u oysistemi -e`):

```cron
* * * * *  cd /srv/oysistemi/kod && OYS_PASSPHRASE=... .venv/bin/oysistemi --home /srv/oysistemi/veri tick
0 3 * * *  cd /srv/oysistemi/kod && OYS_PASSPHRASE=... OYS_BACKUP_PASSPHRASE=... .venv/bin/oysistemi --home /srv/oysistemi/veri backup /yedek/oysistemi-{tarih}.oysbak
```

Parolaları crontab'a düz yazmak yerine systemd zamanlayıcıları (`.timer`) ve
`LoadCredentialEncrypted` kullanmanız daha güvenlidir.

## 5. HTTPS

[Windows kurulumundaki](kurulum-windows.md#5-https-ile-dışarıya-açma) Caddyfile aynen geçerlidir:

```bash
sudo apt install caddy
sudo cp Caddyfile /etc/caddy/Caddyfile && sudo systemctl reload caddy
```
