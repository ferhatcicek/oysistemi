# Windows kurulumu

OySistemi Windows 10/11 ve Windows Server 2019+ üzerinde ek yazılım (derleyici, veritabanı
sunucusu, servis aracı) gerektirmeden çalışır.

## Gereksinimler

- [Python 3.12 veya üstü](https://www.python.org/downloads/windows/). Kurulumda **"Add python.exe
  to PATH"** seçeneğini işaretleyin.
- [Git](https://git-scm.com/download/win), yalnızca depoyu klonlamak için.
- İnternete açılacaksa bir alan adı ve [Caddy](https://caddyserver.com/download) (HTTPS için).
- **NTP sunucularına (UDP 123) çıkış izni.** Kapalıysa [zaman ayarları](#internetsiz-kurulum)
  bölümüne bakın.

## 1. Hesabı seçin

Ana anahtar, Windows DPAPI ile **kurulumu yapan hesaba ve bu bilgisayara** bağlanır. Sunucuyu
hangi hesap çalıştıracaksa kurulumu o hesapla yapın. Ayrı bir yerel hesap (ör. `oysistemi`)
önerilir; bu hesabın yönetici olması gerekmez.

## 2. Kurulum

Seçtiğiniz hesapla, normal (yönetici olmayan) bir PowerShell penceresinde:

```powershell
git clone <depo-adresi> C:\OySistemiKod
cd C:\OySistemiKod
powershell -ExecutionPolicy Bypass -File scripts\windows\kurulum.ps1 -VeriKlasoru C:\OySistemi
```

Betiğin yaptıkları:

1. Python sürümünü denetler, `.venv` sanal ortamını ve bağımlılıkları kurar (`tzdata` dahil).
2. `C:\OySistemi\{data,secrets,checkpoints,outbox}` klasörlerini oluşturur. Devralınan izinleri
   keser; yalnızca bu hesaba ve SYSTEM'e yetki verir.
3. DPAPI korumalı ana anahtarı üretir.
4. **Kurtarma anahtarı** için bir parola ister ve `secrets\KURTARMA_ANAHTARI.oyskey` dosyasını
   üretir.
5. İlk iki yöneticiyi oluşturur. İki kişi kuralı gereği en az iki yönetici gerekir; her biri
   için en az 12 karakterlik bir parola sorulur.
6. `harden` ve `verify` ile son denetimi yapar.

### Kurtarma anahtarını hemen taşıyın

```powershell
Copy-Item C:\OySistemi\secrets\KURTARMA_ANAHTARI.oyskey E:\   # USB bellek
Remove-Item C:\OySistemi\secrets\KURTARMA_ANAHTARI.oyskey
```

Kurtarma dosyasını ve parolasını **ayrı yerlerde** saklayın (ör. dosya kasada, parola başka bir
yöneticide). Veriler şifreli olduğundan, hem bu bilgisayar hem kurtarma anahtarı kaybolursa
seçmen adları ve oylar bir daha okunamaz.

## 3. Deneme çalıştırması

```powershell
powershell -ExecutionPolicy Bypass -File scripts\windows\baslat.ps1 -VeriKlasoru C:\OySistemi -YerelTest
```

http://127.0.0.1:8000/admin adresini açın. İlk girişte telefonunuzdaki kimlik doğrulayıcı
uygulamayı (Google Authenticator, Microsoft Authenticator, Aegis…) kaydedersiniz.
`-YerelTest` seçeneği HTTPS olmadan çalışmayı sağlar; **yalnızca bu bilgisayardan denemek
içindir.**

## 4. Otomatik başlatma ve gece yedeği

Yönetici yetkili bir PowerShell penceresinde:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\windows\otomatik-baslat.ps1 `
    -VeriKlasoru C:\OySistemi -YedekKlasoru D:\OySistemiYedek
```

Bu betik üç Zamanlanmış Görev oluşturur. Üçü de kurulum hesabıyla, oturum açılmamış olsa da
çalışır:

| Görev | Ne zaman | Ne yapar |
|---|---|---|
| OySistemi Sunucu | Bilgisayar açılınca; çökerse 1 dk sonra | `serve` (yalnızca 127.0.0.1:8000) |
| OySistemi Kapanis | Dakikada bir | `tick`: bitiş zamanı gelen oylamaları kapatır |
| OySistemi Yedek | Her gece 03:00 | `backup`: şifreli `.oysbak` dosyası |

Windows, görevler için hesabın parolasını ister. Bunun nedeni DPAPI'dir: anahtar yalnızca bu
hesabın oturumunda açılabilir. SYSTEM ya da "S4U" oturumu anahtarı **açamaz**.

Yedek parolası, hesabın kullanıcı ortam değişkenine (`OYS_BACKUP_PASSPHRASE`) yazılır. Yedek
dosyaları ana anahtarı içermez; açmak için ayrıca kurtarma anahtarı gerekir.

## 5. HTTPS ile dışarıya açma

`C:\Caddy\Caddyfile`:

```
oy.dernegim.org {
    reverse_proxy 127.0.0.1:8000
    log {
        output discard     # erişim logu tutmayın: oy gönderiminin IP/zamanı kalmamalı
    }
    header -Server
}
```

```powershell
caddy run --config C:\Caddy\Caddyfile
```

Caddy'yi de bir Zamanlanmış Görev ya da servis olarak başlatın. Windows Güvenlik Duvarı'nda
yalnızca **443/TCP** (ve sertifika alımı için 80/TCP) açık olmalıdır. 8000 portunu dışarı
açmayın; OySistemi yalnızca `127.0.0.1` adresini dinler.

## İnternetsiz kurulum

Sunucu NTP sunucularına ulaşamıyorsa oylamalar bitişte **kapanmaz**; saat doğrulanana kadar
bekler. Bu, saat manipülasyonuna karşı bilinçli bir güvenlik davranışıdır. Tamamen çevrimdışı
bir ağda:

- Kurum içi bir NTP sunucusu varsa: `setx OYS_TIME_SOURCES "ntp1.kurum.local,ntp2.kurum.local"`
- Yoksa: `setx OYS_TIME_MODE system`. Bu durumda sistem saatine güvenilir ve sonuç sayfasında
  "zaman güvencesi: yalnızca sunucu saati" yazar.

## Güncelleme

```powershell
Stop-ScheduledTask -TaskName "OySistemi Sunucu"
cd C:\OySistemiKod
git pull
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\python -m oysistemi.cli --home C:\OySistemi verify
Start-ScheduledTask -TaskName "OySistemi Sunucu"
```

Güncellemeden önce mutlaka yedek alın. [CHANGELOG.md](../CHANGELOG.md) dosyasında "şema
değişikliği" notu olan sürümlerde yükseltme talimatını izleyin.

## Bilgisayar değiştirme

Yeni bilgisayarda kodu kurun (2. adım, ama `init` **yapmadan**: veri klasörü boş kalsın). Sonra:

```powershell
.\.venv\Scripts\python -m oysistemi.cli --home C:\OySistemi restore D:\OySistemiYedek\oysistemi-20261015-030000.oysbak
.\.venv\Scripts\python -m oysistemi.cli --home C:\OySistemi key recover E:\KURTARMA_ANAHTARI.oyskey
.\.venv\Scripts\python -m oysistemi.cli --home C:\OySistemi verify
```

`restore` klasör izinlerini kilitler. `key recover` ana anahtarı yeni hesap/makine için DPAPI
ile yeniden korur.

## Sık karşılaşılan sorunlar

| Belirti | Neden / çözüm |
|---|---|
| `DPAPI could not decrypt the master key` | Sunucu kurulumu yapan hesaptan farklı bir hesapla çalışıyor. Görevi doğru hesapla yeniden kaydedin ya da `key recover` kullanın. |
| `ZoneInfoNotFoundError` | `tzdata` eksik: `.venv\Scripts\python -m pip install -e .` |
| Yönetici panelinde "Saat dış kaynaklarla doğrulanamadı" | UDP 123 kapalı. [İnternetsiz kurulum](#internetsiz-kurulum) bölümüne bakın. |
| `database is locked` | Antivirüs veri klasörünü tarıyor olabilir. `C:\OySistemi\data` klasörünü gerçek zamanlı taramadan hariç tutun. |
| Betik çalışmıyor: "running scripts is disabled" | Komutu `powershell -ExecutionPolicy Bypass -File ...` biçiminde çalıştırın. |
| Konsolda Türkçe karakterler bozuk | Windows Terminal kullanın ya da `chcp 65001` çalıştırın. |
