# İşletim ve olay müdahalesi

## Düzenli görevler

| Ne zaman | Görev | Komut |
|---|---|---|
| Sürekli | Sunucu (zamanlayıcı dahil) | `oysistemi --home <klasör> serve` |
| Dakikada bir | Bitiş zamanı gelen oylamaları kapat (sunucu kapalıyken de) | `oysistemi --home <klasör> tick` |
| Her gece | Şifreli yedek | `oysistemi --home <klasör> backup <yer>/oysistemi-{tarih}.oysbak` |
| Günlük + her oylama sonrası | Bütünlük denetimi (kritik bulguda çıkış kodu 1) | `oysistemi --home <klasör> verify` |
| Haftalık | Checkpoint dosyasını kurum dışına kopyala | `checkpoints/checkpoints.jsonl` |
| Her oylama öncesi | Saat durumu | `oysistemi --home <klasör> clock` |

Windows'ta ilk üçünü `scripts\windows\otomatik-baslat.ps1` kurar.

## Anahtar yönetimi

| Durum | Komut |
|---|---|
| Koruma modunu gör | `oysistemi key status` |
| Eski düz anahtarı DPAPI'ye geçir | `oysistemi key protect --mode dpapi` |
| Parola korumasına geç (Linux önerisi) | `oysistemi key protect --mode passphrase` |
| Yeni kurtarma anahtarı üret (ör. eskisi kaybolduysa) | `oysistemi key export-recovery E:\yeni.oyskey` |
| Yeni makinede anahtarı geri getir | `oysistemi key recover E:\KURTARMA_ANAHTARI.oyskey` |

> **Uyarı: Anahtar kaybı veri kaybıdır.** Seçmen adları, e-postalar ve oylar ana anahtarla
> şifrelidir. DPAPI'ye bağlı anahtar (hesap/makine) ve kurtarma anahtarı birlikte kaybolursa
> veriler okunamaz. Kurtarma anahtarının en az bir kopyası çevrimdışı olmalıdır.

## Yedekten dönüş

```bash
oysistemi --home <yeni-klasör> restore <yedek>.oysbak
oysistemi --home <yeni-klasör> key recover <KURTARMA_ANAHTARI.oyskey>
oysistemi --home <yeni-klasör> verify
```

`restore` var olan bir veritabanının üzerine yazmaz. Yedek, checkpoint dosyasını da içerir.

## Bütünlük bulguları

`verify` çıktısındaki her bulgunun kodu:

| Kod | Anlamı | Ciddiyet |
|---|---|---|
| `schema` | Şema/tetikleyiciler değiştirilmiş. Web uygulaması da kilitlenir. | Kritik |
| `audit_chain` | Denetim kaydı silinmiş, değiştirilmiş, araya kayıt eklenmiş ya da zaman damgası geriye gitmiş | Kritik |
| `row_mac` | Bir satır uygulama dışından eklenmiş/değiştirilmiş | Kritik |
| `out_of_band` / `shadow_gap` | Tetikleyiciler uygulama dışı bir değişiklik kaydetmiş ya da gölge log silinmiş | Kritik |
| `checkpoint` | Son checkpoint'ten sonra satır silinmiş veya geçmiş yeniden yazılmış | Kritik / Uyarı |
| `roll_changed` | Mühürlü seçmen listesi değişmiş | Kritik |
| `ballot_stuffing` / `forged_ballot` / `over_issuance` / `orphan_credential` | Sandığa sahte oy, fazla oy hakkı ya da liste dışı oy hakkı | Kritik |
| `voter_log` | Seçmen olay zinciri kurcalanmış ya da oy hakkı kayıtlarıyla çelişiyor | Kritik |
| `key_not_destroyed` | Kapanmış oylamanın özel anahtarı hâlâ duruyor | Kritik |
| `clock` | Saat geri alınmış/sıçramış (kritik) ya da doğrulanamıyor (uyarı) | Kritik / Uyarı |
| `filesystem` | Yetkisiz bir hesabın veri klasörüne erişimi var | Kritik |
| `key_protection` / `recovery_key` | Ana anahtar korumasız ya da kurtarma anahtarı sunucuda duruyor | Uyarı |

Oylama sürerken bulgu mesajları **sayı içermez** (katılım sızmasın diye "?" yazılır).

## Olay müdahalesi

### Kritik bütünlük bulgusu

1. **Durdurun:** Sunucuyu kapatın (`Stop-ScheduledTask "OySistemi Sunucu"` / `systemctl stop oysistemi`).
2. **Kanıtı koruyun:** `data`, `checkpoints` klasörlerinin ve harici checkpoint kopyalarının
   salt okunur bir kopyasını alın. Dosyalara dokunmadan önce özetlerini (`Get-FileHash` /
   `sha256sum`) kaydedin.
3. **Kapsamı belirleyin:** `verify` çıktısını, Ayak izi sayfasını ve Windows Güvenlik olay
   günlüğünü (sahiplik/izin değişiklikleri, oturum açmalar) inceleyin.
4. **Karar verin:** Sürmekte olan bir oylama etkilendiyse seçim kuruluyla birlikte oylamanın
   geçerliliğine karar verin. Kriptografik kanıt (imzası geçersiz oylar, liste mühürü
   uyuşmazlığı) karar için yeterli dayanaktır.
5. **Temiz kurulum:** Gerekirse son temiz yedekten yeni bir makineye dönün. Kök neden
   anlaşılmadan aynı sunucuyu kullanmayın.

### "Oy hakkım zaten alınmış" diyen seçmen

1. Seçmenin oyunu başka bir cihazdan verip vermediğini sorun.
2. Vermediyse: o seçmenin kodu ele geçirilmiş demektir. Sayımdan sonra seçmen olay kaydında
   oy hakkının ne zaman alındığı görülebilir; oyun **içeriği** hiçbir zaman görülemez.
3. Kod dağıtım zincirini (yazdıran, zarflayan, dağıtan) gözden geçirin.

### Saat alarmı

- `clock_rollback`: Saat, kayıtlardaki son zamanın gerisinde. Oy verme ve kayıt yazma
  durmuştur. Sistem saatini düzeltin (`w32tm /resync` ya da `timedatectl`) ve sunucuyu yeniden
  başlatın. Kimin değiştirdiğini olay günlüğünden araştırın.
- `system_clock_jump`: Sunucu çalışırken sistem saati değişmiş. Uygulama zamanı etkilenmez,
  ama değişikliğin nedeni araştırılmalıdır.
- `unverified`: NTP sunucularına ulaşılamıyor. Oy verme sürer, kapanış saat doğrulanana kadar
  bekler.

### Ana anahtar açılamıyor

`DPAPI could not decrypt the master key` hatası sunucunun yanlış hesapla çalıştığını gösterir.
Doğru hesabı kullanın; makine değiştiyse `key recover` komutunu kullanın.
