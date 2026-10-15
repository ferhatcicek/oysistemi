# Güvenlik politikası

OySistemi bir oylama sistemidir; güvenlik açıkları seçim sonuçlarını ve seçmen gizliliğini
doğrudan etkileyebilir. Bildirimlerinizi ciddiyetle ve öncelikle ele alıyoruz.

## Açık nasıl bildirilir?

**Herkese açık issue açmayın.** Bunun yerine GitHub'ın özel bildirim özelliğini kullanın:

1. Depo sayfasında **Security** sekmesine gidin.
2. **Report a vulnerability** düğmesine basın.
3. Açığı, etkisini ve mümkünse yeniden oluşturma adımlarını yazın.

Bildirimin alındığını 5 iş günü içinde onaylamaya, ilk değerlendirmeyi 14 gün içinde
paylaşmaya çalışırız. Düzeltme yayımlanana kadar ayrıntıları gizli tutmanızı rica ederiz;
düzeltmeden sonra isterseniz katkınız CHANGELOG'da belirtilir.

## Kapsam

Özellikle şu konulardaki bildirimler değerlidir:

- Bir oyun bir seçmene bağlanabilmesi (oy gizliliğinin kırılması)
- Bir seçmenin birden fazla oy kullanabilmesi ya da listede olmayan birinin oy kullanabilmesi
- Oyların veya seçmen listesinin **tespit edilmeden** değiştirilebilmesi, eklenebilmesi, silinebilmesi
- Bitiş zamanından önce katılımın veya sonucun öğrenilebilmesi
- Saat manipülasyonu ile zaman kurallarının atlatılabilmesi
- İki kişi kuralının tek yöneticiyle aşılabilmesi
- Şifreli verilerin anahtar olmadan okunabilmesi
- Kimlik doğrulama/oturum açıkları (XSS, CSRF, oturum sabitleme vb.)
- Kör imza uygulamasında (RFC 9474) kriptografik hatalar

[docs/guvenlik-modeli.md](docs/guvenlik-modeli.md) dosyasındaki "Kalan riskler" bölümünde
**bilinen ve kabul edilmiş** sınırlar listelenmiştir. Bunları aşan yeni bir saldırı yolu
bulduysanız yine bildirin.

## Desteklenen sürümler

| Sürüm | Destek |
|---|---|
| 0.1.x | ✅ |

## Yöneticiler için

Sisteminizde şüpheli bir durum görürseniz (`oysistemi verify` kritik bulgu veriyorsa) önce
[olay müdahalesi](docs/isletim.md#olay-müdahalesi) adımlarını izleyin. Seçmen verisi, kod,
parola, anahtar veya veritabanı dosyalarını bildirimlere **eklemeyin**.
