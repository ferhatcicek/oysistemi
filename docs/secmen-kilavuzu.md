# Seçmen kılavuzu

*Bu sayfayı seçmenlerinize gönderebilir ya da yazdırıp kod zarfına ekleyebilirsiniz.*

## Nasıl oy veririm?

1. Size verilen adresi açın (ör. `https://oy.dernegim.org/e/baskan-2026`).
2. **Seçmen kimliğinizi** (ör. üye numaranız) ve size verilen **giriş kodunu** yazın.
   E-posta ile giriş açıksa **Kod gönder** düğmesine basın ve e-postanıza gelen 8 haneli kodu
   girin.
3. Pusulayı doldurun ve **Oyumu gönder** düğmesine basın. Oyunuz gönderildikten sonra
   değiştirilemez.
4. Ekranda gösterilen **makbuz numarasını** saklayın. Tarayıcınız da bu numarayı hatırlar.

## Oyum gerçekten gizli mi?

Evet, ve bunu yalnızca söz olarak değil, matematiksel olarak sağlar:

- Giriş yalnızca oy hakkınızı doğrulamak içindir.
- Tarayıcınız rastgele bir oy hakkı belirteci üretir ve onu **kör imza** yöntemiyle
  imzalatır. Sunucu imzaladığı belirteci göremez; mühürlü bir zarfı dışından imzalamaya benzer.
- Oturumunuz kapatılır, kısa ve rastgele bir süre beklenir, oy **kimliksiz** olarak sandığa
  gönderilir.
- Sandıkta adınız, saat bilgisi ya da oyların hangi sırayla atıldığı tutulmaz.

Bu yüzden sistem yöneticileri de dahil kimse hangi oyun size ait olduğunu bulamaz.

## Oyum sayıldı mı?

Oylama bitince sonuç sayfasında **Oyum sayıldı mı?** bölümüne makbuz numaranızı girin.
Kontrol tarayıcınızda yapılır; hangi makbuzu sorguladığınız sunucuya gönderilmez.

Makbuz yalnızca oyunuzun **sayıldığını** kanıtlar, **ne oy verdiğinizi** göstermez. Bu bilinçli
bir tasarım: böylece kimse sizi oyunuzu kanıtlamaya zorlayamaz ve oy satın alınamaz.

## Sonuçları ne zaman görebilirim?

Yalnızca oylama bitiş saatinden sonra. O ana kadar katılım oranı dahil hiçbir bilgi kimseye
(yöneticiler dahil) gösterilmez.

## Sorun mu yaşıyorsunuz?

| Mesaj | Ne yapmalı |
|---|---|
| "Kimlik veya kod hatalı" | Büyük/küçük harf ve tire önemli değildir; kodu yeniden yazın. 5 hatalı denemeden sonra kod kilitlenir; seçim kuruluna başvurun. |
| "Oy hakkınız daha önce başka bir cihazda alınmış" | Oyunuzu başka bir cihazdan verdiyseniz sorun yok. Vermediyseniz **hemen seçim kuruluna bildirin**: kodunuzu başka biri kullanmış olabilir. |
| "Oy verme henüz başlamadı" / "sona erdi" | Oylama başlangıç ve bitiş saatlerine bakın. |
| Oy gönderilirken bağlantı koptu | Aynı tarayıcıdan sayfayı açıp yeniden gönderin. Tarayıcınız oy hakkınızı saklar; ikinci bir oy oluşmaz. |

**Kodunuzu kimseyle paylaşmayın.** Kod, sizin adınıza oy hakkı almaya yeter.
