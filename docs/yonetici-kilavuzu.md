# Yönetici kılavuzu

Bu kılavuz seçim kurulu üyeleri ve sistem yöneticileri içindir.

## Temel kurallar

- **İki kişi kuralı:** Seçmen eklemek/çıkarmak, oylamayı açmak/kapatmak ve yeni yönetici eklemek
  için bir yönetici **öneri** yapar, **başka** bir yönetici onaylar. Kendi önerinizi
  onaylayamazsınız. Tek bir ret öneriyi düşürür.
- **Taslak serbest, açık oylama mühürlü:** Oy türü, seçenekler, tarihler ve seçmen listesi
  yalnızca taslakta değişir. Açılış onaylandığı anda hepsi mühürlenir.
- **Bitişe kadar hiçbir sayı yok:** Oylama sürerken kaç kişinin oy verdiğini siz de
  göremezsiniz. Bu bir eksiklik değil, gizlilik güvencesidir.
- **Seçmenler silinmez:** Gerekirse "devre dışı" bırakılır. Ayak izi kaybolmaz.

## İlk giriş

1. `https://<adres>/admin` adresinden kullanıcı adı ve parolanızla girin.
2. Telefonunuzdaki kimlik doğrulayıcı uygulamada (Google/Microsoft Authenticator, Aegis…)
   **Hesap ekle → Karekod tara** seçeneğiyle ekrandaki **karekodu** taratın ve uygulamanın
   gösterdiği 6 haneli kodu girin.
   - Paneli zaten telefonda açtıysanız **"uygulamaya ekle"** düğmesine dokunun.
   - Kamera kullanılamıyorsa "Karekodu tarayamıyor musunuz?" bölümündeki anahtarı kopyalayıp
     elle girin.

   Bu adım bir kez yapılır; sonraki girişlerde yalnızca kod sorulur.
3. 5 hatalı denemeden sonra hesap 15 dakika kilitlenir.

## Bir oylamanın adımları

### 1. Seçmenleri ekleyin

**Seçmenler** sayfasında her satıra bir seçmen yazın:

```
1001; Ayşe Yılmaz; ayse@ornek.org
1002; Mehmet Kaya; mehmet@ornek.org
1003; Can Demir
```

- **Kimlik** (ör. üye numarası) yalnızca harf, rakam, `.`, `_` ve `-` içerebilir. Seçmen giriş
  ekranında bu kimliği yazacaktır.
- **E-posta** isteğe bağlıdır, ama e-posta ile giriş için gereklidir.
- Gönderdiğinizde bir **öneri** oluşur. Başka bir yönetici **Pano** sayfasında onaylar.

### 2. Taslak oylama oluşturun

**Yeni oylama** sayfasında:

| Alan | Açıklama |
|---|---|
| Oylama kimliği | Adreste görünür: `/e/baskan-2026` |
| Oy türü | Tek seçim · Evet/Hayır/Çekimser · Çoklu seçim (en az/en çok) · Onay oylaması · Sıralı (Borda) · Sıralı (IRV) |
| Seçenekler | Her satıra bir aday/seçenek |
| Başlangıç | Boş bırakılırsa açılış onaylandığı an başlar |
| **Bitiş** | Zorunlu. Bu ana kadar katılım ve sonuç kimseye gösterilmez. Bitiş geldiğinde sistem oylamayı **kendiliğinden** kapatır ve sayar. |
| Asgari katılım | Bu sayının altında oy kullanılırsa sonuç dökümü gizlenir. Çok az oyda kimin neye oy verdiği tahmin edilebileceği için gizlilik önlemidir. Seçmen listesi bu sayıdan küçük olamaz. |
| Giriş yöntemleri | Basılı kod ve/veya e-posta kodu |
| Karışık sıra | Seçenekler her seçmene farklı sırada gösterilir (sıra etkisini azaltır) |

Sıralı (IRV) oylamada eşitlik durumunda önce önceki turlara bakılır. Eşitlik sürerse,
yayımlanan pusulalardan türetilen ve herkesin yeniden hesaplayabileceği bir kura çekilir.

### 3. Seçmen listesini belirleyin

Oylama sayfasında oy kullanacak seçmenleri işaretleyip **Liste değişikliğini öner** düğmesine
basın. İkinci bir yönetici onaylar.

### 4. Açılışı önerin

**Açılışı öner** düğmesine basın; ikinci bir yönetici onaylar. Onaylayan yönetici panoda
başlığı, oy türünü, seçenekleri, tarihleri, asgari katılımı ve seçmen sayısını görür. **Onay
yalnızca bu içerik için geçerlidir:** öneriden sonra taslakta ya da seçmen listesinde herhangi
bir değişiklik yapılırsa açılış reddedilir ve yeniden önerilmesi gerekir.

Onay anında:

- seçime özel kör imza anahtarı üretilir,
- yapılandırma ve seçmen listesinin özetleri ("mühürler") kaydedilir,
- bundan sonra yapılandırma, tarihler ve liste değiştirilemez.

### 5. Giriş kodlarını dağıtın

**Basılı kod:** Oylama sayfasında **Eksik kodları üret ve yazdır** düğmesine basın.

- Kodlar **yalnızca bir kez** gösterilir; sunucuda yalnızca özetleri tutulur.
- Sayfayı yazdırın, her seçmenin satırını kesip **kapalı zarfa** koyun ve elden verin.
- Kodu gören kişi o seçmen adına oy hakkı alabilir. Kodları yazdıran kişi sayısını en aza
  indirin ve zarfları mühürleyin.
- Kodlar oylama başlamadan önce de üretilebilir.

**E-posta kodu:** Ek bir işlem gerekmez. Seçmen giriş sayfasında kimliğini yazar ve 8 haneli
kod e-postasına gelir (10 dakika geçerli, tek kullanımlık).

### 6. Oylama süresince

- Oylama sayfasında yalnızca seçmen listesi büyüklüğü ve tarihler görünür.
- Bir seçmen "oy hakkınız daha önce alınmış" uyarısı aldığını bildirirse, **kodu başka biri
  kullanmış olabilir.** Bunu bir güvenlik olayı olarak ele alın ([İşletim](isletim.md#olay-müdahalesi)).

### 7. Kapanış ve sonuç

Bitiş zamanı geldiğinde sistem dakika içinde:

1. sandığı kapatır,
2. seçimin özel anahtarını **imha eder** (artık kimse geçerli oy üretemez),
3. her oyun imzasını yeniden doğrulayıp sayar,
4. sonuç sayfasını ve ilan panosunu (`/api/e/<kimlik>/bulletin.json`) yayımlar.

Zamanlayıcı herhangi bir nedenle çalışmadıysa (ör. saat doğrulanamadı), oylama sayfasında
**Kapanışı öner** düğmesi görünür. Bu düğme yalnızca bitiş zamanı geçtikten sonra çıkar.

Sayımdan sonra oylama sayfasında **seçmen olay kaydı** görünür: kim, ne zaman giriş yaptı ve
oy hakkı aldı. Bu kaydın oyların içeriğiyle hiçbir bağı yoktur.

## Ayak izi ve bütünlük

- **Ayak izi** sayfası: bütün yönetim işlemleri (kim, ne zaman, ne yaptı).
- **Bütünlük** sayfası: tüm denetimleri çalıştırır. **KRİTİK** bir bulgu görürseniz sistemi
  kullanmayı durdurun ve [olay müdahalesi](isletim.md#olay-müdahalesi) adımlarını izleyin.

## Yeni yönetici ve denetçi

Yeni yöneticinin parolasını **hiçbir yönetici belirlemez**. Yeni hesap iki parçalı bir kodla,
sahibi tarafından etkinleştirilir:

1. Bir yönetici **Yöneticiler** sayfasından kullanıcı adını ve rolü önerir. Ekranda bir kez
   **A kodu** gösterilir.
2. İkinci bir yönetici öneriyi onaylar. Ekranda bir kez **B kodu** gösterilir.
3. İki yönetici kodlarını yeni kişiye **ayrı ayrı** ve güvenli bir kanaldan iletir.
4. Yeni yönetici `/admin/enroll` sayfasında iki kodu girip **kendi** parolasını belirler,
   ardından giriş yapıp kendi kimlik doğrulayıcı uygulamasını kaydeder.

Kodlar 7 gün geçerlidir. İki parçayı birden kimse görmediği için hiçbir yönetici yeni hesabı
tek başına ele geçirip iki kişi kuralını aşamaz. Etkinleştirilmemiş hesap parolayla giriş
yapamaz.

Rol olarak "Denetçi" seçilirse hesap her şeyi görebilir ama hiçbir değişiklik öneremez veya
onaylayamaz; bağımsız gözlemciler için uygundur.
