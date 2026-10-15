# Katkıda bulunma

Katkılarınız için teşekkürler. OySistemi'nde küçük bir hata bile oy gizliliğini ya da seçim
sonucunu etkileyebileceği için katkı süreci biraz titizdir.

## Başlamadan önce

- **Güvenlik açığı** buldunuz mu? Issue açmayın; [SECURITY.md](SECURITY.md) dosyasına bakın.
- Büyük bir değişiklik düşünüyorsanız önce bir **öneri issue'su** açın ve tasarımı tartışalım.
  Özellikle oy akışını, şemayı, kriptografiyi veya zaman kurallarını etkileyen değişiklikler
  için bu adım zorunludur.

## Geliştirme ortamı

Kurulum, testler ve kod kuralları için [docs/gelistirme.md](docs/gelistirme.md) dosyasına bakın.

```bash
python -m pip install -e ".[dev]"
python -m pytest
ruff check oysistemi tests scripts
bandit -q -c pyproject.toml -r oysistemi
```

## Pull request kontrol listesi

- [ ] Her davranış değişikliği için test var. Güvenlik özelliklerinde hem "çalışıyor" hem de
      "saldırı reddediliyor/tespit ediliyor" testi beklenir.
- [ ] `pytest`, `ruff` ve `bandit` temiz. CI Windows ve Linux'ta geçiyor.
- [ ] [Güvenlik kuralları](docs/gelistirme.md#kurallar-güvenlik-açısından-kritik) ihlal edilmiyor:
  - zaman için `get_clock()` kullanılıyor,
  - sandık tarafına kimlik/zaman bilgisi eklenmiyor,
  - oylama sürerken sayı sızdıran yeni bir yol açılmıyor,
  - hassas alanlar şifreleniyor.
- [ ] Kullanıcıyı etkileyen değişiklikler `CHANGELOG.md` dosyasının "Yayımlanmamış" bölümüne
      eklendi. Şema değiştiyse geçiş notu yazıldı.
- [ ] Belgeler (`docs/`) güncellendi.

## Kod biçimi

- Python 3.12+, satır uzunluğu 100, `ruff` kuralları (`pyproject.toml`).
- Yorumlar ve kullanıcı arayüzü metinleri Türkçe. Hata/istisna mesajları İngilizce olabilir
  (loglarda aranabilirlik için).
- Yorumlar *neden*'i açıklamalıdır, özellikle güvenlik gerekçesini.
- Yeni bağımlılık eklemekten kaçının; eklemeniz gerekiyorsa PR'da gerekçesini yazın.

## Commit mesajları

Kısa ve emir kipinde bir başlık, gerekirse boş satırdan sonra açıklama:

```
Seçmen olaylarını ayrı zincire taşı

Ana zincirdeki sıra boşlukları oylama sürerken katılımı ele veriyordu.
```

## Lisans

Katkılarınız [AGPL-3.0-or-later](LICENSE) lisansı altında yayımlanır. PR göndererek
katkınızı bu lisansla sunma hakkına sahip olduğunuzu beyan etmiş olursunuz.
