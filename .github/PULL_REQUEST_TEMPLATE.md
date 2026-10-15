## Ne değişti, neden?

<!-- Kısa açıklama ve ilgili issue -->

## Güvenlik kontrol listesi

- [ ] Oy pusulasına / sandık tablosuna seçmen, zaman veya sıra bilgisi eklenmedi
- [ ] Oylama sürerken katılım veya sonuç gösteren yeni bir yol açılmadı (ekran, API, log, checkpoint, sıra numarası)
- [ ] Zaman kullanan kod sistem saati yerine `timekeeping.get_clock()` kullanıyor
- [ ] Hassas yeni alanlar `fieldenc` ile şifreleniyor; yeni tablolar gerekiyorsa `rowmac` / tetikleyici ile korunuyor
- [ ] `schema.sql` değiştiyse: geçiş notu CHANGELOG'da (mevcut kurulumların şema parmak izi değişir)
- [ ] Yeni davranış için test eklendi; `python -m pytest`, `ruff check`, `bandit` temiz

## Nasıl test edildi?

<!-- Windows / Linux, elle denenen adımlar -->
