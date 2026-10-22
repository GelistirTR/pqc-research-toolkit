# SDK kaynak kullanımı ve arıza dayanıklılığı — alpha.11

Bu tablo alpha.11'in tarihli ölçümüdür. Alpha.12 ortak kasa/hesap Argon2 bütçesi ve ek hesap doğrulama vakası için [ayrı beş vakalık rapor](validation-resources-alpha12.json) üretildi. Diğer testlerle eşzamanlı yük etkisiyle tek örnek alınmıştır; eski/yeni duvar süreleri kontrollü performans karşılaştırması sayılmaz.

22 Ekim 2026, Windows x64, Node 24.22.1 / OpenSSL 3.5.9, Intel Core i5-12450H. [Ham ölçüm](validation-resources-windows-x64.json), tekrar çalıştırma: `npm run benchmark:resources`. Gerçek kullanıcı verisi veya anahtarı kullanılmadı; sentetik dosyalar yalnız sahipliği doğrulanan test temp dizinlerinde üretildi.

## Gerçek ölçüm

Her vaka ayrı Node alt sürecinde bir kez çalıştı. Dosyalar 1 MiB parçalarda yazıldı/şifrelendi; doğrulamada iki dosyanın SHA-256 özeti streaming olarak karşılaştırıldı, tam dosya RAM'e alınmadı. İki paralel dosya vakasında iki ayrı ciphertext/hedef üretildi. CPU süreleri ham JSON'da user/system olarak ayrı tutulur; çok çekirdekli native işlerde toplam CPU wall süresinden büyük olabilir.

| Vaka | Şifreleme wall ms | Çözme/açma wall ms | Örneklenen tepe RSS MiB |
| --- | ---: | ---: | ---: |
| 32 MiB, 1 aktif dosya | 116,77 | 130,36 | 115,64 |
| 128 MiB, 1 aktif dosya | 398,80 | 566,86 | 124,51 |
| 32 MiB × 2 aktif dosya | 242,17 | 215,75 | 126,77 |
| 6 kasa açma, en fazla 2 aktif | — | 328,64 | 176,13 |

RSS 10 ms aralıkla örneklendi; kısa tepeyi kaçırabilir. JSON'daki lifetime maxRSS setup, fixture oluşturma ve hash doğrulamasını da içerir; yalnız kripto fazının bellek miktarı değildir. Node/GC/native allocator, OS önbelleği, disk ve arka plan yükü sonucu etkiler. Bir örnekten p95/p99, mobil performansı, sabit bellek tavanı veya 64 GiB fiziksel dosya başarısı çıkarılamaz. En büyük gerçek dosya bu raporda 128 MiB'dir; 64 GiB üst sınırının bozuk başlık reddi ayrı test edilir.

Ölçümler bu makinede çalışmanın kanıtıdır; daha büyük dosya, uzun süreli paralel servis yükü, saldırgan iş yükü veya tüketici uygulamasının closure/girdi belleği için garanti değildir. `createOperationPool` görev adedini sınırlar, RSS'i değil. Uygulama farklı süreç/worker'ları ve doğrudan SDK çağrılarını ayrıca bütçelemelidir.

## Arıza matrisi

| Durum | Yöntem | Gözlenen sözleşme |
| --- | --- | --- |
| RNG ve kripto sağlayıcısı hatası | 13 kontrollü alt süreç enjeksiyonu | Başarılı kripto sonucu yok; nonce hata sonrası key tüketilmiş, HKDF hata sonrası owned shared-secret tamponu sıfır |
| Disk dolması | Önceki gerçek write üstüne ENOSPC enjeksiyonu | Hedef yok, normal cleanup ile staging yok |
| İzin / fsync / hard-link arızası | Yeni kontrollü I/O enjeksiyonları | Hedef yok, normal cleanup ile staging yok |
| Geç tag hatası / kaynak değişimi / iptal | Gerçek kapsayıcı mutasyonları ve kontrollü I/O | Tam doğrulama olmadan son hedef yok; normal cleanup kontrol edilir |
| Close/unlink/rmdir arızası | Önceki ayrı cleanup regresyonları | Bütün adımlar denenir, CLEANUP_FAILED; hedef daha önce oluşmuş veya staging kalmış olabilir |
| Sürecin zorla kapatılması | İlk gerçek plaintext write sonrası alt süreç kill | Son hedef yok; staging içinde bir sentetik plaintext parça kaldı |
| Dolu görev havuzu | Kontrollü bekletilen promise'ler | RESOURCE_LIMIT, taşan görev çalıştırılmıyor; FIFO; queued abort kaldırılıyor |
| Aktif görevin iptali | İptali yok sayan kontrollü görev | İş yerleşmeden slot bırakılmıyor; sonucu döndürmeden ABORTED |

Enjeksiyonlar tüm gerçek disk/ACL arızalarının birebir modeli değildir. Kill deneyi gerçek güç kesintisi/kernel çökmesi veya diskten silme testi değildir. Testler yalnız kendi yeni sentetik temp klasörlerini temizler. Ürün kendiliğinden eski staging klasörü silmez; bilinmeyen dosyayı otomatik temizlemek veri kaybı riski taşır.

## Uygulama geliştiricisi için sonuç

Tekrar denemeyi sınırlayın; yanlış pin, AUTHENTICATION_FAILED veya LEGACY_KEY_REQUIRES_MIGRATION için kontrolleri otomatik gevşetmeyin. API hata verdiğinde yalnız hedefin varlığına göre başarı kararı vermeyin. Özel staging/hedef klasörlerini ve ACL'leri uygulama kurmalıdır; hassas kullanımda disk/swap/yedek/snapshot koruması ayrıca gerekir. Farklı dosya sistemleri için hard link ve izin davranışını hedef ortamda test edin.

Bu çalışma seçilen kaynak/arıza aşamasını yerel, ölçülebilir bir kapsamda tamamlar; bağımsız denetim, geniş ölçekli DoS testi ve platformlar arası kabul kapıları açık kalır.
