# Runtime güvenlik güncellemesi — 22 Ekim 2026

Alpha.8'in minimum sürümü **Node 24.22.1**, desteklenen hat **24.x**. Portable paket bu tam sürümü ve birlikte gelen **OpenSSL 3.5.9**'u içerir. [21 Ekim 2026 resmî sürüm notu](https://nodejs.org/en/blog/release/v24.22.1/) bunun bir güvenlik yayını olduğunu kaydeder; [duyuru](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) etkilenen sürüm hatlarını açıklar. Burada listelenen her açığın çevrimdışı dosya CLI'sinde kullanılabildiği veya bütün sistemin güvenli olduğu sonucu çıkarılmaz.

Önceki alpha.4–alpha.7 portable paketler 24.16.0 taşıyordu. Önceki checksum/işlev testi, runtime'ın güncel güvenlik yaması olduğu anlamına gelmiyordu. Güncel kit tercih edilmeli; eski arşivler yalnız geçmiş kayıt olarak tutulur. Bilgisayardaki sistem Node kurulumu bu projede değiştirilmedi. Güncelleme, çalışma alanında izole bir binary ile sınandı.

## Kaynak doğrulaması

Binary yalnız resmî Node HTTPS adresinden alındı; SHA-256 hem resmî checksum dosyasıyla hem sürüm sayfasıyla eşleşti. Windows Authenticode durumu Valid, yayıncı OpenJS Foundation olarak kontrol edildi. Tam sürüm lisansı ve kaynak/özet kaydı [third_party/node-v24.22.1](../third_party/node-v24.22.1/provenance.json) altında; binary Git'e alınmaz. Detached GPG checksum imzası doğrulanmadı. Launcher'ın kendisi imzasızdır; binary hash/manifest bir imzalı proje yayını değildir.

## Uyumluluk

**Alpha.11 politika değişikliği:** aşağıdaki alpha.8 deneyi tarihsel bir uyumluluk kaydıdır. Yeni SDK, birleşik seed+expanded kasa içeriğini varsayılan olarak reddeder. Eski kasalar için açık `legacyKeyPolicy: 'seed-authoritative'` kontrollü geçişi ve güvenilir public-key pin kontrolü gerekir; [kasa sözleşmesi](KEY-VAULT.md) geçerlidir. Seed-only/expanded-only desteği sürer. Bu değişiklik runtime güncellemesi veya yeni wire formatı değildir.

Eski Node/OpenSSL'in ürettiği KEM ve imza kasaları yeni runtime ile açıldı; çok parçalı dosya çözüldü ve imza doğrulandı. Bu denemede eski uygulamanın yeniden export karşılaştırmasının seed-only kasayı reddettiği görüldü. Yeni [dar DER okuyucusu](../src/vault-pkcs8.js) seed-only, expanded-only ve eski seed+expanded temsilleri kabul eder. Seed export edilebiliyorsa yeni çıktı sabit seed-only'dir; seed'i olmayan expanded-only anahtarlar korunur. Eski companion'ın içerik tutarlılığı doğrulanmaz, seed otoritatiftir; ayrıntılı kapsam [kasa sözleşmesinde](KEY-VAULT.md) açıklanmıştır.

Node'un raw-seed biçimi belgelerde aktif geliştirme API'si olarak işaretlidir; sürüm sabitleme ve geçiş testleri bu bağımlılığı izler. Bu, bütün Node/OpenSSL sağlayıcı ayarları, dış PKCS#8 biçimleri veya gelecekteki sürümler için uyumluluk garantisi değildir. Eski istemciyi güncellemeden yeni kasa ona verilmemelidir. Kayıtlar [doğrulama raporunda](DOGRULAMA.md); test anahtarları ve fixture dosyaları yalnız ignored yerel test dizinindedir.

## Sonraki güncellemeler

Kurulum, CLI ve doctor otomatik ağ kontrolü veya runtime indirmesi yapmaz. Paket sabit binary taşır; yeni güvenlik duyurusunda sürüm/engine alt sınırı, CI, provenance/lisans, launcher pin'i ve portable paket birlikte gözden geçirilmeli. Resmî kaynak/özet/imza kontrolleri, eski veriyi okuma deneyi ve ilgili testler tamamlanmadan yeni runtime desteklendiği iddia edilmemeli. Bu tarihli kontrol, gelecekte sürekli güncel kalma veya tüm açıklardan etkilenmeme garantisi değildir.
