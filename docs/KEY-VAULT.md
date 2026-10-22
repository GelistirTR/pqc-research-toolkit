# Parolalı anahtar kasası v1

**Uygulama:** 0.3.0-alpha.12 (wire format v1 değişmedi) · **Durum:** Deneysel kapsayıcı; bağımsız güvenlik denetimi yoktur.

`sealPrivateKey(key, passphrase, options?)` KEM private veya ML-DSA signing handle'ını parolayla şifrelenmiş bayt dizisine dönüştürür. `openPrivateKey(vault, passphrase, options?)` türü ayrılmış anahtar çifti döndürür. Çıktının diske yazılması çağırana aittir; `wx` gibi üzerine yazmayan oluşturma ve yerel erişim kontrolleri kullanılmalı. Örnek: [file-roundtrip](../examples/file-roundtrip.mjs).

Parola `Uint8Array`/`Buffer` olarak **16–1024 bayt** olmalı. Alt uzunluk sınırı entropi ölçümü değildir; tekrar kullanılan veya tahmin edilebilir parola güçlü hale gelmez. UTF-8/parola oluşturma politikası uygulamaya aittir. API, çağıranın orijinal parola tamponunu değiştirmez; kendi kopyasını temizler. Kullanıcı orijinal kopyanın yaşam döngüsünü yönetmelidir.

## Sabit profil

Argon2id sürüm 19, **64 MiB**, **3 geçiş**, **4 lane**, 32 bayt çıktı. Salt 16 rastgele bayt; Argon2 associated data `ASCII("pqc-research-core/vault/v1\0")`. Çıktı AES-256-GCM anahtarıdır; 12 rastgele nonce baytı ve 16 bayt tag kullanılır. Bu maliyet profili [RFC 9106'nın bellek sınırlı ortamlar için ikinci önerisine](https://www.rfc-editor.org/rfc/rfc9106.html#section-4) dayanır; hedef cihazda gecikme ve kaynak kullanımı ayrıca değerlendirilmelidir.

Uygulama yalnızca bu tam profili kabul eder; saldırganın verdiği bellek/geçiş/lane değerleriyle KDF çalıştırılmaz. Her çağrı yine yaklaşık 64 MiB Argon2 belleği ve CPU tüketir. İşlem [Node native asenkron API'sinden](https://nodejs.org/docs/latest-v24.x/api/crypto.html#cryptoargon2algorithm-parameters-callback) geçer; başlamış native işi kesme API'si kullanılmaz.

## Eşzamanlı iş sınırı

Alpha.5'ten itibaren `sealPrivateKey` ve `openPrivateKey` aynı yüklenmiş modül örneğinde ortak sınırlayıcı kullanır: en fazla **2 başlatılmış native KDF isteği**, **16 FIFO bekleyen istek**. Değerler değiştirilemeyen `vaultProfile.maxConcurrentKdf` ve `maxQueuedKdf` alanlarında görünür. Kapasite dolduğunda yeni istek native KDF'ye gönderilmeden `CryptoError` / `RESOURCE_LIMIT` ile reddedilir. Yapısal kasa/parola kontrolleri kuyruğa girmeden önce yapılır. Native hata veya eşzamanlı sağlayıcı hatası da rezervasyonu bırakır; bekleyen en eski istek sırayı alır. API'nin parola kopyası ve seal işlemindeki geçici DER, kuyruk reddi dahil normal sonlanma yollarında best-effort temizlenir.

İki işin Argon2 bellek parametresi toplamı 128 MiB'dir; bu, süreç RAM üst sınırı veya bellek ölçümü değildir. Bekleyen işler parola kopyasını, seal için geçici DER'i veya open için kasa kopyasını taşır. KDF tamamlandığında slot serbest bırakılır; daha sonraki AES/parse işlemi bu slotun parçası değildir. Native iş libuv içinde de bekliyor olabilir. Sağlayıcı tamamlanmazsa aktif slotlar dolu kalır ve yeni işler sınırda reddedilir.

Bu politika **süreçler, worker'lar veya ayrı yüklenmiş kütüphane kopyaları arasında ortak değildir**. Başka doğrudan `crypto.argon2` çağrılarını sınırlamaz. Çok kullanıcılı servisler kimlik başına rate sınırı, toplam worker/süreç bütçesi ve dış istek kuyruğunu ayrıca yönetmeli; dolu kuyruğa sınırsız/anında otomatik retry eklememeli. Bu sınırlar bir DoS koruması garantisi veya bütün cihazlar için performans önerisi değildir.

## İptal

Alpha.6'da iki API de üçüncü argümanda `{ signal: AbortSignal }` kabul eder. Örneğin `await openPrivateKey(vault, passphrase, { signal: AbortSignal.timeout(5000) })`. Bu bir kesin süre sınırı değildir: zamanlayıcı event loop'tan geçer ve başlamış native işin bitişini bekler.

Önceden iptal edilmiş signal, girdi kopyalama/KDF öncesinde `ABORTED` üretir. Kuyrukta iptal edilen istek hemen sıradan çıkar; Promise hata ile sonlanırken sahip olunan parola/DER tamponları best-effort temizlenir ve bekleyen kapasitesi boşalır. Kuyruktan slot alan fakat henüz native işe gönderilmeyen istek de yeniden kontrol edilir. Başlamış native işin rezervasyonu **callback gelene kadar bırakılmaz**; girdi belleği native iş kullanırken sıfırlanmaz. Sonrasında çıktı materyali temizlenir, kasa veya açık anahtar handle'ı döndürülmeden `ABORTED` üretilir. Aynı anda native hata oluşursa iptal hatası önceliklidir. İptal gerekçesi (`signal.reason`) hata mesajına eklenmez.

Kuyruk dinleyicileri [Node `addAbortListener`](https://nodejs.org/download/release/v24.16.0/docs/api/events.html#eventsaddabortlistenersignal-listener) ile kurulur; iptal veya slot aktarımı sonrası kaldırılır. Başka bir dinleyicinin `stopImmediatePropagation()` çağrısı bu dinleyiciyi engellemez. İptal, daha önce çağırana dönmüş çıktıyı/handle'ı geri almaz; fiziksel bellek silme veya sağlayıcı işini zorla durdurma garantisi değildir. CLI ve doctor aynı sinyali kasa işlemlerine iletir; Ctrl+C aktif KDF sırasında kullanılırsa normal çıkış için native callback beklenir.

## Bayt biçimi

Bütün tamsayılar unsigned big-endian. Başlık 56 bayt:

| Ofset | Uzunluk | Alan |
|---:|---:|---|
| 0 | 8 | `PQCVAULT` |
| 8 | 1 | Sürüm 1 |
| 9 | 1 | Anahtar türü: 1 ML-KEM-1024, 2 ML-DSA-87 |
| 10 | 1 | KDF kimliği 1 |
| 11 | 1 | AEAD kimliği 1 |
| 12 | 4 | Bellek KiB: 65536 |
| 16 | 4 | Geçiş: 3 |
| 20 | 4 | Lane: 4 |
| 24 | 16 | Salt |
| 40 | 12 | Nonce |
| 52 | 4 | Ciphertext uzunluğu |

Ardından `ciphertext || tag` gelir. Plaintext, sürüm-0 DER PKCS#8 private key'dir; raw private key export API'si çağırana açılmaz. Alpha.8 seed export edilebildiğinde yeni çıktıda seed-only temsilini sabitler: ML-KEM-1024 için 86, ML-DSA-87 için 54 plaintext baytı. Bu yeni seed-only kasalar sırasıyla 158 ve 126 bayttır. Seed yoksa dar şemayla doğrulanan native PKCS#8 korunur; eski daha uzun kasalar da sınır dahilinde okunur. Plaintext için 16 KiB sınır; tam kapsayıcı için 16456 bayt sınır vardır. Başlığın tamamı GCM AAD'dir. Ek bayt, eksik bayt ve bilinmeyen profil reddedilir.

Yanlış parola ile salt/nonce/ciphertext/tag veya geçerli tür alanının değiştirilmesi aynı `AUTHENTICATION_FAILED` kodunu üretir. Yapısal/profil hataları `INVALID_VAULT`, genel girdi/tür/uzunluk hataları `INVALID_INPUT` olabilir. Doğrulanmış plaintext parse edildikten sonra beklenen algoritma kontrol edilir.

CLI `change-password` mevcut kasayı açar, aynı anahtarı yeni salt/nonce ile yeni bir kasaya kapatır ve farklı bir hedefe exclusive yayınlar. Etkileşimli yeni parola iki kez alınır. Özel anahtar plaintext olarak diske export edilmez; işlem sırasında sağlayıcının belleğinde ve kasa API'sinin geçici DER tamponunda bulunur. Bellek temizliği best-effort düzeyindedir. Orijinal kasa silinmez; anahtar kimliği/algoritması değişmez ve eski yedekler eski parolayla açılabilir.

## Testler ve sınırlar

### PKCS#8 ve eski kasa geçişi

Node 24.16.0 / OpenSSL 3.5.6 eski çıktılarda seed+expanded temsilini üretirken, yeni sağlayıcının varsayılan çıktısı aynı anahtar için seed-only olabilir. Geçerli PKCS#8 girdisini yeniden export edilen baytlarla karşılaştırmak bu nedenle sürümler arası bir doğrulama kuralı değildir. Alpha.8 bunun yerine dar bir DER şemasını doğrular: sürüm 0, beklenen algoritma OID'si, parametresiz AlgorithmIdentifier ve tam olarak tek bir seed-only, expanded-only veya eski seed+expanded CHOICE. Minimal uzunluk kodlaması gerekir; trailing byte, ek alan/attribute, yanlış tür/uzunluk reddedilir. Expanded-only biçimde tür/uzunluk sınırından sonra native sağlayıcı private-key import/validasyon yolu kullanılır. Genel PKCS#8 import API'si değildir.

Alpha.11, eski `both` temsilini varsayılan olarak **`LEGACY_KEY_REQUIRES_MIGRATION`** ile reddeder. Bu hata ancak dış kasa doğrulandıktan sonra üretilebilir; yanlış parola önce `AUTHENTICATION_FAILED` verir. Kontrollü geçişte `openPrivateKey(vault, password, { legacyKeyPolicy: 'seed-authoritative' })` açıkça seçilebilir. Bu seçenekte kimliği belirleyen tek kaynak doğrulanmış plaintext içindeki seed'dir; expanded alanın türü/uzunluğu denetlenir fakat içeriği karşılaştırılmaz. Çağıran, dönen public key'i bağımsız güvenilir tam pin ile doğrulayıp yeni seed-only kasaya kapatmalı; orijinali/yedeği korumalıdır. Normal uygulama akışında hata yakalayıp otomatik olarak gevşek politikayla tekrar denemeyin.

[RFC 9935 §8](https://www.rfc-editor.org/rfc/rfc9935.html#section-8), ML-KEM seed'den genişletilen anahtarın tam bayt karşılaştırmasını tanımlar. Desteklenen Node API'si bu iki PQ anahtar türünde `raw-private` genişletilmiş export sunmaz; yerel denemede `ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS` üretildi. Bu yüzden tam tutarlılık testi yapıldığı iddia edilmez. JWK export'u da seed taşır; tutarlılık kanıtının yerine kullanılmaz. Katı politika tutarlılık kanıtlamaz, belirsiz temsili reddeder. Seed-only ve desteklenen expanded-only biçimler varsayılan olarak kabul edilmeye devam eder.

Alpha.7 ve eski uygulamaların bytewise re-export kontrolü yeni seed-only kasayı reddedebilir; yeni kasayı eski uygulamaya taşımadan önce uygulamayı güncelleyin. Alpha.8 eski kasayı açabilir; geçiş mevcut dosyayı değiştirmez. İncelenen Node güvenlik güncellemesi ve ölçülen geçiş sonuçları [runtime politikasındadır](RUNTIME-POLICY.md).

KEM ve imza anahtarı şifreleme/açma; eski handle kapatıldıktan sonra geri yüklenen anahtarın gerçek şifre çözme/imza işlemi; yanlış parola; başlık ve tag değişimi; kötü niyetli maliyet alanları; async girdi kopyalama test edilir. Node Argon2id, [RFC 9106 §5.3 sabit test vektörü](https://www.rfc-editor.org/rfc/rfc9106.html#section-5.3) ile karşılaştırılır. Noble Argon2id ayrıca gerçek 64 MiB profili türetip üretilen kasayı açar.

Bu testler parola entropisi, fiziksel yan kanal, swap/snapshot veya sağlayıcının tüm bellek kopyalarının silinmesi için garanti vermez. Kasayı ve parolayı birlikte ele geçiren saldırgana karşı koruma veya çevrimdışı parola tahminini tamamen engelleme iddiası yoktur. Eski kasaların kopyaları, parola değişiminden sonra da eski parolayla açılabilir; güvenli silme ve anahtar rotasyonu ayrı işlemlerdir.
