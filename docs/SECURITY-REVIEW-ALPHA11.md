# Alpha.11 yerel güvenlik incelemesi

22 Ekim 2026. Kullanıcının seçtiği güvenlik açık işleri ve kaynak/arıza dayanıklılığı kapsamı incelendi, uygulanabilir değişiklikler bu sürümde yapıldı. Yöntem: kaynak okuma, resmi Node/OpenSSL/RFC belgeleri, kontrollü alt süreç hata enjeksiyonu ve regresyonlar. JavaScript/TypeScript için security-best-practices becerisi kullanıldı; düz Node kripto kütüphanesine özel framework referansı bulunmadığından ilgisiz web framework kuralları uygulanmadı. Bağımsız denetim, tüm kodun güvenli olduğu hükmü veya kriptografik bileşim ispatı değildir.

## R1 — Orta: birleşik eski özel anahtarın sessiz kabulü — varsayılan değiştirildi

Kaynak: `src/vault-pkcs8.js:55`, `src/vault-pkcs8.js:87`, `src/key-vault.js:156`. Önceki politika, dış GCM doğrulaması geçince seed+expanded girdide companion içeriğini kullanmadan seed'i seçiyordu. Bu açıkça belgelenmişti; fakat geliştirici varsayılan kabulü tutarlılık kontrolü olarak yorumlayabilirdi. Dış GCM doğrulaması olmadan bir saldırganın geçerli kasa üretebildiği tespit edilmiş değildir.

Alpha.11 varsayılanı birleşik temsili `LEGACY_KEY_REQUIRES_MIGRATION` ile reddeder. Bilinmeyen politika girdi aşamasında reddedilir. Açık `seed-authoritative` yalnız kontrollü geçişte kullanılabilir; yeni reseal seed-only üretir. Testler iki algoritmada eşleşen/çelişen companion, yanlış parola, geçersiz politika, açık geçiş ve katı varsayılanla yeniden açmayı kapsar. Red-before/green-after kaydı ignored yerel logda korunur.

Ayrıca gerçek Node 24.16.0 / alpha.7 sentetik kasaları, aynı eski okuyucudan alınan public pin'lerle karşılaştırıldı. Alpha.11 varsayılan ret, açık geçişte pin eşleşmesi, eski dosya/imzanın kullanılması ve reseal sonrası strict okuma geçti: [makine raporu](validation-legacy-policy-alpha11.json). Bu rapor özel anahtar veya parola içermez; dış sağlayıcıların tamamını kapsamaz.

Sınır: bu değişiklik tam consistency kontrolü değildir. [RFC 9935 §8](https://www.rfc-editor.org/rfc/rfc9935.html#section-8), ML-KEM için yeniden türetme ve bytewise karşılaştırmayı açıklar. [Node key formats](https://nodejs.org/docs/latest-v24.x/api/crypto.html#key-formats) bu PQ türlerinde raw-seed/public/JWK/DER sağlar; raw-private genişletilmiş export yoktur. Gerçek pinned runtime denemesinde incompatible-key-options alındı; JWK private alanı da seed boyutundaydı. Harici tam consistency gereksinimi açık kalır. Bağımsız güvenilir public pin kontrolü companion tutarlılığının yerine geçmez.

## R2 — Dağıtıma bağlı kaynak tüketimi — isteğe bağlı kontrol eklendi, global risk açık

Kaynak: `src/operation-pool.js:7`, `src/operation-pool.js:20`, `src/operation-pool.js:39`. Tek işlemde bayt sınırı, saldırganın uygulamaya çok sayıda paralel iş kabul ettirmesini engellemez. Yeni `createOperationPool` aktif/bekleyen görev sayısını sınırlar, FIFO ve kuyruk iptali uygular. Native/diğer asenkron iş bitmeden aktif slot bırakılmaz. Sync/async hata sonrası kapasite geri gelir; close, queued/future işleri reddeder. Gerçek dosya SDK entegrasyonu test edildi. Son incelemede havuzun iptal sırasında CLEANUP_FAILED'i ABORTED ile maskeleyebilmesi regresyonla yakalandı ve giderildi: görev hatası korunur; yalnız başarılı geç sonuç iptal hatasına dönüşür.

Sınır: çağıran doğrudan SDK çağrılarıyla havuzu atlayabilir; closure girdileri ve toplam worker/süreç belleği sınırlanmaz. Callback signal'ı iletmiyorsa yan etkiden sonra ABORTED alınabilir. Aynı dolu havuza iç içe await uygulama deadlock'u yaratabilir. Servis global rate/input/tenant limitleri hâlâ gereklidir. Bu bir sandbox veya DoS ispatı değildir.

## R3 — Hassas veriye bağlı yüksek etki: çökmede staging plaintext — tasarım sınırı doğrulandı

Kaynak: `src/file-io.js:47`, `src/file-io.js:69`, `test/file-faults.test.js`. Zorla kapanan alt süreçte bir doğrulanmış parça staging dosyasına yazıldıktan sonra süreç sonlandırıldı. Son hedef oluşmadı, fakat sentetik plaintext staging altında kaldı. Bu önceki sözleşmeyle uyumludur; kesin temizlik veya fiziksel silme iddiası eklenmez. Test yalnız kendi sentetik geçici klasörünü temizler.

Kontrollü sync/izin/link arızalarında normal cleanup geçti. Önceki disk-full, geç doğrulama, iptal ve cleanup-failure testleri de geçerli. Gerçek güç kesilmesi, kernel crash, tüm ACL varyantları, antivirüs/OneDrive/ağ volume davranışları ve diskten kurtarma sınanmadı. Kütüphane otomatik eski staging silmez; bu kullanıcı verisi silme riski yaratabilir. Uygulama özel klasör, şifreli disk ve yetkili kurtarma politikası kurmalıdır.

## R4 — Sağlayıcı/RNG hata davranışı — kontrollü test kapsamı genişletildi

Kaynak: `test/provider-faults.test.js`, `src/aead.js`, `src/kdf.js`, `src/asymmetric.js`, `src/key-vault.js`. On üç ayrı alt süreç senaryosu: simetrik keygen/nonce RNG, HKDF, iki PQ keygen, encapsulate/decapsulate, sign/verify, Argon2, dosya RNG/KEM/cipher. Hata başarılı sonuç üretmez; nonce hatasından sonra encryption handle tekrar kullanılamaz; HKDF hatasında owned shared-secret tamponu sıfırlanır; Argon hata sonrası yeni iş çalışır; dosya hatalarında son hedef/staging kalmaz.

Sınır: bunlar API düzeyinde kontrollü arızalardır; gerçek entropi kalitesi, kernel RNG arızası, hardware fault, tüm OpenSSL iç durumları veya zamanlama sızıntısı testi değildir. SDK beklenmedik provider/I/O hatalarını çağırana aktarabilir; HTTP/log sınırında sanitize edilmelidir. CLI'nin mevcut sanitize davranışı ayrı regresyonlarla korunur.

## Açık kabul kapıları

Bağımsız kriptografik tasarım/uygulama incelemesi; tüm desteklenen sağlayıcı/anahtar temsilleri; gerçek diğer OS/cihazlar; yan kanal ve geniş fuzzing; üretim servis yükü ve kaynak bütçesi. Hesap parolası hash API'si, kalıcı uygulama sırrı yönetimi ve tam mesaj protokolü bu sürümde yoktur. İlgili gereksinimler [SDK sözleşmesinde](GELISTIRICI-SDK.md), ölçümler [kaynak raporunda](KAYNAK-DAYANIKLILIK.md) tutulur.
