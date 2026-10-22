# Alpha çekirdek sözleşmesi — 0.3.0-alpha.12

**Durum:** Deneysel uygulama tanımı, bağımsız denetimden geçmedi. Bu belge yeni bir standart veya güvenlik ispatı değildir.

## Sağlayıcı ve kapsam

Node.js 24.22.1+ / 24.x `node:crypto` ve Node'un birlikte getirdiği OpenSSL kullanılır. Yerel ölçümde Node 24.22.1 / OpenSSL 3.5.9 / Windows x64 test edildi. KEM, anahtar üretimi ve imza işlemleri callback API'leri üzerinden asenkrondur; yerel AEAD ve HKDF çağrıları senkrondur. 16 MiB mesaj sınırı bir prototip sınırıdır, yüksek trafikli servis için performans garantisi değildir.

ML-KEM-1024 ve ML-DSA-87 parametreleri sağlayıcıdan değiştirilmeden alınır. ML-DSA saf/pure imzalama modunda `algorithm=null`, native `context` seçeneğiyle kullanılır. Node'un KEM API kararlılığı sürüm bağımlılığıdır; [Node 24 belgeleri](https://nodejs.org/docs/latest-v24.x/api/crypto.html) ile birlikte değerlendirilmelidir.

## Anahtar ve yetki modeli

- KEM public/private, signing/verification, encapsulated/decapsulated secret ve encryption/decryption handle'ları ayrıdır.
- Public anahtarlar yalnızca kanonik DER SPKI olarak export/import edilir. Native parse sonrası algoritma ve yeniden export edilen baytlarla birebir eşitlik kontrol edilir.
- `publicKeyFingerprint(key)` tam kanonik SPKI'nin SHA-256 özetini `SHA256:` + 64 lowercase hex olarak döndürür. `requirePublicKeyFingerprint(key, expected)` tam güvenilir pin'i zorunlu kılar; hex case farkını kabul eder, kısa/whitespace/satır sonlu pin'i reddeder ve eşleşmede kanonik pin'i döndürür. KEM public veya imza verification handle gerekir; private/simetrik handle kabul edilmez. CLI aynı yardımcıları kullanır. Digest karşılaştırması native `timingSafeEqual` kullanır; bütün API için constant-time iddiası yoktur. Güvenilir expected değeri uygulama edinir; anahtarın kendisinden hesaplamak kimlik doğrulama sağlamaz. `encryptFile` otomatik pin doğrulamaz.
- Private/signing anahtarlar yalnızca [parolalı anahtar kasası](KEY-VAULT.md) olarak dışarı alınabilir ve geri yüklenebilir. Raw private key export/import genel API'ye açılmaz. KEM private handle `publicKey()`, signing handle `verificationKey()` ile eşleşen açık anahtarı üretebilir.
- Dış arayüz ham ortak sırrı döndürmez; bir kez türetilebilen handle döndürür. Alıcı tarafı yalnızca decryption yetkisi üretir.
- Şifreleme handle'ı bir mesaj içindir. Native işleme/RNG aşamasına girildiğinde tüketilir; tekrar şifreleme denemesi reddedilir. Açık girdi doğrulaması aşamasındaki ret handle'ı tüketmez.
- `destroy()` gelecekteki kullanımı kapatır. Buffer materyali eldeyse sıfırlanır, native key referansı bırakılır. JavaScript/GC, sağlayıcı kopyaları, snapshot veya fiziksel RAM için kesin sıfırlama iddiası yoktur. Başlatılmış async işlemi iptal etmez.
- Aynı JS sürecindeki saldırgan kod, monkey patch, debugger veya internal dosyalara erişim güven sınırının dışındadır; handle bir sandbox değildir.

## Deneysel KEM/KDF/AEAD akışı

Bu akış yeni bir klasik+PQC hibriti değildir; tek ML-KEM sırrından AES anahtarı türetir. Alpha API'nin gerçek davranışını incelenebilir kılmak için tam olarak yazılmıştır. HPKE diye etiketlenmez.

1. Alıcı ML-KEM-1024 anahtar çifti üretir. Açık anahtarın kimlikle güvenilir bağlanması uygulamanın sorumluluğundadır.
2. Gönderici standart ML-KEM encapsulation ile `ct_kem` ve 32 bayt sır elde eder.
3. Gönderici OS destekli RNG'den 32 bayt `salt` üretir.
4. `info` şu bayt dizisidir:

```text
ASCII("pqc-research-core/alpha1/ml-kem-1024/hkdf-sha512/aes256gcm\0")
|| uint32_be(context.length)
|| context
```

Buradaki `\0` tek bir NUL baytıdır. `context` en fazla 512 bayt olabilir; uygulama beklediği context'i kendisi sağlamalıdır.

5. `K = HKDF-SHA-512(IKM=shared_secret, salt=salt, info=info, L=32)` hesaplanır. Ortak sır handle'ı tüketilir ve eldeki Buffer temizlenir.
6. Tek kullanımlık encryption handle, RNG'den 12 bayt nonce üretir ve AES-256-GCM ile mesajı ve AAD'yi korur. Tag 16 bayttır.
7. Alıcı standart decapsulation çıktısı ve aynı salt/context ile anahtar türetir. Etiket doğrulandıktan sonra plaintext döndürülür.

KEM ciphertext'i 1568 bayt, salt 32 bayt, nonce 12 bayt ve tag 16 bayttır. API paketi `{nonce, ciphertext, tag}` döndürür; KEM ciphertext/salt bu paketin dışındaki ayrı alanlardır. **Wire format, paket serileştirme, transcript ve gönderici kimliği protokolü tanımlanmamıştır.** Bir oturum/mesaj formatı geliştirilirken profil ve kritik üstverinin kimlik doğrulamaya nasıl bağlanacağı ayrıca incelenmelidir. Bu küçük alpha akışının bağımsız bileşim kanıtı yoktur.

Rastgele salt her yeni türetmede anahtar çeşitliliği sağlar; aynı KEM ciphertext'in alıcıda tekrar çözülmesi replay'ı engellemez. Aynı runtime belleğinin/snapshot'ın geri yüklenmesi için tek kullanım garantisi verilmez. Rastgelelik sağlayıcısının doğru çalıştığı varsayılır.

`generateSymmetricKeyPair()` tek bir rastgele AES-256 anahtarı için bir kullanımlık encryption ve decrypt-only handle üretir. Bu yol KEM veya KDF kullanmaz; örneğin testler ve tek mesajın süreç içi korunması içindir. Ham anahtar paylaşma/kaydetme API'si olmadığı için kalıcı dosya şifreleme ürünü gibi kullanılamaz.

## Dosya ve kasa uzantıları

Önceki bölümdeki mesaj primitive'inin KDF etiketi ve akışı 0.1 ile uyumlu tutuldu. 0.2'de ayrı [dosya v1 biçimi](FILE-FORMAT.md) ve [kasa v1 biçimi](KEY-VAULT.md) eklendi. Dosya kökü, mesaj akışından ayrı context etiketi kullanır; her kayıt için ayrı HKDF anahtarı türetir. Bu, mesaj API'sindeki tek kullanım kuralını kaldırmaz. Uzantıların bağımsız bileşim kanıtı veya denetimi yoktur.

Dosya başlığı, bütün kayıtlar ve zorunlu son kayıt doğrulanır; hedef dosya en son exclusive hard link ile oluşturulur. Geçici plaintext diskte bulunur; çökmelerde kalabilir. Var olan hedefler üzerine yazılmaz. Dosya akışı iptal ve kaynak değişikliği kontrolleri içerir. Parolalı kasa yalnızca sabit Argon2id profili kabul eder; yanlış parola doğrulama hatası üretir.

## Girdi/hata sözleşmesi

`inspectContainer(inputPath, { signal })`, dosya veya kasa başlığındaki **doğrulanmamış iddiaları** salt okunur bir sonuçta döndürür. `kind` alanı `encrypted-file` veya `key-vault`, `authenticated` her zaman literal `false` olur. Dosyada alıcı pin iddiası, açık metin/parça boyutları ve algoritma profili; kasada anahtar türü ve sabit KDF profili sunulur. En fazla 1.664/64 bayt okunur. Şema/profil ve toplam uzunluk kontrolü normal okuyucularla paylaşılan yordamları kullanır; KDF/decapsulation/özel anahtar import'u, ciphertext kaydı veya tag doğrulaması yapılmaz. Başarılı inceleme, dosyanın çözülebilir/bozulmamış olduğu veya anahtarın sahibine ait olduğu anlamına gelmez. Başlık pin'i güvenilir pin yerine kullanılamaz. İşlem öncesi/sonrası stat kontrolü kötü niyetli eşzamanlı yazara karşı snapshot garantisi değildir.

- Bayt girdileri `Uint8Array`/`Buffer` olmalı; string kabul edilmez. `SharedArrayBuffer` reddedilir.
- Asenkron sağlayıcı çağrısından önce girdiler kopyalanır.
- Mesaj/ciphertext 16 MiB, AAD 64 KiB ile sınırlıdır.
- KDF context 512 bayt; imza context 255 bayt sınırındadır. Context argümanı zorunludur; uygulama açıkça boş bayt dizisi seçebilir.
- AEAD nonce ve tag uzunluğu sabittir. Tag doğrulanmadan plaintext dönmez; `update()` ara plaintext tamponu temizlenir.
- `INVALID_INPUT`: Açık tür/uzunluk/biçim sınırı ihlali.
- `INVALID_PASSWORD_HASH`: Hesap parola kaydı kanonik PHC veya desteklenen sınırlı profillerden biri değil; native KDF başlamaz. Doğru biçimli kayıtta yanlış parola verifyPassword için false verir.
- `INVALID_CONTAINER`: İncelemede tanınmayan başlangıç baytları veya 8 bayttan kısa girdi. Tanınan dosya/kasa başlığı hataları sırasıyla `INVALID_FILE`/`INVALID_VAULT` üretir.
- `INVALID_KEY`: Yanlış handle/algoritma veya geçersiz/noncanonical SPKI.
- `KEY_UNAVAILABLE`: Kapatılmış/tüketilmiş handle.
- `INVALID_FINGERPRINT`, `FINGERPRINT_MISMATCH`: Tam pin biçimi geçersiz veya geçerli pin başka public key'e ait.
- `RESOURCE_LIMIT`: Modül örneğinin kasa KDF kuyruğu dolu; native iş başlatılmaz.
- `POOL_CLOSED`: Uygulamanın isteğe bağlı işlem havuzu kapatıldı; queued/future görev kabul edilmez. Aktif görevler zorla durdurulmaz.
- `LEGACY_KEY_REQUIRES_MIGRATION`: Dış kasa doğrulandı fakat birleşik seed+expanded temsil katı varsayılanla reddedildi. Yalnız kontrollü geçiş `legacyKeyPolicy: 'seed-authoritative'` seçebilir; bu companion tutarlılık testi değildir.
- `ABORTED`: Dosya/kasa işlemi iptal edildi. Kasa sırasında başlamış native KDF'nin callback'i beklenir; bu bir zorla durdurma veya kesin süre sınırı değildir.
- `CLEANUP_FAILED`: Geçici çıktı temizliği hata bildirdi. Kalan close/unlink/rmdir adımları da denenir; cause içindeki AggregateError alttaki temizlik hatalarını saklar. Bu hata önceki işlem hatasının yerine geçebilir. Hedef daha önce yayımlanmış olabilir; çıktı klasörü ve `.pqc-stage-*` verileri incelenmelidir.
- `AUTHENTICATION_FAILED`: Doğru biçimli AEAD girdisinde yanlış anahtar, nonce, tag, ciphertext veya AAD. Alttaki provider hata ayrıntısı bu hata için verilmez.
- İmza doğrulama, biçim sınırları içindeki kısa veya yanlış imzada `false` döndürür; aşırı uzun/türce bozuk girdiler hata üretir.
- Doğru uzunluktaki geçersiz ML-KEM ciphertext için sağlayıcının implicit rejection davranışı korunur; ayrı doğruluk bayrağı döndürülmez. Boyutça yanlış ciphertext açık girdi hatasıdır.
- Provider/runtime/RNG kaynaklı operasyonel hatalar ayrıca fırlayabilir. Hata mesajları uygulama dışına ayrıntılı aktarılmamalı; limit/rate policy uygulama katmanında kurulmalıdır.

## Sağlamadığı özellikler

Alıcı anahtarı dağıtım/güven modeli, gönderici kimlik doğrulaması, replay koruması, forward secrecy, ele geçirme sonrası toparlanma, key commitment, metadata/uzunluk gizliliği, çok alıcılı format ve donanım yan kanal garantisi bu sürümün iddiaları değildir. ML-DSA imza primitive'i vardır; bunun bir şifreli protokole güvenli biçimde eklenmesi ayrıca tasarlanmalıdır.

## Sonraki kararlar

Dosya/kasa biçimlerinin bağımsız incelemesi ve kaynak tüketimi ölçümleri; güvenilir public-key dağıtımı; oturum gereksinimleri; sağlayıcı/runtime sürüm politikası; ticari kullanımı kısıtlayan nihai lisans. Özgün matematik ve çok algoritmalı birleşimler bu çekirdeğin güvenliğiyle karıştırılmadan ayrı araştırılmalıdır.
