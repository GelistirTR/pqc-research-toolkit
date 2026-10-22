# Geliştirici SDK'sı: kullanım alanı ve entegrasyon sözleşmesi

Ürün hedefi uygulamalara eklenen JavaScript/TypeScript kütüphanesidir. CLI tanılama ve entegrasyon yardımcısıdır; masaüstü arayüz geliştirme kapsamı değildir. Bu alpha yalnız Node 24.22.1+ / 24.x ile çalışır; tarayıcı, React Native, Android/iOS native veya diğer diller için SDK desteği iddiası yoktur. Yerel test ortamı Windows x64'tür.

## Birbirinden ayrı kullanım alanları

| Uygulamanın ihtiyacı | Doğru soyutlama | Mevcut durum |
| --- | --- | --- |
| Giriş parolasını doğrulamak | Salt'lı, maliyeti sınırlı parola hash/doğrulama; sürüm ve rehash politikası | Alpha.12 hashPassword/verifyPassword/passwordHashNeedsRehash; [hesap API sözleşmesi](ACCOUNT-PASSWORDS.md) |
| Sonradan geri alınması gereken token/sır saklamak | Authenticated encryption + uygulama/tenant bağlamı + anahtar saklama/rotasyon | Düşük seviye AEAD handle'ları var; kalıcı uygulama sırları için yüksek seviye format/anahtar yönetimi henüz yok |
| Bir alıcıya içerik şifrelemek | Güvenilir alıcı public key'i, KEM, bağlama bağlı KDF ve AEAD | Primitive ve dosya API'leri var; tam mesajlaşma protokolü değil |
| Gönderici kimliği, tekrar saldırısı ve oturum güvenliği | Kimlik/güven modeli, imza/oturum bağlama, replay politikası, anahtar yaşam döngüsü | Otomatik gönderici doğrulama, replay koruması, ratchet/forward secrecy yok |

Parola doğrulamada geri açılabilir şifreleme yerine uyarlanabilir hash yaklaşımı, [OWASP parola saklama rehberinin](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#hashing-vs-encryption) tavsiyesidir; 22 Ekim 2026'da kontrol edildi. `sealPrivateKey`/`openPrivateKey` yalnız özel anahtar kasası içindir. Alpha.12 ayrı hesap parolası API'si ekler; login parolası ile kasa parolası aynı kavram değildir. Tam sohbet protokolü için [tasarım kapısı](MESSAGING-DESIGN.md) geçerlidir.

## Kaynakları uygulama sınırında yönetme

Mevcut primitive'lerle tek mesajın süreç içi roundtrip örneği: `npm run demo:message`, kaynak [sdk-message-roundtrip.mjs](../examples/sdk-message-roundtrip.mjs). Örnek ağa mesaj göndermez ve kalıcı mesaj biçimi tanımlamaz; gerçek uygulamada gereken kimlik/oturum katmanlarını kapsamaz.

```js
import { createOperationPool, encryptFile } from 'pqc-research-core';

// Uygulamanın paylaşılan servis kapsamına yerleştirin, her istek için yeniden yaratmayın.
const pool = createOperationPool({ maxConcurrent: 2, maxQueued: 8 });

export function encryptDocument(options, requestSignal) {
  // recipient kimliği önceden güvenilir pin ile doğrulanmış olmalı.
  return pool.run(signal => encryptFile({ ...options, signal }), { signal: requestSignal });
}

export function stopAcceptingWork() { pool.close(); }
```

Havuz varsayılanı 2 aktif / 16 bekleyen görevdir; izin verilen aralık 1–16 aktif ve 0–64 bekleyendir. Dolu kuyruk `RESOURCE_LIMIT` verir. Sıra FIFO'dur; beklerken iptal görevini çıkarır. Aktif görev iptalinde gerçek promise yerleşene kadar slot tutulur. İptal sonrası görevin sonucu döndürülmez; callback sinyali yok sayıyorsa görev yine yan etki üretebilir. Callback sinyali gerçek SDK operasyonuna iletmeli; hatada yalnız çıktı varlığına bakarak karar verilmemelidir.

`close()` bekleyen ve gelecek görevleri `POOL_CLOSED` ile reddeder; aktif görevleri zorla durdurmaz. Aktif promise'leri çağıran takip edip beklemelidir. `stats`, active/queued/limit/closed için dondurulmuş anlık görünüm verir; polling ile bütün geçişleri yakalama garantisi yoktur.

Görev hata verirse kendi hatası korunur; iptal, CLEANUP_FAILED gibi temizlik/I/O hatalarını maskelemez. Başarıyla tamamlanan fakat iptal edilmiş görev sonucu ABORTED olur. Görevin gerçek yan etkileri bu hata koduyla geri alınmış sayılmaz.

Bu sınır görev adedidir: callback closure'ları ve girdileri kopyalanmaz veya bayt olarak sınırlanmaz. Doğrudan SDK çağrıları, başka havuzlar, worker'lar ve süreçler kapsam dışıdır. Global rate limit, toplam bellek bütçesi, istek gövdesi sınırı ve kullanıcı/tenant kotası uygulama sorumluluğudur. Dolu aynı havuzdaki bir görevin içinden başka bir görevi sıraya koyup `await` etmeyin; uygulama düzeyinde deadlock oluşabilir.

## Eski kasayı kontrollü dönüştürme

Alpha.11'in varsayılanı `legacyKeyPolicy: 'reject-combined'` olur. Birleşik seed+expanded temsil `LEGACY_KEY_REQUIRES_MIGRATION` üretir; seed-only ve desteklenen expanded-only korunur. CLI otomatik gevşek geçiş yapmaz. Önceki alpha.8 geçiş raporu tarihsel sonuçtur ve yeni politikanın yerine geçmez.

```js
import { openPrivateKey, requirePublicKeyFingerprint, sealPrivateKey } from 'pqc-research-core';

export async function migrateLegacyVault(oldVault, oldPassword, newPassword, trustedPin) {
  // Yalnız kontrollü geçiş; rutin hata kurtarmada otomatik fallback yapmayın.
  const restored = await openPrivateKey(oldVault, oldPassword, { legacyKeyPolicy: 'seed-authoritative' });
  const privatePart = restored.kind === 'kem' ? restored.privateKey : restored.signingKey;
  try {
    const publicPart = restored.kind === 'kem' ? restored.publicKey : restored.verificationKey;
    requirePublicKeyFingerprint(publicPart, trustedPin);
    return await sealPrivateKey(privatePart, newPassword);
  } finally { privatePart.destroy(); }
}
```

`trustedPin`, aynı eski kasadan yeni hesaplanmış pin değil, bağımsız güvenilir kimlik kaydı olmalıdır. Yeni kasa farklı bir hedefe yazılmalı ve geri açılarak doğrulanmalı; orijinal/yedekler korunmalıdır. Bu seçenek seed ile companion tutarlılığını kanıtlamaz; karşılaştırma gerektiren dış anahtar aktarımı için uygunluk iddiası değildir. API çağıranın parola tamponlarını sahiplenmez; çağıran da kendi geçici sırlarını temizlemelidir.

## Sıradaki API kapıları

Parola modülünün ilk sürümü alpha.12'de eklendi: sabit yeni profil, sınırlı eski profil, PHC kaydı, ortak KDF bütçesi ve iptal. Sonraki kapılar pepper/rotasyon ihtiyacı, hedef sunucuda maliyet/servis yükü, bağımsız inceleme ve uygulama auth politikasıdır; tek makine ölçümü bütün dağıtımlar için maliyet önerisi sayılmaz.

Uygulama sırrı modülü: anahtar kaynağı/rotasyonu, envelope sürümü, tenant/amaç bağlama, nonce yaşam döngüsü, veri saklama ve yedekten kurtarma sözleşmesi; key material ile şifreli verinin aynı korumasız yerde tutulmaması.

Mesaj modülü: tehdit modeli, çevrimiçi/çevrimdışı alıcı, kimlik ve anahtar değişimi, sıralama/replay, oturum ve cihaz geçişleri, forward secrecy beklentisi, standart protokol/sağlayıcı değerlendirmesi. Primitive'lere JSON sarmalamak güvenli sohbet protokolü kurmuş sayılmaz. Tasarım ve inceleme tamamlanmadan böyle bir API kararlı olarak sunulmaz.
