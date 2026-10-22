# Hesap parolası API'si — alpha.12

`hashPassword`, `verifyPassword`, `passwordHashNeedsRehash` ve `passwordHashProfile` geliştirici SDK export'larıdır. Bunlar geri açılabilir şifreleme veya hesap yönetimi servisi değildir. Hash kaydı veritabanına konur; plaintext parola kaydedilmez. Salt ve hash kayıtlarını da erişim denetimiyle koruyun; örnekler dışındaki gerçek değerleri loglamayın.

```js
import { hashPassword, verifyPassword, passwordHashNeedsRehash } from 'pqc-research-core';

const bytes = Buffer.from(passwordFromYourValidatedRequest, 'utf8');
try {
  const record = await hashPassword(bytes, { signal: requestSignal });
  // Kayda özel kimlik/tenant bağlama ve atomik DB işlemi uygulama sorumluluğudur.
  // await users.storePasswordHash(accountId, record);

  const valid = await verifyPassword(record, bytes, { signal: requestSignal });
  if (valid && passwordHashNeedsRehash(record)) {
    const upgraded = await hashPassword(bytes, { signal: requestSignal });
    // DB'de karşılaştır-ve-değiştir; eşzamanlı parola değişimini ezmeyin.
  }
} finally { bytes.fill(0); }
```

Yukarıdaki kayıt/giriş parçaları API kullanımını birlikte gösterir; üretim girişinde DB'deki mevcut kayıt doğrulanır, istemciden gelen hash güvenilir kabul edilmez. İstekten gelen string'in orijinal kopyası immutable olabilir; `Buffer.fill` bütün kopyaların silinmesini garanti etmez. Çalışan sentetik örnek: `npm run demo:passwords`.

## Kayıt ve maliyet sözleşmesi

Yeni kayıt `Argon2id`, v=19, m=65536 KiB, t=3, p=4; rastgele 16 bayt salt ve 32 bayt digest kullanır. Kayıt tam 97 ASCII karakterlik standart PHC string'idir; base64 `+`/`/` alfabesiyle, padding olmadan ve kanonik son bitlerle kodlanır. Kaynaklar: [Node Argon2 API](https://nodejs.org/docs/latest-v24.x/api/crypto.html#cryptoargon2algorithm-parameters-callback), [RFC 9106 §4](https://www.rfc-editor.org/rfc/rfc9106.html#section-4), [PHC Strings](https://c2sp.org/phc-strings). 22 Ekim 2026'da kontrol edildi. RFC'nin bellek kısıtlı ikinci profili seçildi; bu her sunucu için ölçülmüş ideal maliyet iddiası değildir.

Doğrulama yalnız iki açık profili kabul eder: güncel 65536/3/4 ve geçiş için 19456/2/1; her ikisi v=19, 16 bayt salt ve 32 bayt digest olmalıdır. İkinci profil `passwordHashNeedsRehash` için true verir. Yeni hash üretimi hep güncel profildedir; kullanıcı/DB parametrelerinden keyfi iş faktörü yüklenmez. Başka geçerli Argon2 profilleri bu alpha tarafından desteklenmeyebilir; otomatik bir genel amaçlı PHC parser değildir. 19456/2/1, [OWASP Argon2id rehberindeki](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id) uyum/geçiş profillerinden seçildi.

Pepper ve Argon2 associatedData kullanılmaz; kayıt standard unkeyed Argon2id hesaplamasıyla bağımsız Noble uygulamasında çapraz kontrol edilir. Özel anahtar kasasının domain bağlamı bu hesaplamaya taşınmaz. Pepper gerektiren kurulumlar için API/rotasyon sözleşmesi henüz yoktur; bir pepper'lı kaydı normal kayıt gibi doğrulamaya çalışmayın.

Girdiler yalnız non-shared Uint8Array/Buffer, 1–1024 bayttır. Minimum 1 bayt kütüphane biçim sınırıdır, kabul edilebilir hesap parolası politikası değildir. Uygulama uzunluk, ele geçirilmiş parola listesi ve kullanıcı akışını ayrıca belirler. Parola kesilmez, trim/Unicode normalizasyonu yapılmaz; UTF-8 kodlama uygulamada açıkça seçilmelidir.

## Hata, iptal ve kaynak yönetimi

Doğru biçimli kayıtta yanlış parola `false` verir; desteklenmeyen/bozuk kayıt `INVALID_PASSWORD_HASH` ile **KDF başlamadan** reddedilir. Kayıt uzunluğu, sürüm, parametre sırası, profil, salt/digest ve kanonik base64 kontrol edilir. Aşırı uzun girdi veya yanlış tür `INVALID_INPUT` verir. Karşılaştırma eşit uzunluklu 32 bayt digest'lerde `timingSafeEqual` kullanır; bütün endpoint'in eşit süreli olduğu iddia edilmez.

Kasa seal/open ve hesap hash/verify **aynı modül örneğinin 2 aktif + 16 FIFO bekleyen Argon2 bütçesini paylaşır**. Dolu kuyruk RESOURCE_LIMIT verir. Girdiler async beklemeden önce kopyalanır; owned parola/digest tamponları normal hata/başarı/iptal yollarında temizlenir. Bekleyen iptal sıradan çıkarır; aktif native Argon2 zorla durmaz, callback beklenir ve iptal edilmiş türetme sonucu verilmez. Native hatalar ile runtime/GC tüm kopyaların fiziksel temizlendiği garantisini vermez.

Uygulama rate limit, tenant kotası, toplam worker/süreç bütçesi, istek boyutu ve eşzamanlı DB güncellemelerini yönetmelidir. Hesap yokluğu veya bozuk DB kaydı için erken dönüş kullanıcı varlığını sızdırabilir; HTTP katmanı genel hata mesajları ve uygun dummy doğrulama akışını ayrıca tasarlamalıdır. Bu SDK MFA, oturum, parola sıfırlama, account lockout veya transport sağlamaz.

## Test kanıtı

İki profilde bağımsız Noble Argon2id karşılaştırması; doğru/yanlış parola; salt yeniliği; bozuk PHC/sınırsız iş faktörü/kanonik olmayan base64/newline reddi; girdi snapshot'ları; shared memory/uzunluk sınırları; tipler; iki API ailesinin ortak slot bütçesi; aktif/queued abort; native hatadan sonra slot ve tampon temizliği sınanır. Gerçek kayıt/parola fixture olarak commit edilmez; test verileri sentetiktir.
