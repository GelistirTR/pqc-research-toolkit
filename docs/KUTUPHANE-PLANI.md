# Kütüphane tasarımı ve araştırma programı

> Bu tablo ilk araştırma aşamasındaki planı kaydeder. İlk alpha çekirdeği sonradan uygulandı; güncel kapsam ve tamamlanan kontroller [README](../README.md) ve [doğrulama raporundadır](DOGRULAMA.md). Buradaki bütün uzun vadeli kabul ölçütlerinin tamamlandığı iddia edilmez.

**Tarih:** 21 Ekim 2026  
**Durum:** Uygulanacak çalışmanın önerisi; aşağıdaki deney ve kontroller henüz yürütülmedi.  
**Dayanak:** [Araştırma raporu](ARASTIRMA.md) ve [kaynak dizini](KAYNAKLAR.md).

## 1. İlk sürümün sınırı

Genel amaçlı kütüphane, her kriptografi dalını ilk sürümde uygulamak anlamına gelmemeli. Önerilen çekirdek:

| İş | Aday | İlk teslimat |
|---|---|---|
| Ortak sır kurma | ML-KEM-1024 | Standart dış API'ye uygun, tipleri ayrılmış arayüz |
| Anahtar türetme | HKDF-SHA-512 | Amaç/bağlam ayrımı, sınırları açık çıktı üretimi |
| Simetrik koruma | AES-256-GCM | Anahtar ve nonce yaşam döngüsünü yöneten arayüz |
| Dijital imza | ML-DSA-87 | Mesaj/bağlam sınırları tanımlı imzalama ve doğrulama |
| Hash tabanlı imza | SLH-DSA | İkinci aşama; özellikle seyrek imzalama ölçümleri |
| Parola ile anahtar koruma | Argon2id | İhtiyaç doğrulanırsa, cihazda kalibre edilmiş kaynak sınırları |
| Yeni hibrit KEM | Literatürden seçilecek | Ayrı deneysel modül; yapı seçimi henüz açık |

Bu tablo yeni bir protokolün normatif algoritma listesi değildir. Standartların algoritma ayrıntıları değiştirilmemeli. Geliştirme dili ve sağlayıcı seçimi henüz yapılmadı.

İlk kapsam dışında tutulması önerilen işler: blokzincir/konsensüs, homomorfik şifreleme, anonim ağ, QKD donanımı, eşik imzaları ve tam mesajlaşma protokolü. Bunlar ayrı gereksinimler ve güvenlik analizleri ister.

## 2. Güvenlik sözleşmesi

Aşağıdakiler projenin önerilen gereksinimleridir; elde edilmiş garantiler değildir.

### Saldırgan modeli

- Ağdaki ve saklanan veriyi görebilen, değiştirebilen, silebilen veya tekrar gönderebilen saldırgan.
- Seçilmiş ciphertext'ler gönderebilen, hata mesajlarını ve süreleri gözleyen saldırgan.
- Bugünün kayıtlarını gelecekte güçlü kuantum hesaplamayla inceleyen saldırgan.
- Birçok kullanıcı ve anahtara eşzamanlı saldıran saldırgan.
- Ayrı değerlendirme olarak: aynı cihazda çalışan süreç, fiziksel güç/EM gözlemi ve hata enjeksiyonu.

Teorik analiz, saldırganın hangi oracle'lara klasik veya kuantum erişimi olduğunu belirtmeli. Ağ API'sine klasik istek gönderebilmek ile bütün şifre çözme işlemini kuantum süperpozisyonda sorgulayabilmek aynı varsayım değildir.

Çalışan uç cihazın bütünüyle ele geçirilmesi, ekranda açık plaintext veya saldırganın anahtarı doğrudan okuyabilmesi, salt bir şifreleme kütüphanesiyle çözülemez. Hangi donanım/OS korumasına güvenildiği yazılmalı.

### Ayrı ayrı değerlendirilecek özellikler

| Özellik | Hedef / açık sınır |
|---|---|
| KEM gizliliği | Somut standart ve sağlayıcı için seçilmiş ciphertext saldırılarına karşı güvenlik argümanı |
| İmza sahteciliği | Seçilmiş mesaj saldırıları altında sahtecilik modeli; anahtar kimliğinin güvenilir bağlanması |
| Veri gizliliği ve bütünlüğü | Seçilen AEAD'nin kullanım sınırları içinde |
| Replay | Durumsuz primitive API sağlamaz; üst katmanın sorumluluğu açık olmalı |
| Forward secrecy | Statik alıcı KEM anahtarıyla otomatik sağlanmaz; ayrıca oturum tasarımı gerekir |
| Ele geçirme sonrası toparlanma | Ayrı ratchet/protokol gerektirir; ilk çekirdek bunu vaat etmez |
| Metadata gizliliği | Boyut, zaman ve alıcı bilgisi için ayrıca tasarım gerekir |
| Key commitment | AEAD adından çıkarılamaz; kullanım alanında gerekip gerekmediği araştırılmalı |
| Yan kanal direnci | Sağlayıcı, CPU, derleyici ve kapsam belirtilerek kanıt/ölçüm raporu |

Bu sınırların önemli örnekleri [RFC 9180 §9](https://www.rfc-editor.org/rfc/rfc9180.html) içinde de görülür. Tablo kütüphanemiz için önerilen sözleşmedir.

### İddia başına kanıt kaydı

Her güvenlik iddiası için şu alanlar zorunlu olmalı:

```text
İddia / API / profil sürümü
Saldırganın erişimi ve sorgu bütçesi
Matematiksel varsayım, hash modeli ve kaynak teorem
Anahtar başına veri, mesaj ve doğrulama-denemesi sınırları
Çok kullanıcı / çok hedef etkisi
Çözme hatasının, nonce çakışmasının ve sahteciliğin ayrı katkıları
Sağlayıcı commit'i, derleyici ve hedef mimari
İddianın dışında kalan sızıntılar
İnceleyen kişi / rapor / tarih / yeniden inceleme tetikleyicisi
```

Bir teoremdeki somut avantaj sınırı yerine kaynaksız “en az 2^256 işlem gerekir” yazılmamalı. Kategori hedefi, kullanılan model ve bütün sistemin sınırları ayrı kaydedilmeli.

## 3. API ve veri biçimi kuralları

1. İmza anahtarı, KEM anahtarı, AEAD anahtarı ve ortak sır farklı türler olmalı. Key kullanımının anlamı ham bayt dizisinden çıkarılmamalı.
2. Varsayılan API işletim sistemi destekli kriptografik rastgelelik kullanmalı; RNG hatasında işlem başarısız olmalı. Test seed'i arayüzü test alanıyla sınırlanmalı.
3. Parametreleri kullanıcıya keyfî modül, eğri veya hata dağılımı olarak açmamalıyız. Desteklenen profiller açık ve sınırlı olmalı.
4. Nonce üretimi ve anahtar başına limitler tasarımın içinde olmalı. Süreç kopyalama, eşzamanlılık, çökme ve snapshot geri yükleme senaryoları ele alınmalı.
5. Şifreli kapsayıcı tasarlanırsa sürüm, profil, kritik başlıklar ve uygulama bağlamı kimlik doğrulanan veriye bağlanmalı. Kanonik kodlama, alan sırası ve uzunluklar kesin tanımlanmalı.
6. Bilinmeyen kritik alan/profil açık hata üretmeli. Başarısız kuantum sonrası işlemden sessizce klasik profile geçilmemeli.
7. KEM'in gizli implicit-rejection sonucunu dışarı bildirmemeliyiz. Açık biçim hatalarıyla gizli doğrulama davranışı standartla uyumlu ayrılmalı.
8. AEAD doğrulama tamamlanmadan plaintext dışarı çıkmamalı. Akış API'sinde her doğrulanan parçanın anlamı ve son-parça garantisi ayrıca tanımlanmalı.
9. Hassas anahtarların log, Debug, serileştirme veya istemsiz kopyalama yoluyla çıkışı engellenmeli. Bellek temizliği desteklenen ortamın sınırlarıyla belgelenmeli; OS yedeği veya eski snapshot'taki kopyaların silindiği vaat edilmemeli.
10. Güvenilir alıcı anahtarıyla şifreleme ve gönderici kimliği doğrulanan şifreleme ayrı API sözleşmeleri olmalı. Bir KEM veya AEAD çağrısının göndericiyi tanıttığı izlenimi verilmemeli.

Yüksek seviyeli `seal/open` işlevlerinin adı ve wire formatı henüz sabitlenmemeli. Önce KEM/KDF/AEAD birleşiminin seçimi, kimlik modeli ve güvenlik analizi tamamlanmalı. Taslak pseudocode'un yanlışlıkla üretim protokolüne dönüşmesini önlemek için bu belgede uygulanabilir yeni bir birleşim tarifi bulunmuyor.

## 4. Araştırma deneyleri

### A. Parametre ve saldırı maliyeti incelemesi

ML-KEM-768/1024 için yayımlanan parametreleri değiştirmeden, en iyi bilinen saldırı modellerini karşılaştıran tekrar üretilebilir bir notebook hazırlanmalı. Lattice Estimator kullanılırsa commit, Sage/runtime, tüm girdiler, klasik/kuantum maliyet modeli ve bellek/depth varsayımları kaydedilmeli. Eski Kyber tanımının güncel ML-KEM parametrelerini ne kadar temsil ettiği ayrıca açıklanmalı. Yalnızca varsayılan `rough` çıktısı güvenlik kararı için yeterli sayılmamalı. [Araç belgeleri](https://github.com/malb/lattice-estimator)

**Beklenen çıktı:** Model duyarlılığı tablosu, saldırı ailesi listesi ve sonuçların sınırlılıkları. Bu deney bu turda çalıştırılmadı.

### B. Birleştirici incelemesi

Genel amaçlı bir klasik+PQC veya PQC+PQC KEM seçilmeden önce kaynak yapı ve teorem eşleştirmesi çıkarılmalı. Sorgu modeli, bileşen bozulma senaryosu, ciphertext/açık anahtar bağlama, domain separation ve kodlama varsayımları belgelenmeli. TLS için analiz edilmiş yapı, genel KEM'in yerine kanıtsız geçirilmemeli.

**Beklenen çıktı:** Seçilmiş bir yapının sürümü ve güvenlik argümanı veya neden uygun bulunmadığını açıklayan rapor. Henüz seçilmiş yeni combiner yok.

### C. Sağlayıcı karşılaştırması

En az iki bağımsız uygulamayla aynı standart sürümünde çapraz test yapılmalı. Her sağlayıcı için lisans, güvenlik duyuruları, bakım, kanıt kapsamı ve desteklenen mimariler kaydedilmeli. İki wrapper'ın altta aynı uygulamayı kullanması bağımsız doğrulama diye sayılmamalı.

**Beklenen çıktı:** Sürümü sabitlenmiş sağlayıcı karar kaydı. mlkem-native incelenecek adaylardan biridir; liboqs prototip/karşılaştırma rolünde değerlendirilebilir. [mlkem-native kapsamı](https://github.com/pq-code-package/mlkem-native/blob/main/SOUNDNESS.md), [liboqs kendi kullanım uyarısı](https://github.com/open-quantum-safe/liboqs)

### D. Hedef cihaz ölçümleri

Windows x86-64 ve Linux x86-64 ile başlayıp Android ARM64/iOS ARM64 gereksinimleri netleşince ölçümler genişletilmeli. KeyGen, Encaps, Decaps, Sign ve Verify ayrı ölçülmeli. Soğuk/sıcak çalışma, medyan/p95/p99, bellek, anahtar/imza boyutu ve eşzamanlılık raporlanmalı. Henüz ölçülmemiş platforma destek veya performans garantisi yazılmamalı.

### E. Yan kanal ve durum incelemesi

Hedef CPU/derleyicide zamanlama dağılımları incelenmeli; assembly ve sağlayıcı kanıtlarının kapsamı kontrol edilmeli. Geçersiz ciphertext, RNG arızası, anahtar yükleme, VM snapshot ve süreç kopyalama senaryoları denenmeli. İstatistiksel testte bulgu çıkmaması sızıntı yokluğunun kanıtı değildir. Fiziksel güç/EM/fault incelemeleri ayrı uzmanlık işi olarak kayda geçmeli.

## 5. Yayın öncesi kabul ölçütleri

| Alan | Gerekli kanıt |
|---|---|
| Standarda uygunluk | Sabitlenmiş resmi test vektörü korpusundaki uygulanabilir vakaların tamamı geçer; kaynak ve sürüm kayıtlı |
| Birlikte çalışabilirlik | Bağımsız sağlayıcılar arasında anahtar/işlem uyumluluğu |
| Bozuk girdiler | Kesilmiş, uzatılmış, değiştirilmiş ve sınır dışı girdilerde belgeli hata davranışı |
| Simetrik koruma | Yanlış key/nonce/AAD/tag ve ciphertext değişiminde doğrulamasız plaintext çıkışı yok |
| Durum yönetimi | Eşzamanlılık, çökme, fork/snapshot ve limit aşımı senaryolarının sonucu açıklanmış |
| Fuzzing | Test bütçesi, seed/korpus, hedefler ve rapor kaydedilmiş; bütçe içinde açık çökme/bellek hatası yok |
| Sırlar | Log/kopya/export incelemesi; desteklenen platformda temizleme davranışı belgeli |
| Yan kanallar | Hedef platform, yöntem, kanıt/ölçüm kapsamı ve açık kalan sınırlamalar yazılı |
| Güvenlik analizi | Her genel API için iddia–varsayım–kanıt tablosu |
| Dış inceleme | Kriptografik tasarım ve uygulama için bağımsız rapor; kritik/yüksek bulgular kapatılmış ve doğrulanmış |
| Dağıtım | Sabit bağımlılıklar, SBOM, yayın bütünlüğü, güvenlik bildirim yöntemi |
| Lisans | Ticari kullanım sınırı ve üçüncü taraf koşulları belirlenmiş |

Resmi vektör kaynağı [NIST ACVP sunucusunun vektör dizinidir](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files). Uygulamada seçilmiş örnekler `975de31eb83d87039ec88934fdc47d8c312b892d` commit'ine sabitlendi; kullanılan alt küme ve sınırlar [doğrulama raporunda](DOGRULAMA.md) kayıtlıdır. Tam ACVP korpusu yürütülmedi. Vektörleri geçmek FIPS modül sertifikası veya bütün güvenliğin ispatı değildir.

## 6. Özgün matematik için araştırma kapısı

Yeni bir algoritma fikrini değerlendirmeye almak için şu teslimatlar istenmeli:

1. Problemin kesin tanımı; KeyGen/Encaps/Decaps veya Sign/Verify algoritmaları.
2. Doğruluk argümanı, hata olasılığı ve bütün parametreler.
3. IND-CCA / imza sahteciliği gibi hedef oyunların kesin tanımı.
4. Dayanılan varsayım ve indirgeme; idealize model veya sezgisel adımların açık işaretlenmesi.
5. Klasik ve kuantum saldırı ailesi taraması; maliyet ve bellek/depth değerlendirmesi.
6. Örnekleme, yan kanal, bozuk girdiler ve hata davranışı analizi.
7. Bağımsız yeniden uygulama ve kamuya açık inceleme çağrısı.

Rastgele görünen çıktı, avalanche deneyi veya istatistiksel rastgelelik testini geçmek tek başına güvenli şifreleme kanıtı değildir. Yeni modül/q/hata dağılımı seçip anahtarı büyütmek de bu teslimatların yerine geçmez.

## 7. Çalışma sırası

| Aşama | Somut sonuç | Şu an |
|---|---|---|
| 0 | İlk literatür taraması, adaylar, belirsizlikler | Bu belge paketiyle tamamlandı; alanın kapsamlı kriptanalizi sürer |
| 1 | API güvenlik sözleşmesi, profil gereksinimleri, lisans politikası | Deneysel sözleşme CORE-SPEC.md, güvenlik sınırları SECURITY.md ve ticari olmayan lisans mevcut; bağımsız inceleme bekleniyor |
| 2 | Sağlayıcı ve hedef platform kararı, referans çekirdek | Node 24.22.1/OpenSSL 3.5.9 çekirdeği ve yerelde doğrulanan Windows x64 portable hazır; diğer platformlar uzakta test edilmedi |
| 3 | Vektör, birlikte çalışabilirlik, fuzzing ve cihaz deneyleri | Sabit NIST/RFC örnekleri, Noble çapraz kontrolleri ve sınırlı mutasyon korpusu mevcut; geniş fuzzing, yan kanal ve hedef cihaz deneyleri açık |
| 4 | Yüksek seviye format/protokol seçimi ve güvenlik analizi | Deneysel v1 dosya/kasa biçimleri, CLI ve typed SDK mevcut; bağımsız bileşim analizi ve ağ protokolü yok |
| 5 | Bağımsız inceleme ve düzeltmeler | Başlanmadı |
| 6 | Lisanslı GitHub yayını ve sürüm politikası | Kullanıcı yayın talimatı verdi; kaynak incelemesi ve uzak commit/ağaç doğrulamasıyla takip ediliyor |

Araştırma kodu daha erken kamuya açılabilir; inceleme durumu ve deneysel niteliği açıkça yazılmalı. Üretime uygunluk iddiası ayrı bir eşik olmalı. Takvim, ekip ve denetim kaynakları bilinmeden tamamlanma tarihi verilmemeli.

### Alpha.10 sonrasında öncelik

Yerel kullanımda anahtar oluşturma, dosya şifreleme/çözme, imza, parola değiştirme, tanılama ve parola gerektirmeyen başlık inceleme akışları mevcut. `inspect`, yalnız doğrulanmamış başlık iddialarını gösterir; anahtar güvenini veya dosya bütünlüğünü kurmaz. Güncel uygulama kapsamı [çekirdek sözleşmesinde](CORE-SPEC.md), gerçekte koşulan kontroller [doğrulama raporunda](DOGRULAMA.md) tutulur.

Ürün yönü kullanıcının son talimatıyla **uygulamalara gömülebilen geliştirici SDK'sıdır**; masaüstü arayüz hedef değildir. CLI geliştirme/tanılama yardımcısıdır. Alpha.11 çalışması seçilen 1. güvenlik açık işleri ve 4. kaynak/arıza dayanıklılığı aşamalarına odaklanır: katı eski kasa politikası, sağlayıcı/RNG arızaları, isteğe bağlı işlem havuzu, gerçek süreç kapanması ve sentetik büyük dosya ölçümleri. Tamamlanan kanıt ve açık sınırlar [güvenlik raporunda](SECURITY-REVIEW-ALPHA11.md) ve [kaynak raporunda](KAYNAK-DAYANIKLILIK.md) tutulur.

Alpha.12 ayrı hesap parolası hash/doğrulama API'sini ekler; geri açılabilir uygulama sırrı yönetimi ve tam mesaj koruma protokolü ayrı gereksinimler taşır. Özel anahtar kasası hesap parolası API'si olarak sunulmaz; KEM+AEAD primitive'i tek başına güvenli sohbet protokolü sayılmaz. Kapılar [geliştirici sözleşmesinde](GELISTIRICI-SDK.md) ve [mesajlaşma tasarımında](MESSAGING-DESIGN.md) tanımlıdır. Bağımsız inceleme, gerçek diğer platformlar ve yan kanal deneyleri açık kalır. Kullanıcı GitHub yayınına artık açıkça talimat verdi; yayın durumu uzak commit doğrulanmadan tamamlandı sayılmaz. Gece otomasyonu duraklatılmıştır.
