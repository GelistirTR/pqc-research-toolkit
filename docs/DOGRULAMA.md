# Uygulama doğrulaması — 0.3.0-alpha.12

**Tarih:** 22 Ekim 2026 · **Ortam:** Windows x64, Node 24.22.1, OpenSSL 3.5.9  
**Durum:** Yerel test; bağımsız güvenlik denetimi veya FIPS/ACVP sertifikasyonu değil.

## Sonuçlar

- `npm run test:coverage`: **219/219 geçti**; iptal edilen, atlanan veya başarısız vaka yok. Alpha.12 ölçümünde toplam satır kapsamı %99,14, branch kapsamı %93,42, işlev kapsamı %99,29. Yeni password modülünde satır/branch/işlev %100. Bu C# launcher veya PowerShell araçlarının kapsam oranı değildir; yüzdeler güvenlik kanıtı değildir.
- `npm run test:package`: tarball oluşturuldu, yalnız izin verilen runtime/belge dosyalarını içerdiği kontrol edildi, ayrı geçici klasöre kuruldu; kurulan kopyada hesap hash/doğru-yanlış parola/rehash API'si, doctor, SDK parmak izi, operation pool run/close, başlık incelemesi, gerçek dosya encrypt/decrypt ve parola değişimi geçti. npm registry yayını yapılmadı.
- En son `npm run fuzz:formats` çalışması alpha.12 üzerinde, ortak Argon2 bütçesine geçiş nedeniyle yeniden yapıldı: **14.247** bozuk dosya/kasa girdisi reddedildi; [makine tarafından üretilen yerel rapor](validation-format-corpus.json). Yapısal geçersiz girdiler için Argon2 ve ML-KEM decapsulation sayaçları sıfır kaldı. Bu korpus PHC fuzzing kampanyası değildir; hesap parola parser'ının adversarial vakaları ayrı test edilir.
- `npm run typecheck`: Geçti; yanlış anahtar türlerini ve context'in atlanmasını reddeden derleme vakaları dahil.
- `npm run check`: JavaScript sözdizimi kontrolü.
- `npm run demo`: ML-KEM/KDF/AES-GCM roundtrip ve ayrı ML-DSA imzası çalıştı.
- `npm run demo:files`: Parolalı kasa diske yazılıp açıldı, private key geri yüklendi; 3 MiB+17 baytlık dosya 4 parçada şifrelenip çözüldü.
- Önceki 0.1 çekirdeğin 30 örnekli performans ölçümleri [JSON raporunda](benchmark-windows-x64.json). Bu eski rapor yeni dosya/kasa performansı gibi yorumlanmamalı.

## Windows portable doğrulaması

Bu bölüm alpha.10'un önceki yardımcı CLI paketini anlatır; alpha.11/12 SDK değişiklikleri için yeni Windows portable paket derlenmedi. Mevcut alpha.10 arşivi katı legacy politikasını, havuzu veya hesap parola API'sini içermez. Güncel SDK teslimatları kaynak ZIP ve npm tarball'dır; bunlar registry'ye yüklenmedi.

Alpha.4'te eklenen `npm run build:windows-portable`, kaynağı/lisansı sabitlenmiş Node binary'sinin resmî HTTPS özetini ve OpenJS Authenticode durumunu denetler, arşivi oluşturur ve final konumuna almadan ayrı klasörde `test-windows-portable.mjs` ile doğrular. Alpha.10'da on kontrol grubu: bütün dosya özetleri/lisans; doctor; doğrulanmamış dosya/kasa başlığı incelemesi; çok parçalı dosya roundtrip; parola değişimi; imza roundtrip; argv iletimi; devralınmış preload/provider ortamının dışlanması; bozuk runtime reddi; çıkış kodu iletimi. Bunlar Node testlerine eklenmiş bir test toplamı olarak sunulmuyor.

Alpha.4'te önceki runtime ile gerçek ConPTY oturumunda gizli Türkçe parola/onay ile keygen başarıyla tamamlandı. Başka bir keygen girişinde Ctrl+C çıkış kodu 130 ve `ABORTED` üretti, hedefler oluşmadı ve parola terminal çıktısında görünmedi. Launcher imzasızdır; Node binary'sinin imzası bütün projeyi sertifikalandırmaz. Derleme raporu `.artifacts/portable-verification-<version>-<tree>.json`, ayrıntılar [PORTABLE-WINDOWS](PORTABLE-WINDOWS.md) içindedir. Diğer makineler veya bütün Windows terminal ürünleri sınanmadı.

## Sabit test verileri

Alpha.12: beş hesap parola testi; bağımsız Noble ile iki Argon2id profilinde karşılaştırma, salt yeniliği, doğru/yanlış parola, bozuk PHC/sınırsız maliyet/kanonik base64/newline, input snapshot/uzunluk/shared memory ve pre-abort. Üç ortak bütçe testi; kasa+hesap toplam sınırı, kuyruk/aktif iptal, wipe ve yanlış native çıktı sonrası iyileşme. Provider fault korpusuna üç hesap parola RNG/hash/verify hatası eklendi. Toplam 11 yeni test, önceki 208'den 219'a yükseldi. Alt süreçte kurulan paketin hesap API export'ları ayrıca sınanır.

Alpha.11 özel kontrolleri: iki yeni gerçek şifreli legacy geçiş/reseal testi, 13 provider/RNG fault vakası, 8 operation pool testi ve 5 dosya arıza/entegrasyon/crash testi. Bu 28 yeni testle önceki 180 toplamı 208 oldu. Bazı mevcut DER testleri de katı policy için güncellendi. Havuzun iptal sırasında cleanup hatasını maskelemesi red-before/green-after regresyonuyla giderildi. Gerçek eski Node 24.16.0 / alpha.7 fixture'larında yeni varsayılan ret, açık geçişte eski okuyucunun pin'iyle eşleşme, dosya/imza işlemi ve strict reseal kontrolü ayrıca geçti: [tarihli politika raporu](validation-legacy-policy-alpha11.json). Bu ek deney normal test sayısına katılmaz. [Yerel güvenlik incelemesi](SECURITY-REVIEW-ALPHA11.md) ve [SDK sözleşmesi](GELISTIRICI-SDK.md) sınırları açıklar.

NIST ACVP kaynağı: `usnistgov/ACVP-Server`, commit `975de31eb83d87039ec88934fdc47d8c312b892d`.

- `ML-KEM-encapDecap-FIPS203`, grup 6, ML-KEM-1024 decapsulation: 10 vaka. Native sonuç yayımlanan beklenen ortak sırla karşılaştırılır; wrapper'ın KDF/decryption yolu da denenir. Bazı vakalar değiştirilmiş ciphertext için implicit rejection çıktısını sınar.
- `ML-DSA-sigVer-FIPS204`, grup 5, ML-DSA-87 external/pure: 15 vaka. Geçerli ve geçersiz imzalar, yayımlanan `testPassed` değeriyle karşılaştırılır.
- [NIST GCM örnekleri](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf): GCM-AES256 örnek 1 ve 2 için boş/dört bloklu plaintext doğrulaması.

Seçilen ACVP gruplarının bütün vakaları saklanır; **bütün ACVP algoritma/mod/grupları test edilmez**. KeyGen, deterministik encapsulation ve signature-generation ACVP grupları bu ilk korpusta yoktur. Ağ testi sırasında kullanılmaz. Kaynak URL ve SHA-256 özetleri [fixture dosyasında](../test/fixtures/nist-acvp.json); tekrar üretim aracı [scripts/refresh-nist-fixtures.mjs](../scripts/refresh-nist-fixtures.mjs) içindedir. Bunlar kamuya açık test anahtarlarıdır.

## Bağımsız uygulama karşılaştırması

Runtime sağlayıcısı OpenSSL; test karşılaştırıcısı `@noble/post-quantum` 0.7.1:

1. OpenSSL encapsulation → Noble decapsulation.
2. Noble encapsulation → OpenSSL decapsulation.
3. OpenSSL ML-DSA imza → Noble verify.
4. Noble ML-DSA imza → OpenSSL verify.

HKDF-SHA-512 çıktısı, aynı belgeli info/salt üzerinde `@noble/hashes` 2.4.0 ile karşılaştırılır. Aynı implementasyonu iki wrapper ile çağırmakla sınırlı bir karşılaştırma değildir. Test bağımlılıklarının kendi güvenlik/denetim durumu bu kütüphaneye bağımsız güvenlik onayı vermez.

0.2 uzantıları: Dosya biçimi ayrı bir okuyucuyla, Noble ML-KEM/HKDF kullanılarak çözüldü; AES-GCM yine native sağlayıcıdır. Argon2id sağlayıcısı [RFC 9106 §5.3](https://www.rfc-editor.org/rfc/rfc9106.html#section-5.3) sabit vektörüyle karşılaştırıldı. Noble Argon2id ayrıca gerçek 64 MiB / 3 geçiş / 4 lane profiliyle anahtar türetip kasayı açtı.

## Olumsuz ve durum testleri

0.3 CLI testleri gerçek keygen, çok parçalı dosya roundtrip, detached imza ve bağımsız kütüphane doğrulamasını çalıştırır. Zorunlu tam parmak izi, yanlış context/AAD/parola, seçenek sınırları, çıktı üzerine yazmama ve 16 MiB imza sınırı sınanır. Gizli terminal girdisinin UTF-8/backspace, Ctrl+C, stream hatası/sonu ve uzunluk sınırlarında terminal durumunu geri yüklemesi de test edilir. Bu terminal vakaları sahte TTY stream'leri kullanır; bütün terminal emülatörleri için fiziksel UI testi değildir.

Beş sıkılaştırma regresyonu authenticated PKCS#8 sonuna eklenmiş baytları, async context/AAD snapshot'larını, disk dolması sonrası staging temizliğini ve kasa açılırken handle yaşam döngüsünü kapsar.

0.3 alpha.2 ekleri: doctor gerçek native işlemleri çalıştırır; başarısız sağlayıcı durumunda başarı yazmadığı ve iç hata ayrıntılarını sızdırmadığı sınanır. Launcher'ın desteklenmeyen sürüm hatası, test sürecindeki sürüm alanı değiştirilerek kontrol edilir; bu vaka eski bir Node binary'sinin çalıştırıldığı anlamına gelmez. Paket smoke testi kullanıcıdan gerçek veri veya anahtar almaz; tüm geçici çıktılar doğrulanmış test klasöründe temizlenir.

0.3 alpha.3 ekleri: KEM ve imza kasası yeni parolayla kapatılıp gerçek çözme/imza işleminde kullanılır, eski kimlik/parmak izi ve orijinal dosya korunur. Yanlış güncel parola, kısa yeni parola, eksik otomasyon parolası, mevcut hedef ve aynı girdi/çıktı reddedilir. Sahte TTY ile güncel/yeni/onay istemleri, onay uyuşmazlığı ve Ctrl+C sınanır. Terminal setup/cleanup metotlarının eşzamanlı hata fırlatması halinde Promise'in hata ile sonlanması ve dinleyicilerin kaldırılması kontrol edilir; bozuk bir terminalin her durumda geri yüklenebildiği iddia edilmez.

0.3 alpha.5 ekleri: `vault-concurrency.test.js` ayrı test sürecinde native Argon2 girişini modül yüklenmeden sarar. Dört test; 2 aktif + 16 FIFO bekleyen sınırını, taşmada native çağrı yapılmamasını, yapısal hata önceliğini, seal/open ortak kapasitesini, kuyruktaki girdi snapshot'ını, tampon temizliğini ve callback/eşzamanlı sağlayıcı hatasından sonra slotların kullanılabilmesini sınar. Gerçek native bölümde dört seal ve dört open çağrısı aynı anahtar kimliğini geri verir; ölçülen en yüksek başlatılmış native istek sayısı 2'dir. Bu bir RAM/CPU yük ölçümü, worker'lar arası sınır veya servis DoS deneyi değildir. CLI sürümü paket metadata'sıyla karşılaştırılır.

0.3 alpha.6 ekleri: Altı kasa iptal regresyonu önceden iptal/bozuk signal, dolu kuyruktan iptal ve kapasiteyi yeniden kullanma, FIFO sırasının korunması, aktif native callback öncesinde Promise/rezervasyonun tutulması, slot aktarımı ile native dispatch arasındaki iptal, native hata ile iptal önceliği ve stopImmediatePropagation durumunu kapsar. Dinleyici sayıları iptal/handoff sonrası sıfırlanır; aktif işlem girdisinin callback öncesinde sıfırlanmadığı, callback sonrası sahip olunan tamponların temizlendiği kontrol edilir. İki ayrı CLI alt sürecinde doctor'ın ilk/ikinci kasa KDF çağrısında programatik SIGINT olayı üretilir: çıkış 130/ABORTED, başarı çıktısı yok, iptal sonrası ek KDF yok. Bunlar yeni fiziksel terminal/klavye testleri değildir.

0.3 alpha.7 ekleri: Dört staging regresyonu close hatasından sonra silme denemelerini, unlink hatasından sonra rmdir denemesini ve iki alttaki hatanın korunmasını, yayın sonrası temizlik hatasında hedefin korunmasını, ayrıca geç final-tag doğrulama hatasıyla close hatası birlikte oluştuğunda geçici plaintext'in kaldırılmasını sınar. Close enjeksiyonu gerçek close tamamlandıktan sonra hata fırlatır; her OS close arızasında dosyanın kaldırılabileceği iddia edilmez. Ayrı CLI alt sürecinde unlink hata ayrıntısı enjekte edilir: CLEANUP_FAILED sabit mesajı, boş başarı çıktısı, hata ayrıntılarının gizlenmesi ve daha önce yayımlanan anahtar çiftinin korunması kontrol edilir.

0.3 alpha.8 ekleri: On DER codec testi seed-only, expanded-only ve eski seed+expanded temsilleri, bağımsız Noble'dan türetilen public key ile eşitlik, kesilme/ek bayt/unknown alan/minimal olmayan DER uzunluğu ve otoritatif seed politikasını kapsar; seed'i olmayan anahtar da gerçek şifreli kasaya kapatılıp açıldıktan sonra KEM veya imza işleminde kullanılır. CLI ve kütüphane için güvenlik sürümü alt sınırı kontrol edilir. Sürüm ret testleri gerçek eski Node binary'lerini değil, alt süreçte değiştirilen version alanını kullanır. Ayrı [runtime geçiş raporu](validation-runtime-upgrade.json) ise gerçek 24.16.0/3.5.6 ve 24.22.1/3.5.9 süreçlerini kullanır: eski kasa/dosya/imza yeni okuyucuda, yeni dosya/imza mevcut eski kasayı kullanan eski okuyucuda geçti. Yeni seed-only kasanın eski alpha.7 okuyucuda reddedildiği de kaydedilir; bütün yönler için kasa uyumu iddiası yoktur.

0.3 alpha.9 ekleri: Altı SDK fingerprint testi mevcut public NIST ACVP ML-DSA tcId61 anahtarının tam DER SPKI özetini sabit .NET/Get-FileHash sonucuyla karşılaştırır; KEM/imza handle'larında export/import kararlılığı, hex case normalizasyonu, yanlış pin, boşluk/newline/kısaltma ve private/simetrik/duck-typed handle reddini kapsar. CLI satır sonlu pin için çıktı oluşturmadan INVALID_FINGERPRINT üretir; kurulan paketin gerçek SDK export'ları da sınanır. Türkçe parola onayı dahil tüm etkileşimli regresyonlar geçti. Primitive/wire kodu değişmediğinden alpha.8 malformed korpusu sebepsiz tekrarlanmadı.

0.3 alpha.10 ekleri: Sekiz SDK inceleme testi ve bir CLI alt testi eklendi. Sentetik geçersiz tag'li dosya/kasaların başlık iddiası olarak okunabilmesi ve gerçek dosyada değişmiş son tag'in yalnız incelemeyle bulunamaması açıkça sınanır. Sürüm/profil, reserved alanlar, uzunluk, parça ve 64 GiB sınırı; iki kasa türü; hatalı girdi/iptal; kaynak değişimi ve okuma hatasında handle kapanışı kontrol edilir. Alt süreçte native Argon2/decapsulation/private-key import işlevleri hata verecek biçimde sarılıyken inceleme geçer; sarılan read işlevi dosyada 1.664 ve kasada 64 bayt okunduğunu, ciphertext gövdesine erişilmediğini ölçer. Bu kontrollü hata enjeksiyonu kaynak dosya sahipliği veya bütün yarış koşullarının güvenliği için kanıt değildir. Normal okuyucularla paylaşılan başlık kodu değiştiğinden malformed korpusu bu sürümde tekrar koşuldu.

### Sınırlı biçim mutasyon korpusu

`scripts/fuzz-formats.mjs`, her çalışmada geçici test anahtarı ve kapsayıcı üretir. Mutasyon takvimi sabittir; taban ciphertext/nonce/salt her çalışmada yenidir. Alpha.8 kasasının seed-only plaintext'i daha kısa olduğundan uzunluğa bağlı kesilme vakası sayısı eski 17.427'lik toplamdan azdır; bu karşılaştırmalı güvenlik gücü ölçümü değildir. Geçerli dosya ve kasa kontrolleri, okuyucunun yalnız her şeyi reddeden bir hale gelmesini dışlamak için korpus öncesinde/sonrasında çalıştırılır.

| Bölüm | Bu yerel çalışmada vaka |
| --- | ---: |
| Dosya yapısal alanları ve başlık kesilmeleri | 4.741 |
| Dosya kimlik/KEM/salt/tag/kayıt baytları ve geçerli fakat doğrulanmamış parça boyutları | 1.717 |
| İlk parça yazıldıktan sonraki kayıt/son tag mutasyonları | 456 |
| Kasa yapısal alanları, profil, tür ve uzunluklar | 7.299 |
| Kasa salt/nonce/ciphertext/tag ve doğrulanmamış geçerli tür | 34 |

Native işlevler modüller yüklenmeden önce sayaçlarla sarılır. Yapısal dosya vakalarında decapsulation, yapısal kasa vakalarında Argon2 çağrısı yapılmadığı doğrudan ölçülür. Bütün vakalar sıralıdır; bu test eşzamanlı DoS veya zamanlama analizi değildir. Hata kodu/türü, hedefin oluşmaması ve staging klasörlerinin temizliği kontrol edilir. Malformed girdi çeşitliliği burada belirtilen planla sınırlıdır; keyfi bütün girdilerin güvenli olduğu sonucu çıkarılamaz.

Yanlış alıcı/AAD/context/salt; ciphertext/nonce/tag değişimi; kesilmiş tag; uzunluk ve tür sınırları; shared memory reddi; async girdilerin sonradan değiştirilmesi; tüketilmiş/kapatılmış handle; yanlış algoritma ve kanonik olmayan SPKI kontrol edilir. Bir test, 64 bayt mesaj paketinin nonce/ciphertext/tag alanlarında toplam 92 tek-bayt mutasyonunu sınar.

Dosyalar: Boş ve parça sınırındaki dosyalar, 17 MiB+31 baytlık dosya, kesilme/ek bayt, sıra değiştirme, çoğaltma, dosyalar arası parça ekleme, yanlış alıcı/context/AAD, değiştirilmiş başlık, son tag ve kaynak dosya değişikliği test edilir. Eşzamanlı aynı hedefe iki çözme çağrısından yalnızca biri yayın yapabilir. Geç iptal ve son doğrulama hatasında hedef oluşmadığı ve normal temizlikte geçici dosya kalmadığı kontrol edilir. Kısa sistem okuma/yazmaları ve sıfır yazma ilerlemesi de sınanır.

Kasa: KEM/imza anahtarının kapatılıp tekrar açılması, gerçek işlem yapabilmesi, yanlış parola, değişmiş alanlar, kötü niyetli iş faktörleri, uzunluk/tür sınırları ve async girdi snapshot'ları test edilir. Argon2 belleğinin/CPU'sunun çok istemcili yük altında sınanması bu testlerin kapsamı değildir.

Bu korpus fuzzing kampanyası değildir. Sağlayıcı hata enjeksiyonu doctor ve kasa KDF'sinin belgelenen testleriyle sınırlıdır; bütün primitive'ler için yapılmadı. RNG arıza enjeksiyonu, VM snapshot geri alma, fiziksel güç/EM, zamanlama ölçümü, büyük ölçekli DoS, yan kanal doğrulaması, tam ACVP validasyonu ve bağımsız kriptanaliz henüz yapılmadı.

## Performansın yorumu

Alpha.12 beş vakalık ayrı süreç raporu: [ham kaynak ölçümü](validation-resources-alpha12.json). İki aktif iş sınırıyla altı gerçek hesap doğrulaması 457,55 ms wall, örneklenen tepe RSS yaklaşık 179,06 MiB; CPU user/system ayrı JSON'dadır. Makinede diğer testler de çalıştığı için yük etkisi vardır. Tek örnekten yüzdelik veya servis kapasitesi garantisi çıkarılmaz; bu yeni vaka alpha.11 tablosuyla aynı ölçüm turu değildir.

Alpha.11 ayrı süreçlerde CPU/RSS ölçümlerini 32/128 MiB dosyalar, iki aktif dosya ve iki aktif kasa işi için ekler: [kaynak/arıza raporu](KAYNAK-DAYANIKLILIK.md), [ham JSON](validation-resources-windows-x64.json). Her vaka tek örnektir; aşağıdaki eski primitive benchmark'ın 30 örneğiyle birleştirilmez. Yeni `demo:message` yalnız süreç içi mesaj primitive roundtrip'ini doğrular; ağ veya sohbet protokolü yoktur.

Benchmark yalnızca bu bilgisayarda, 3 warmup ve 30 örnekle, sıralı çalıştırıldı. Async callback/threadpool maliyeti sonuca dahildir. AES-GCM satırı anahtar üretimi ve şifreleme/çözme toplamıdır; diğer işlemler ayrı ölçülür. Sonuçlar mobil cihazları, paralel yükü, servis gecikmesini veya kuantum saldırı maliyetini temsil etmez.

## GitHub Actions

Windows/Linux/macOS ve Node 24 için [workflow](../.github/workflows/ci.yml) hazırlandı. Actions commit'leri sabitlendi, yalnızca repository read yetkisi verildi. Bu çalışma sırasında uzak GitHub Actions çalışması gerçekleştirilmedi; platformlar arası sonuç varmış gibi raporlanmıyor.
