# Değişiklikler

## 0.3.0-alpha.12 — 22 Ekim 2026

- `hashPassword`, `verifyPassword`, `passwordHashNeedsRehash`, typed options ve dondurulmuş profile: Argon2id v19 PHC hesabı; yeni kayıt 64 MiB/t3/p4, salt16/digest32; sınırlı 19 MiB/t2/p1 geçiş doğrulaması.
- Katı 97 karakterlik kanonik PHC ve allowlisted iş faktörleri; bozuk/sınırsız kayıt native KDF'ye ulaşmaz. Yanlış parola false, bozuk kayıt INVALID_PASSWORD_HASH; raw 1–1024 bayt parola, trim/normalizasyon yok.
- Kasa ve hesap parolaları ortak 2 aktif/16 FIFO bekleyen Argon2 bütçesine taşındı; mevcut kasa abort davranışı korundu. Ortak sınır, iptal, malformed native çıktı, provider/RNG hata sonrası kapasite ve owned tampon temizliği regresyonları.
- Native/Noble Argon2 çapraz doğrulaması, kurulan SDK paketi, hesap parola örneği ve kaynak ölçümü; mesajlaşma kimlik/oturum/replay/ratchet tasarım kapısı. Tam sohbet protokolü uygulanmadı.
- GitHub yayını için kullanıcı açık talimat verdi; tüm HEAD geçmişi için seçili sır örüntüsü ve dosya adı tarayıcısı eklendi. Bu tarama kapsamlı sır/güvenlik denetimi değildir. Yayın sonucu uzak ağaç doğrulamasıyla ayrıca raporlanır.

## 0.3.0-alpha.11 — 22 Ekim 2026 (yerel SDK odaklı)

- Ürün hedefi uygulamalara gömülebilen geliştirici SDK'sı olarak netleştirildi; masaüstü arayüz kapsamdan çıkarıldı. CLI yardımcı araç olarak korundu; parola hash, kalıcı uygulama sırrı ve mesaj protokolü gereksinimleri ayrı belgelendi.
- **Davranış değişikliği:** birleşik seed+expanded özel anahtar varsayılan olarak LEGACY_KEY_REQUIRES_MIGRATION verir. Kontrollü SDK geçişinde `legacyKeyPolicy: 'seed-authoritative'` açıkça seçilebilir; tam companion tutarlılığı kontrolü iddiası yoktur. Seed-only/expanded-only desteği sürer; v1 wire format değişmedi.
- `createOperationPool`: örnek başına ayarlanabilir aktif/bekleyen görev sınırı, FIFO, queued abort, aktif işi erken serbest bırakmama, close ve salt okunur stats. Doğrudan çağrıları/süreçleri veya girdi baytlarını sınırlamaz.
- İki algoritmada gerçek şifreli legacy geçişi/reseal; 13 RNG/provider arıza senaryosu; sync/izin/link arızaları; gerçek alt süreç kill sonrası staging plaintext gözlemi ve gerçek havuz-dosya entegrasyonu.
- 32/128 MiB dosya, iki paralel dosya ve iki aktif kasa için ayrı süreçlerde CPU/RSS ölçümü; geliştirici, güvenlik ve kaynak/arıza raporları. Yeni süreç içi mesaj primitive örneği tam sohbet protokolü veya ağ iletimi değildir.

## 0.3.0-alpha.10 — 22 Ekim 2026 (yerel)

- `pqc inspect --input FILE [--json]` ve typed `inspectContainer(path, { signal })`: dosya/kasa türünü uzantı yerine public başlıktan tanıma, desteklenen profil ve toplam uzunluk kontrolü.
- Kütüphane ve CLI aynı dosya/kasa başlık okuyucularını kullanır. Okuma dosyada en fazla 1.664, kasada 64 bayt; KDF/KEM/özel anahtar import'u ve çıktı oluşturma yoktur.
- `authenticated: false` sabit sözleşmesi ve insan çıktısında açık doğrulanmamışlık uyarısı. Tag/ciphertext içeriği, parola veya anahtar kimliği doğrulanmaz; başlık parmak izi güvenilir pin kaynağı değildir.
- Bozuk başlıklar, boyut sınırları, gerçek dosya/kasa akışları, kaynak değişimi, iptal ve hata durumunda handle kapanışı testleri; kurulan paket ve Windows portable inceleme akışı.
- Türkçe rehber sürümü ve geliştirme planındaki eski durumlar güncellendi. Kriptografik suite ve v1 wire formatları değişmedi.

## 0.3.0-alpha.9 — 22 Ekim 2026 (yerel)

- Typed SDK'ya `publicKeyFingerprint` ve `requirePublicKeyFingerprint`; CLI aynı public-key sınıf/biçim/eşleşme kontrollerini kullanır.
- Tam `SHA256:` + 64 hex biçimi; hex case normalizasyonu, private/simetrik/duck-typed handle reddi. Satır sonunun regex son sınırında kabul edilebilmesi giderildi; whitespace/newline pin artık reddedilir.
- Mevcut public NIST ACVP anahtarının .NET ile bağımsız hesaplanmış sabit SPKI özeti, SDK tür/yanlış pin sınırları, CLI'da satır sonlu pinin çıktı oluşturmaması ve kurulan paketin SDK export'ları test edilir.
- Güvenilir pin'i edinmek çağıranın sorumluluğudur; dosya API'sine otomatik güven/sertifika/iptal listesi eklenmedi. Kriptografik primitive ve v1 biçimleri değişmedi.

## 0.3.0-alpha.8 — 22 Ekim 2026 (yerel)

- Windows portable runtime Node 24.22.1 / OpenSSL 3.5.9 güvenlik sürümüne yükseltildi; resmî SHA-256 ve OpenJS Authenticode doğrulandı. Kaynak lisans/provenance ve launcher hash pin'i güncellendi; global Node kurulumu değiştirilmedi.
- Minimum runtime ve yerel CI tanımı 24.22.1 olarak güncellendi; CLI/kütüphane eski sürümleri reddeder. Yapılandırılmış CI uzakta çalıştırılmış değildir.
- Sağlayıcının PKCS#8 temsil değişimi için eski kasayı okuma desteği; minimal DER şeması ve seed export edilebildiğinde sabit seed-only temsil; expanded-only anahtarların korunması. Eski seed+expanded girdide seed açıkça otoritatiftir; expanded içerik tutarlılığı iddiası yoktur. Alpha.7 eski uygulamalar yeni kasaları reddedebilir.
- Yeni runtime ile tam regresyon, paket, malformed korpusu ve eski runtime'ın ürettiği kasa/dosya/imzaları okuma kontrolleri. Kriptografik suite ve dış kapsayıcı başlıkları v1 kaldı; evrensel/gelecek sürüm uyumu iddiası yoktur.

## 0.3.0-alpha.7 — 22 Ekim 2026 (yerel)

- Geçici çıktı temizliği, close/unlink/rmdir adımlarından biri hata verse de diğerlerini dener; alttaki hataları `AggregateError` cause içinde saklayan `CLEANUP_FAILED` üretir.
- CLI, dosya sistemi hata ayrıntılarını yazmadan çıktı klasöründeki staging verilerini incelemeyi bildirir. Yayınlama tamamlandıktan sonra temizlik hata verebilir; yayımlanmış hedef geri alınmaz.
- Kapanma/silme hataları, geç dosya doğrulama hatasından sonra plaintext temizliği ve CLI hata ayrıntılarının dışarı çıkmaması regresyonları. OS/izin/çökme halinde kesin silme iddiası yoktur; v1 kripto/biçim değişmedi.

## 0.3.0-alpha.6 — 22 Ekim 2026 (yerel)

- Kasa seal/open API'lerine isteğe bağlı `{ signal }`; iptal edilen bekleyen işin sıradan çıkarılması, slot aktarımı yarışının kontrolü ve dinleyici temizliği.
- Aktif native KDF iptalinde callback beklenir; rezervasyon erken bırakılmaz, sonuç yayımlanmadan temizlenip `ABORTED` döndürülür. Native işlemi zorla durdurma veya kesin timeout iddiası yoktur.
- CLI ve doctor sinyali kasaya iletir. Kuyruk iptali, aktif iptal, girdi/slot sınırları ve doctor KDF sırasında SIGINT için regresyonlar; v1 biçimi/kripto parametreleri değişmedi.

## 0.3.0-alpha.5 — 22 Ekim 2026 (yerel)

- Kasa seal/open işlemlerinde ortak 2 native KDF isteği ve 16 FIFO bekleyen istek sınırı; kapasite aşımı native iş başlatmadan `RESOURCE_LIMIT` döndürür.
- Başarılı/başarısız sağlayıcı tamamlanmalarında slot aktarımı, hata sonrasında devam etme, kuyrukta girdi snapshot'ları ve tampon temizliği regresyonları; gerçek native paralel kasa roundtrip kontrolü.
- Sınır modül örneğine aittir; worker/süreç toplamı, rate limiti veya genel DoS koruması garantisi değildir. Kriptografik parametreler ve v1 wire format değişmedi.

## 0.3.0-alpha.4 — 22 Ekim 2026 (yerel)

- Ayrı Node/npm kurulumu gerektirmeyen Windows x64 portable ZIP derleyicisi ve doğrudan native süreç başlatan C# launcher; Windows/.NET Framework 4.x gerekir.
- Resmî Node 24.16.0 binary özeti, OpenJS Authenticode kontrolü ve tam lisans metni; runtime hash pin'i ve çalışma sırasında dosya kilidi. Launcher'ın kendisi imzasızdır.
- Ortamdan Node preload/provider ayarlarının çocuk süreçte devralınmaması; argv quote/Unicode/metakarakter iletimi ve çıkış kodunun korunması.
- Bağımsız ayıklanmış kopyada bütünlük, doctor, dosya/imza roundtrip, parola değişimi, ortam enjeksiyonu ve bozuk runtime reddi kontrolleri.
- Gerçek ConPTY oturumunda gizli Türkçe parola/onay ve Ctrl+C iptali doğrulandı.
- Proje kaynak arşivinde executable/ZIP gibi build ürünlerinin yanlışlıkla yer alması yayın kontrolünde reddedilir. Kriptografik suite ve wire format değişmedi.

## 0.3.0-alpha.3 — 22 Ekim 2026 (yerel)

- `change-password` ile KEM/imza anahtarını aynı kimlikte tutup yeni parolalı ayrı kasaya yazma. Orijinal korunur, mevcut hedeflerin üzerine yazılmaz; anahtar rotasyonu veya eski yedekleri iptal etme iddiası yoktur.
- Etkileşimli güncel/yeni parola istemleri, yeni parola onayı, otomasyonda ayrı `--new-password-file`; yanlış parola, iptal, onay uyuşmazlığı ve çıktı çakışması testleri.
- Gizli terminal isteminde eşzamanlı setup/cleanup hatalarının tampon temizliğini ve Promise sonlandırılmasını atlaması önlendi. Geri yükleme, resume ve write arızaları için regresyonlar.
- 17.427 vakalık sınırlı dosya/kasa mutasyon korpusu; yapısal geçersiz girdilerin native Argon2/ML-KEM çağrısına ulaşmadığını sayaçlarla kontrol eder. Bu sayı bir fuzzing kampanyası, denetim veya güvenlik ispatı değildir.
- Dosya/kasa wire formatı ve kriptografik suite değişmedi. Geliştirme kullanıcının isteğiyle yalnız yerelde sürüyor.

## 0.3.0-alpha.2 — 22 Ekim 2026 (yerel)

- `pqc doctor`: kullanıcı dosyalarını kullanmadan geçici anahtarlarla gerçek KEM/KDF/AEAD, imza ve Argon2id kasa kontrolü; JSON ve insan tarafından okunabilir sonuçlar. Denetim/sertifikasyon veya dosya sistemi kontrolü olduğu iddia edilmez.
- Native API import edilmeden önce CLI çalışma zamanı kontrolü; uyumsuz sürümde anlaşılır `UNSUPPORTED_RUNTIME` hatası.
- Dağıtım paketinin geçici klasöre kurulup doctor ve dosya roundtrip ile sınanması; paket içeriği için izin listesi.
- Doctor sağlayıcı hataları ve sürüm sınırları için regresyon testleri; üç platform CI tanımına paket kontrolü eklendi. Uzak CI henüz çalıştırılmadı.
- Resmî kaynaklara dayalı proje karşılaştırması ve güvenlik geliştirme öncelikleri.
- GitHub deposu oluşturuldu; Chrome yükleme izni reddedildiği için kaynak kodu yayımlanmadı. Kullanıcı isteğiyle çalışma yalnız yerelde sürüyor.

## 0.3.0-alpha.1 — 21 Ekim 2026

- İnsanların kullanabileceği `pqc` komut satırı aracı: keygen, fingerprint, encrypt/decrypt ve detached sign/verify.
- Terminalde gizli parola ve keygen onayı; otomasyon için uzunluğu sınırlı raw password-file. Parola argv/env üzerinden alınmaz ve hata mesajlarına eklenmez.
- Şifrelemede doğrulanmış tam SHA-256 public-key parmak izi zorunluluğu, katı seçenek ayrıştırma, JSON sonuçlar ve anlaşılır hata kodları.
- Yeni çıktıların exclusive oluşturulması ve keygen'in ikinci çıktısı başarısızsa ilk çıktıyı kontrollü geri alması.
- Anahtar kasasında doğrulanmış PKCS#8 içeriğinin canonical kontrolü; authenticated trailing DER baytları reddedilir. Bu, iç format sıkılaştırmasıdır; gizli anahtar kurtarma saldırısı bulunduğu iddia edilmez.
- İngilizce ana rehber ve Türkçe kullanıcı kılavuzu; resmî PolyForm Noncommercial 1.0.0 lisansı. Üçüncü tarafların lisansları değişmez.
- CLI uçtan uca testleri ve beş çekirdek sıkılaştırma regresyonu. Runtime npm bağımlılığı eklenmedi.
- Deneysel durum devam eder; bu çalışma dışarıdan bağımsız kriptografik denetim değildir.

## 0.2.0-alpha.1 — 21 Ekim 2026

- ML-KEM alıcısına parçalı dosya şifreleme/çözme eklendi. Bütün başlık, beklenen bağlam, kayıt sırası ve son kayıt doğrulanır; her kayıt için ayrı anahtar türetilir.
- Hedef dosyanın yalnızca tam başarıda oluşturulması, üzerine yazmama, iptal ve kaynak değişikliği kontrolleri eklendi. Normal hata/iptalde özel staging klasörü temizlenir.
- Sabit Argon2id profili ve AES-256-GCM ile parola korumalı KEM/signing key saklama/geri yükleme eklendi.
- Private key'den public/verification handle türetme eklendi; raw private key export genel API'de yoktur.
- Disk üzerinde çalışan örnek, nominal TypeScript türleri ve GitHub Actions adımı eklendi.
- Test sayısı 51'den 89'a çıktı. RFC Argon2 vektörü, bağımsız KEM/HKDF dosya okuyucusu, bağımsız Argon2 kasa doğrulaması ve dosya saldırı/durum testleri eklendi.
- Runtime npm bağımlılığı eklenmedi. Dosya/kasa biçimleri deneysel; bağımsız güvenlik denetimi ve GitHub yayını yapılmadı.

## 0.1.0-alpha.1 — 21 Ekim 2026

- ML-KEM-1024, ML-DSA-87, HKDF-SHA-512 ve tek kullanımlık AES-256-GCM handle çekirdeği.
- NIST ACVP/AES vektörleri, Noble uyumluluk testleri ve ilk 51 test.
- İlk matematik/standart/saldırı araştırması ve yerel benchmark kaydı.
