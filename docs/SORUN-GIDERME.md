# Komut seçimi ve sorun giderme

Bu rehber yerel CLI ve Windows taşınabilir paket için geçerlidir. Örneklerde `$pqc`, çıkarılan `pqc.exe` dosyasının tam yoludur. Kaynak CLI kullanıyorsanız `& $pqc` yerine `node $pqc` yazın ve `$pqc` değerini `bin/pqc.mjs` yoluna ayarlayın. Gerçek verilerden önce bir deneme dosyası ve yedekten geri yükleme akışı kullanın.

## Hangi işlem için hangi komut?

| İhtiyaç | Komut | Ne doğrular? |
| --- | --- | --- |
| Çalışma zamanının kripto işlevlerini denemek | `doctor` | Geçici test anahtarlarıyla işlemlerin çalışmasını; makine/izin güvenliğini değil |
| Elinizdeki dosya/kasa türünü görmek | `inspect --input FILE` | Desteklenen başlık/profil ve toplam uzunluk; içerik veya kimliği değil |
| Alıcı için anahtar üretmek | `keygen --type kem` | Yeni anahtar ve parolalı kasa üretir; yedek/kurtarma hizmeti değildir |
| İmza için ayrı anahtar üretmek | `keygen --type signature` | Ayrı imza anahtarını üretir; gönderici kimliğini dışarıdan doğrulamaz |
| Açık anahtarın tam özetini görmek | `fingerprint --public FILE` | Verilen açık anahtarın parmak izini hesaplar; sahibini doğrulamaz |
| Alıcıya dosya hazırlamak | `encrypt` | Verilen güvenilir pin ile anahtarı eşleştirir ve şifreler |
| Şifreli dosyayı açmak | `decrypt` | Verilen özel anahtar, beklenen context/AAD ile bütün dosya doğrulanınca hedefi oluşturur |
| Dosyayı imzalamak / ayrı imzayı doğrulamak | `sign` / `verify` | Dosya baytları ve imza bağlamı; anahtarın sahibini ayrıca doğrulayın |
| Aynı anahtarın kasa parolasını değiştirmek | `change-password` | Yeni kasa yazar; eski kasa/yedekleri veya ele geçirilmiş anahtarı iptal etmez |

Tam seçenekler: `& $pqc --help`. Tam akış örnekleri: [Türkçe kullanım kılavuzu](KULLANIM.md).

## İlk yerel kontrol

```powershell
& $pqc --version
& $pqc doctor --json
& $pqc inspect --input belge.pqc --json
```

Her komutun çıkış kodunu kendi çağrısından hemen sonra kontrol edin: `$LASTEXITCODE`. `0` komutun tamamlandığını, `1` hatayı, `130` kontrollü iptali belirtir. **`inspect` için `0`, bütünlük/kimlik doğrulaması değildir:** `authenticated: false` kalır. Doktor kontrolünün başarısı gerçek dosyanın sağlam olduğunu göstermez. Başarısızlıkta sırf hedef dosya oluştu diye başarı kararı vermeyin.

## Hata kodları ve sonraki adım

| Kod | Anlamı | İzlenecek yol |
| --- | --- | --- |
| `UNSUPPORTED_RUNTIME` | Kaynak CLI için Node sürümü desteklenmiyor | Kararlı 24.22.1+ bir 24.x kullanın veya güncel tam taşınabilir paketi seçin |
| `RUNTIME_INTEGRITY` | Taşınabilir başlatıcı runtime özetini kabul etmedi | Paketi kullanmayı bırakın; güvenilir kaynaktan alınan tam arşiv ile karşılaştırın. Hash kontrolünü kaldırmayın |
| `PASSWORD_REQUIRED` | Gizli parola için etkileşimli terminal yok | Etkileşimli PowerShell kullanın; otomasyon gerekiyorsa özel izinli parola dosyası sözleşmesini okuyun |
| `INVALID_FINGERPRINT` | Tam pin biçimi bozuk | `SHA256:` ve 64 hex karakteri kullanın; boşluk/satır sonu eklemeyin, pin'i kısaltmayın |
| `FINGERPRINT_MISMATCH` | Anahtar, güvendiğiniz pin ile eşleşmiyor | İşlemi durdurup alıcıyla bağımsız güvenilir kanalda doğrulayın. Yeni dosyadan hesaplanan pin'i otomatik güvenilir saymayın |
| `INVALID_CONTAINER` | İnceleme desteklenen başlangıç baytlarını bulamadı | Dosyanın doğru ürün/biçime ait olduğunu kontrol edin; uzantıyı değiştirmek dönüştürme yapmaz |
| `INVALID_FILE` / `INVALID_VAULT` | Desteklenmeyen veya yapısal olarak bozuk kapsayıcı | Doğru dosyayı, sağlam yedeği ve okuyucu sürümünü kontrol edin; [eski kasa geçiş politikasını](RUNTIME-POLICY.md) inceleyin |
| `AUTHENTICATION_FAILED` | Parola, anahtar, bağlam/AAD veya doğrulanan içerik eşleşmedi | Özgün dosyayı koruyun; doğru kasa/parola ve bayt düzeyinde aynı context/AAD'yi doğrulayın. Tek başına bu kod sebebi ayırmaz |
| `SIGNATURE_INVALID` | Verilen anahtar/bağlama göre imza doğrulanmadı | Özgün dosya/imza çiftini, bağımsız doğrulanan imzacı pin'ini ve imza context'ini kontrol edin |
| `OUTPUT_EXISTS` / `EEXIST` | Hedef zaten var | Var olan veriyi koruyup farklı ve yeni bir hedef adı seçin |
| `INPUT_CHANGED` | Okuma sırasında sıradan dosya boyutu/zaman değişimi gözlendi | Kaynak yazımını/eşitlemeyi durdurup güvenilir sabit bir kopyayla yeniden deneyin |
| `RESOURCE_LIMIT` | Bu modül örneğinin kasa kuyruğu dolu | İstek hızını ve paralel işi azaltın; servis/worker toplamına ayrıca sınır koyun |
| `LEGACY_KEY_REQUIRES_MIGRATION` | Alpha.11 birleşik seed+expanded eski anahtarı varsayılan olarak reddetti | Otomatik kontrolleri gevşetmeyin. [SDK kontrollü geçişini](GELISTIRICI-SDK.md) ve bağımsız güvenilir pin kontrolünü kullanın; eski dosyayı koruyun |
| `POOL_CLOSED` | Uygulamanın işlem havuzu kapatıldı | Yeni istek kabulünü durdurun; aktif işler yerleşsin. Havuz yaşam döngüsünü servis katmanında yönetin |
| `ABORTED` | İşlem iptal edildi | Native KDF başladıysa tamamlanması beklenebilir; iptal kesin süre veya fiziksel silme garantisi değildir |
| `CLEANUP_FAILED` | Geçici çıktı temizliğinin en az bir adımı hata verdi | Çıktı klasörünü ve `.pqc-stage-*` verilerini inceleyin. Kısmi açık metin kalabilir; hedef daha önce yayımlanmış olabilir. Otomatik silme/üzerine yazma yapmayın |
| `EACCES` / `EPERM` | Erişim veya dosya sistemi işlemi reddedildi | Özel klasörün ACL/erişim izinlerini ve hard link desteğini kontrol edin |
| `EXDEV` / `ENOTSUP` | Güvenli çıktı yayınlaması gereken dosya sistemi özelliği yok | Aynı yerel volume üzerinde hard link destekleyen güvenilir bir çıktı klasörü seçin |
| `ENOSPC` | Yeterli alan yok | Kaynak/yedekleri koruyarak çıktı ve geçici veriler için yeterli alan sağlayın |

## İnceleme neden başarılı, çözme neden başarısız?

`inspect`, ciphertext kayıtlarına veya doğrulama etiketlerine bakmaz. Başlıkta anlamlı değerler ve tutarlı dosya uzunluğu olması doğru parola, doğru anahtar veya sağlam içerik anlamına gelmez. İleri sürülen alıcı pin'i de doğrulanmamıştır. Tam dosya doğrulaması, güvenilir context/AAD ve uygun özel anahtarla `decrypt` sırasında yapılır. Context/AAD dosyadan otomatik kurtarılamaz; bunlar kaybolursa parola doğru olsa da çözme başarısız olabilir.

## Hata raporu hazırlama

Paylaşmadan önce sürüm, işletim sistemi/mimari, hata kodu ve sentetik verilerle tekrar üretim adımlarını kaydedin. `doctor --json` çıktısını kişisel bilgiler için inceleyin. Parola/parola dosyası, özel anahtar/kasa, gerçek belge, hassas context/AAD veya kişisel dosya yolu paylaşmayın. `inspect` çıktısı alıcı pin'i ve dosya boyutu gibi metadata içerebilir; paylaşım öncesi bunları da değerlendirin.

Bu yönerge bağımsız güvenlik denetimi, parola kurtarma veya üretim uygunluğu onayı değildir. [Güvenlik sınırları](../SECURITY.md) geçerlidir.
