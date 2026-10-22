# Türkçe kullanım kılavuzu

Hangi komutu seçeceğiniz ve hata kodlarında izlenecek adımlar: [komut seçimi ve sorun giderme](SORUN-GIDERME.md).

**PQC Research Core 0.3.0-alpha.12 — deneysel ve bağımsız denetimden geçmemiştir.**

Ana ürün [geliştirici SDK'sıdır](GELISTIRICI-SDK.md); bu rehber yardımcı CLI içindir. Alpha.11 birleşik seed+expanded eski kasayı varsayılan olarak LEGACY_KEY_REQUIRES_MIGRATION ile reddeder. CLI otomatik geçiş seçeneği sunmaz; kontrollü SDK geçişi ve güvenilir public pin doğrulaması gerekir. Orijinal kasa/yedekleri koruyun.

Windows x64 portable ZIP kullanıyorsanız ayrı Node/npm kurulumu gerekmez. Arşivin tamamını çıkarın, klasörde PowerShell açıp `.\pqc.exe doctor` çalıştırın. `.NET Framework 4.x` gereklidir. Bu rehberdeki `node $pqc` çağrılarının yerine `& $pqc` kullanabilirsiniz; `$pqc` değişkeni çıkarılan `pqc.exe` dosyasının tam yolu olmalıdır. Ayrıntılar: [taşınabilir paket](PORTABLE-WINDOWS.md).

Kurulumdan sonra `node bin/pqc.mjs doctor` ile yerel kriptografik işlevleri kontrol edebilirsiniz. Komut kullanıcı dosyalarını açmaz, diske yazmaz ve ağa bağlanmaz; geçici anahtarlarla KEM/KDF/AES-GCM, imza ve Argon2id kasa roundtrip yapar. Yaklaşık 64 MiB Argon2 çalışma belleği kullanır. `--json` yapılandırılmış sonuç verir. Bu kontrol güvenlik sertifikası veya dosya sistemi izin/hard link testi değildir.

Bu araç dosyaları alıcının açık anahtarına şifrelemenizi ve ayrı bir imza anahtarıyla imzalamanızı sağlar. İşlemler Node.js/OpenSSL üzerinden yürür; çalışma zamanında üçüncü taraf npm bağımlılığı yoktur. Anahtar kurma ML-KEM-1024, imza ML-DSA-87, anahtar türetme HKDF-SHA-512, veri şifreleme AES-256-GCM kullanır. Özel anahtar kasası Argon2id ve AES-256-GCM ile korunur. Dosya ve kasa biçimleri projenin deneysel tasarımlarıdır.

Kuantum sonrası standartları kullanmak, tüm aracın güvenliğinin kanıtlandığı anlamına gelmez. Mükemmellik, gelecekteki tüm saldırılara dayanıklılık, bağımsız denetim veya FIPS sertifikasyonu iddiası yoktur. Güvenlik sınırlarını [SECURITY.md](../SECURITY.md) ve [dosya biçimi belgesinden](FILE-FORMAT.md) okuyabilirsiniz.

## Kurulum

Node.js **24.22.1 veya üzeri bir 24.x** sürümü gerekir. Depo klasöründe PowerShell açın:

```powershell
node --version
npm ci --ignore-scripts
node bin/pqc.mjs help
node bin/pqc.mjs --version
```

Sonraki örnekler için CLI'ın tam yolunu kaydedin ve depo dışında önceden oluşturduğunuz özel çalışma klasörüne geçin:

```powershell
$pqc = (Resolve-Path .\bin\pqc.mjs).Path
Set-Location (Read-Host 'Depo disindaki mevcut ozel calisma klasorunun tam yolu')
```

İsterseniz depo klasöründe `npm link` ile yerel `pqc` komutunu kurun; örneklerde `node $pqc` yerine `pqc` yazabilirsiniz. npm kayıt sisteminde yayımlanmış bir paket kurulmaz. Bağımlılıklar kurulduktan sonra işlemler ağ bağlantısı gerektirmez.

Örneklerdeki dosya yolları çalıştığınız klasöre göredir. Dosyalar için kaynak kod deposu dışında, yalnızca hesabınızın erişebildiği güvenilir bir yerel klasör seçin. Windows'ta klasör ACL izinlerini denetleyin; POSIX izin sayıları Windows gizliliğini tek başına sağlamaz. Özel anahtarları, parolaları veya gerçek belgelerinizi Git'e eklemeyin.

## 1. Şifreleme anahtarı oluşturma

```powershell
node $pqc keygen --type kem --vault alici.vault --public alici.public.der
node $pqc fingerprint --public alici.public.der
```

Araç parolayı ekranda göstermeden ister ve anahtar üretirken tekrarını sorar. Parola 16–1024 bayt olmalıdır; bu alt sınır güçlü parola garantisi değildir. Güçlü, benzersiz bir parola seçin ve parolayla kasanın güvenli yedeğini alın. Parola veya kasa kaybı için kurtarma mekanizması yoktur.

- `alici.public.der`: Paylaşılabilen kanonik SPKI DER açık anahtarı.
- `alici.vault`: Gizli tutulması gereken, parolayla şifrelenmiş özel anahtar kasası.

Açık anahtar parmak izi `SHA256:` öneki ve **64 küçük harfli onaltılık karakterdir**. Tamamını, alıcıyla önceden doğruladığınız bir kanaldan veya yüz yüze karşılaştırın. Size gelen anahtardan parmak izi hesaplamak, o anahtarın kime ait olduğunu kanıtlamaz.

## 2. Dosya şifreleme

`belge.txt` hazır olduğunda, alıcıyla doğruladığınız tam parmak izini girin:

```powershell
$beklenenParmakIzi = Read-Host 'Aliciyla dogruladiginiz tam SHA256 parmak izini yapistirin'
node $pqc encrypt --input belge.txt --output belge.pqc --public alici.public.der --fingerprint $beklenenParmakIzi --context benim-uygulamam/belgeler/v1 --aad belge:42
```

`--fingerprint` şifrelemede zorunludur. Yanlış anahtarı, aynı güvensiz kaynaktan aldığınız parmak iziyle eşleştirmeniz kimlik doğrulama sağlamaz. Yerel denemede, bizzat oluşturduğunuz anahtarın çıktısıyla karşılaştırabilirsiniz.

`--context`, uygulamayı ve amacı belirten zorunlu bağlamdır. `--aad` isteğe bağlı ek doğrulama verisidir; örneğin alıcının önceden beklediği belge kimliği olabilir. Bunlar parola değildir ve gizli bilgi taşımamalıdır. Alıcıyla ayrıca kararlaştırıp saklayın; araç bunları şifreli dosyadan güvenilir kabul ederek otomatik almaz.

## 3. Dosyayı çözme

```powershell
node $pqc decrypt --input belge.pqc --output belge.cozulmus.txt --vault alici.vault --context benim-uygulamam/belgeler/v1 --aad belge:42
```

Alıcı kasa parolasını girer. Context ve varsa AAD, şifrelemedeki değerlerle bayt düzeyinde aynı olmalıdır. Yazım, büyük/küçük harf veya UTF-8 farkı doğrulama hatası üretir. Değerler kaybolursa dosya çözülemeyebilir. Aynı belge kimliği, eski dosyanın tekrar gönderilmesini engellemez.

Mevcut çıktıların üzerine yazılmaz; kaynak dosyalar silinmez. Çıktı adını değiştirerek yeniden deneyin ve orijinal verinin güvenli yedeğini koruyun. Araca güvenmeden önce deneme dosyasıyla yedekten geri yüklemeyi de doğrulayın.

## Parola girmeden dosya/kasa bilgisi inceleme

```powershell
node $pqc inspect --input belge.pqc
node $pqc inspect --input alici.vault --json
```

Windows taşınabilir pakette aynı çağrı `& $pqc inspect --input belge.pqc` şeklindedir. Uzantıya bakılmaz; biçim başlangıç baytlarından tanınır. Desteklenen sürüm/profil, başlık ve toplam dosya uzunluğu kontrol edilir. Şifreli belgede beyan edilen açık metin boyutu, parça sayısı/boyutu ve alıcı parmak izi; kasada beyan edilen anahtar türü ve sabit Argon2id profili gösterilir. Başlangıç yoklaması dahil en fazla dosyada 1.664, kasada 64 bayt okunur. Parola istenmez, özel anahtar yüklenmez, KDF çalıştırılmaz ve çıktı dosyası oluşturulmaz.

**Bu bir bütünlük veya kimlik doğrulaması değildir.** Bütün alanlar değiştirilebilir başlık iddialarıdır; JSON sonucunda `authenticated` her zaman `false` olur. Başarılı çıkış kodu yalnızca incelemenin tamamlandığını belirtir. Ciphertext/tag bozulmuş olsa bile başlık incelemesi başarılı olabilir. Buradan alınan alıcı parmak izini güvenilir parmak izi olarak kaydetmeyin. Tam doğrulama için güvenilir context/AAD ile `decrypt`, ayrı imzalar için `verify` kullanılır. İnceleme unutulan parola/anahtarı, context veya AAD'yi kurtarmaz; anahtarın sahibini veya klasör izinlerini doğrulamaz.

Geliştiriciler aynı akışı `inspectContainer(inputPath, { signal })` üzerinden kullanabilir. Sonuç salt okunurdur ve `kind` alanına göre `encrypted-file` veya `key-vault` olarak ayrılır. İşlem sırasındaki sıradan boyut/zaman değişimleri reddedilir; kötü niyetli eşzamanlı yazara karşı snapshot garantisi yoktur.

## 4. İmzalama ve doğrulama

İmza için ayrı anahtar üretin. `sign`, girdinin gerçek baytlarını pure ML-DSA-87 ile imzalar; bu CLI'da imza girdisi en fazla **16 MiB** olabilir.

```powershell
node $pqc keygen --type signature --vault imzaci.vault --public imzaci.public.der
node $pqc fingerprint --public imzaci.public.der
node $pqc sign --input belge.txt --output belge.sig --vault imzaci.vault --context benim-uygulamam/imza/v1
```

İmzacının parmak izini doğruladığınız kanaldan alın:

```powershell
$imzaciParmakIzi = Read-Host 'Imzaciyla dogruladiginiz tam SHA256 parmak izini yapistirin'
node $pqc verify --input belge.txt --signature belge.sig --public imzaci.public.der --fingerprint $imzaciParmakIzi --context benim-uygulamam/imza/v1
```

Doğru imza, verilen anahtara göre dosya baytlarının ve bağlamın doğrulandığını gösterir. Anahtarın kişiye ait olduğunu ayrıca doğrulamalısınız. `verify` için parmak izi teknik olarak isteğe bağlı olsa da kimlik doğrulama iş akışında kullanılmalıdır. Şifreleme kendi başına gönderici kimliğini doğrulamaz. Bu komutlar otomatik bir mesajlaşma protokolü oluşturmaz.

## Otomasyon ve parola dosyası

Kasanın parolasını aynı anahtarı koruyarak değiştirmek için:

```powershell
node $pqc change-password --vault alici.vault --output alici-yeni.vault
```

Önce mevcut parolayı, ardından yeni parolayı iki kez girin. İşlem KEM ve imza kasalarında desteklenir; yeni ve eski kasanın açık anahtar parmak izi aynıdır. Eski kasa silinmez, mevcut hedefin üzerine yazılmaz. Yeni kasanın iş akışınızda çalıştığını ve yedeğini doğrulayın. **Eski kasa ve yedekleri eski parolayla açılmaya devam eder.** Bu komut anahtar rotasyonu veya ele geçirilmiş anahtarın güvenliğini geri kazanma işlemi değildir. Unutulan parola kurtarılamaz.

`keygen`, `decrypt` ve `sign`, otomasyon için `--password-file YOL` kabul eder. `change-password` mevcut parola için `--password-file`, yeni parola için `--new-password-file` kullanır. Dosya **ham 16–1024 bayt** olarak okunur. Satır sonu kırpılmaz, Unicode normalleştirilmez; editörün eklediği yeni satır parolanın parçasıdır. Dosyayı özel anahtar kadar koruyun; kasanın yanında herkesin erişebildiği şekilde saklamayın.

Parola komut satırı argümanı veya ortam değişkeniyle verilmez. Özel bilgileri terminal geçmişine, loglara veya depoya yazmayın. Etkileşimli kullanımda parola dosyası gerekmez.

Makineyle işlenen sonuçlar için `--json` ekleyebilirsiniz. Sıfırdan farklı çıkış kodunu hata olarak ele alın ve açıklamayı inceleyin. Son bir disk/temizlik hatası, tam çıktı oluşmuşken de bildirilebilir; yalnızca dosyanın varlığına bakarak başarı kararı vermeyin.

`CLEANUP_FAILED` çıktı klasöründeki geçici verilerin incelenmesini gerektirir. `.pqc-stage-*` klasörlerinde kısmi açık metin bulunabilir; hedef dosya da daha önce oluşturulmuş olabilir. Temizlik close hatasından sonra bile silme adımlarını dener, ancak OS/izin/çökme durumunda garanti vermez. Hatanın ardından hedefi otomatik silmeyin veya üzerine yazmayı denemeyin; mevcut veriyi koruyarak sonucu değerlendirin.

## Sınırlar ve diskteki geçici veriler

Dosya şifreleme/çözme sınırı 64 GiB, varsayılan parça boyutu 1 MiB'dir. Dosya/KDF bağlamı en fazla 512 bayt, imza bağlamı en fazla 255 bayt, AAD en fazla 64 KiB'dir. Bayt sınırı karakter sayısıyla aynı değildir. Argon2id her kasa açılışında yaklaşık 64 MiB KDF belleği kullanır. Modül örneği başına 2 native istek ve 16 FIFO bekleyen sınırı vardır; taşma RESOURCE_LIMIT döndürür. Servislerde süreç/worker toplamı ve rate limiti ayrıca yönetilmelidir. Ctrl+C kasa KDF sırasında kullanılırsa çıkış için başlamış native işin callback'i beklenir; kuyruktaki işler iptal edilebilir.

Çözme sırasında tek tek doğrulanmış parçalar geçici dosyaya **açık metin** olarak yazılır. Bütün dosya doğrulanınca hedef adı oluşturulur. Normal işlemlerde geçici dosyalar temizlenir; süreç/bilgisayar çökmesi veya izin/disk hatasında açık metin kalabilir. Güvenilir çıktı klasörü kullanın; disk, swap, yedek ve snapshot güvenliğini ayrıca yönetin. Yayınlama aynı volume üzerinde hard link desteği gerektirir. Bulutla eşitlenen veya ağ üzerindeki klasörler farklı izin ve dosya sistemi davranışları gösterebilir.

Şifreli başlık boyutu, profili, parça boyutunu ve alıcı parmak izini gizlemez. Sistem replay önleme, forward secrecy, alıcı anonimliği veya anahtar ele geçirme sonrası toparlanma sağlamaz. Süreçteki kötü niyetli koddan izolasyon yoktur. Bellek temizliği mümkün olduğunca yapılır; tüm kopyaların kesin silinmesi garanti edilmez.

## Geliştiriciler için

Bu komutları kaynak kod deposunun klasöründe çalıştırın:

```powershell
npm test
npm run typecheck
npm run check
npm run demo
npm run demo:files
npm run test:package
npm run fuzz:formats
```

API örneği [README.md](../README.md) içindedir. `encryptFile`, CLI'daki zorunlu parmak izi kontrolünü uygulamaz; çağıran uygulama açık anahtar kimliğini kendisi doğrular. Türler [src/index.d.ts](../src/index.d.ts), disk örneği [examples/file-roundtrip.mjs](../examples/file-roundtrip.mjs) içindedir. Gerçek sonuçları ve kapsam sınırlarını [doğrulama raporundan](DOGRULAMA.md) inceleyin.

Alpha.9 SDK'da `publicKeyFingerprint` ve `requirePublicKeyFingerprint` sunar. İkincisini güvenilir kanaldan edinilmiş tam pin ile **şifrelemeden önce** çağırın; aynı doğrulanmamış public dosyasından pin üretip karşılaştırmak kimlik güveni oluşturmaz. Pin, tam DER SPKI'nin SHA-256 özetidir: `SHA256:` ve 64 hex. Hex case farkı kabul edilir; boşluk/satır sonu veya kısaltma reddedilir. Bu proje biçimi diğer araçların base64 veya sertifika parmak izi biçimleriyle birbirinin yerine kullanılmaz. CLI aynı kontrolü kullanır.

## Lisans

Projenin kendi kodu [PolyForm Noncommercial 1.0.0](../LICENSE) altında sunulur; SPDX kimliği `PolyForm-Noncommercial-1.0.0`'dır. Ticari kullanım genel ticari olmayan amaç izni kapsamında lisanslanmaz. Tanımlanmış kişisel kullanımlar ve belirli kurumlar için açık izin hükümleri vardır; listelenen kurumlara ilişkin hüküm fon kaynağından veya yükümlülüklerinden bağımsızdır. Yasadan doğan fair-use hakları korunur. Kesin kapsam için [resmî lisans metni](https://polyformproject.org/licenses/noncommercial/1.0.0) geçerlidir.

Ticari kullanım kısıtı nedeniyle bu model [OSI açık kaynak tanımına](https://opensource.org/osd) uymaz; İngilizce adıyla source-available'dır. Üçüncü taraflar kendi lisanslarını korur: [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md).
