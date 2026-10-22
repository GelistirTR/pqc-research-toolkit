# Windows taşınabilir paket

0.3.0-alpha.10 için yerel Windows x64 ZIP'i hazırlanmıştır. Ayrı Node/npm kurulumu gerekmez; Windows x64 ve .NET Framework 4.x gerekir. Paket, kaynakla aynı deneysel güvenlik durumundadır; bağımsız denetim veya imzalı proje yayını değildir.

## Kullanım

ZIP'in tamamını güvenilir bir yerel klasöre çıkarın. Çıkarılan klasörde PowerShell açıp çalıştırın:

```powershell
.\pqc.exe doctor
.\pqc.exe --help
.\pqc.exe inspect --input belge.pqc
```

`doctor`, geçici anahtarlarla kriptografik işlevleri sınar. Disk izinlerini veya makinenin güvenliğini denetlemez. Şifreleme, çözme, imza ve parola değiştirme seçenekleri kaynak CLI ile aynıdır. Program klasöründe anahtar veya kullanıcı belgeleri biriktirmek yerine, çalışacağınız özel veri klasörüne geçmeden önce çalıştırılabilir dosyanın tam yolunu kaydedin:

```powershell
$pqc = (Resolve-Path .\pqc.exe).Path
# Kendi özel veri klasörünüze geçtikten sonra:
& $pqc keygen --vault alici.vault --public alici.der
& $pqc fingerprint --public alici.der
```

Dosya şifrelemede tam parmak izini alıcıyla bağımsız güvenilir kanaldan doğrulayın. Diğer komutlar ve dosya güvenliği sözleşmesi [kullanım rehberinde](KULLANIM.md), İngilizce örnekler `tool/README.md` içindedir. Parola kurtarma yoktur; eski kasaların kopyaları parola değişiminden sonra eski parolayla açılabilir. Anahtarları/yedekleri ve erişim izinlerini koruyun.

## İçerik ve doğrulama

- `pqc.exe`: [C# kaynağından](../packaging/windows/PqcLauncher.cs) derlenen küçük, **imzasız** .NET başlatıcı. Kabuğa komut metni göndermez; bağımsız argümanları Windows CRT kurallarına göre doğrudan Node'a aktarır. Node dosyasını SHA-256 ile kontrol eder ve çalışma sırasında yazma/silme paylaşımı açmadan tutar. Çocuğun çıkış kodunu iletir; terminal Ctrl+C olayını çocuğun temizliğini bekleyerek ele alır.
- `runtime/node.exe`: değiştirilmemiş Node **24.22.1**, OpenSSL **3.5.9**, x64. Resmî HTTPS [SHA-256 kaydıyla](https://nodejs.org/dist/v24.22.1/SHASUMS256.txt) birebir eşleşti; derlemede Windows Authenticode durumu `Valid`, yayıncı OpenJS Foundation olarak doğrulandı. Detached GPG imzası doğrulanmadı. Başlatıcı her çalışmada hash kontrol eder; her seferinde çevrimiçi imza/revocation sorgusu yapmaz.
- `runtime/LICENSE.txt`: aynı Node sürümünün tam Node/OpenSSL/üçüncü taraf lisans ve atıf metni. Proje lisansı bunların kendi haklarını değiştirmez.
- `tool/`: CLI, JavaScript/TypeScript kütüphanesi, biçim belgeleri, örnekler ve proje lisansı. npm/geliştirme bağımlılıkları, gerçek anahtar veya kullanıcı verisi eklenmez.
- `MANIFEST.json`: dahil dosyaların SHA-256 değerleri, kaynak Git tree kimliği ve runtime kaynağı. Manifest kendi kendisini doğrulamaz; güvenilir dağıtım kanalının veya imzalı yayının yerine geçmez. Bütünlük kontrolü, yerel dosyaları değiştirebilen saldırgana karşı sandbox garantisi değildir.

Başlatıcı çocuk süreçte `NODE_OPTIONS`, `NODE_PATH`, `OPENSSL_CONF`, `OPENSSL_MODULES`, `OPENSSL_ENGINES` değişkenlerini kaldırır. Böylece devralınmış preload/provider ayarları bu kitin çalışmasını değiştirmez; sistemin veya kullanıcının kalıcı ayarlarına dokunulmaz. Dosya yolları mevcut çalışma klasörüne göre çözülür. Binary ile birlikte sabitlenmiş Node güvenlik güncellemeleri için kitin tekrar derlenmesi gerekir.

## Gerçekte yapılan kontroller

Arşiv ayrı, boş bir geçici klasöre çıkarıldı; bütün manifest dosyaları, lisans ve runtime özetleri kontrol edildi. Çıkarılan `pqc.exe` ile doctor, 1 MiB+17 bayt dosya encrypt/decrypt, parola değişimi sonrası çözme ve ML-DSA imza doğrulama çalıştı. Dosya ve klasör adlarında boşluk, Türkçe karakter, `%` ve `&`; context/argv içinde tırnak, backslash, boş argüman, tab ve newline korundu. Ayrı bir test kopyasında ortamdan preload çalışmadığı ve bozuk runtime'ın çalıştırılmadan reddedildiği doğrulandı. Başarısız CLI işleminin çıkış kodu başlatıcıdan aynı şekilde geçti.

Alpha.4'te, önceki Node 24.16.0 runtime ile gerçek bir ConPTY terminal oturumunda Türkçe parola + onay ile anahtar üretildi ve parola ekrana yansımadı. Ayrı giriş Ctrl+C ile iptal edildi; çıkış kodu 130 oldu ve iptal edilen hedef dosyaları oluşmadı. Bunlar bu yerel Windows makinesindeki gözlemlerdir; tüm terminal uygulamaları, makineler veya platformlar için test sonucu değildir.

## Kaynaktan derleme

Tam kaynak checkout'u gerekir. `npm ci --ignore-scripts` sonrasında, incelenmiş proje değişikliklerini Git index'ine alın ve Windows x64 üzerinde:

```powershell
npm run build:windows-portable
```

Derleyici Node binary/NOTICE kaydını ağdan otomatik değiştirmez. Tam olarak sabitlenmiş resmî Node 24.22.1 x64 binary'siyle çalıştırılmalı; yerel özet veya yayıncı doğrulaması başarısızsa derleme durur. Sistem .NET Framework C# derleyicisi ve yerleşik Windows PowerShell modülleri kullanılır. Kurulum, yürütme politikası değişikliği veya güvenlik denetimi atlama yapılmaz. Hazır ZIP yalnız testleri geçtikten sonra `.artifacts/` içine yeni dosya olarak alınır; var olan arşivin üzerine yazılmaz. Kaynak klasöründe veya diğer dosyalarda recursive temizlik yapılmaz; yalnız bu çalışmanın oluşturduğu ve yolu doğrulanmış geçici klasörler temizlenir.

Tekrar doğrulama: `npm run test:windows-portable`. Bu araç yalnız çalışma alanının `.artifacts/` dizinindeki yerel adayları test etmek içindir. ZIP ayıklamada path traversal, aygıt adı, yinelenen hedef/link ve boyut sınırları kontrol edilir; gerçek çıkarılan bayt sayısı da sınırlıdır.
