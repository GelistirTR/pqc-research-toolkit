# Karşılaştırma ve geliştirme kararları

Araştırma: 22 Ekim 2026. Bu karşılaştırma bir güvenlik sıralaması değildir. Farklı kullanım amaçlarını ayırır; protokol analizi, bağımsız denetim ve gerçek saldırı maliyeti ölçümü yapılmış gibi yorumlanmamalıdır.

| Proje / kapsam | Birincil kaynağın doğruladığı özellik | Bizim mevcut durumumuz ve çıkarım |
| --- | --- | --- |
| age 1.3 — dosya şifreleme | Yerleşik hibrit ML-KEM-768 alıcıları ve HPKE tabanlı tasarım. [Sürüm notları](https://github.com/FiloSottile/age/releases/tag/v1.3.0), [biçim tanımı](https://github.com/C2SP/C2SP/blob/main/age.md). | ML-KEM-1024 kullanıyoruz; klasik bileşenle hibrit değiliz ve age dosyalarıyla uyumlu değiliz. Daha büyük ML-KEM parametresi tüm uygulama için üstünlük kanıtlamaz. |
| OpenSSL 3.5 — kriptografik sağlayıcı | ML-KEM, ML-DSA ve SLH-DSA desteği. [Resmî duyuru](https://openssl-library.org/post/2025-04-08-openssl-35-final-release/), [ML-KEM belgesi](https://docs.openssl.org/3.5/man7/EVP_KEM-ML-KEM/). | Node üzerinden bu sağlayıcıya dayanıyoruz. Sağlayıcı algoritması ile bizim dosya/kasa biçimimizin güvenliği ayrı değerlendirilir; sağlayıcıyı kullanan wrapper bağımsız algoritmik yenilik değildir. |
| liboqs — PQC araştırma kütüphanesi | Ortak KEM/imza API'si, test ve benchmark araçları. Araştırma/prototipleme kapsamı açıkça belirtiliyor; bazı bölümleri için dış inceleme mevcut. [Kapsam](https://openquantumsafe.org/liboqs/), [güvenlik politikası](https://openquantumsafe.org/liboqs/security.html). | Algoritma çeşitliliği yerine dar bir profil ve dosya/CLI akışı sunuyoruz. liboqs kullanmıyoruz. Başka projenin denetimi bizim kodumuza güvenlik onayı sağlamaz. |
| Signal SPQR / Triple Ratchet — mesajlaşma | Post-quantum forward secrecy ve compromise sonrası toparlanmayı hedefleyen ratchet protokolü. [Duyuru](https://signal.org/blog/spqr/), [revizyon 4 teknik tanım](https://signal.org/docs/specifications/doubleratchet/). | Bizim kalıcı alıcı anahtarlı dosya şifrelememiz ratchet içermez. Anahtarın gelecekte ele geçirilmesine karşı geçmiş dosyalar için forward secrecy sunmuyoruz. Signal ile aynı tehdidi çözüyor gibi karşılaştırılamaz. |

## Matematiksel tasarımdan çıkan sonuçlar

[FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), ML-KEM'i ortak sır kurulumu için tanımlar. KEM, kendiliğinden alıcının kimliğini, gönderenin kimliğini, replay korumasını veya sonradan anahtar ele geçirilmesine dayanıklılığı sağlamaz. Parmak izinin güvenilir kanaldan karşılaştırılması ve ayrı imza kullanımı bu ayrımlar nedeniyle gereklidir. NIST sayfasındaki errata/güncelleme notu da standart izleme sürecine dahildir.

AES-256, ML-KEM-1024 ve ML-DSA-87 sayılarının büyük olması, bunların birleşimine tek bir evrensel “güvenlik puanı” vermez. Zayıf parola, yanlış public key, nonce tekrar kullanımı, doğrulamadan plaintext sunma veya sızan geçici dosya güçlü temel algoritmaları etkisiz bırakabilir. Bu sebeple mevcut uygulamada tek kullanımlık encryption handle, her dosya kaydına ayrı türetme, zorunlu tam parmak izi ve doğrulama sonrası yayın testlerine öncelik verildi.

Hibrit KEM'in amacı farklı matematiksel varsayımları birlikte kullanarak tek bir ailedeki beklenmeyen ilerlemeye karşı çeşitlilik sağlamaktır. Bu, iki sırrı gelişigüzel birleştirmekle elde edilen otomatik bir garanti değildir. Algoritma ve kimlik bağlama, KDF girdileri, domain separation, hatalı girdi davranışı, downgrade ve combiner'ın güvenlik argümanı birlikte belirlenmelidir. Şimdiki biçime sessizce X25519 eklemek yerine, ayrı suite/version ve yayımlanmış tasarım/test vektörleri üzerinde çalışılmalıdır.

## Uygulama sırası ve kabul ölçütleri

1. **Kurulumun doğrulanması:** kaynak testleri yanında kurulmuş tarball ile çalıştırma. Doctor yalnız işlevsel kontrol yapar; bağımsız denetim yerine geçmez. Bu aşama 0.3 alpha.2'de yerelde tamamlandı.
2. **Parser ve hata yolları:** deterministik mutasyon korpusunu genişlet, bounded fuzzing çalıştır, geçersiz başlık/uzunlukların KDF maliyeti veya plaintext yayınından önce reddedildiğini doğrula. Bunu bağımsız kriptanaliz olarak adlandırma.
3. **Yayın ve bakım:** kullanıcı yeniden yayın isterse üç platform CI sonuçları, temiz kaynak arşivi ve özel güvenlik bildirimi kanalını tamamla. Şu anda kullanıcı kararıyla yalnız yerelde çalışılıyor.
4. **Hibrit tasarım araştırması:** güncel yayımlanmış combiner/HPKE tasarımını seç, varsayımları ve wire formatı yaz, iki bağımsız uygulamayla vektörleri doğrula; dış inceleme olmadan kararlı veya üstün güvenlik iddiası yapma.
5. **Dağıtım öncesi inceleme:** bağımsız format/uygulama denetimi, yan kanal değerlendirmesi, işletim sistemi crash/staging senaryoları, kaynak tüketimi ve anahtar yedekleme/kurtarma tatbikatı. Bunlar henüz tamamlanmadı.

Bu liste mevcut eksikleri kapatmak içindir. Denetlenmemiş bir alpha'yı olgun sistemlerden daha güvenli ilan etmek için dayanak değildir.
