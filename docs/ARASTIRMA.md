# Kuantum sonrası kriptografi: matematik ve sistem tasarımı araştırması

> Bu belge ilk araştırma aşamasının kaydıdır. Sonraki çalışan alpha ve test durumu için [README](../README.md) ve [doğrulama raporuna](DOGRULAMA.md) bakın.

**Araştırma tarihi:** 21 Ekim 2026, Europe/Istanbul  
**Kapsam:** Genel amaçlı kriptografi kütüphanesi için ilk literatür ve mimari değerlendirme  
**Kanıt durumu:** Kaynak incelemesi yapıldı; bağımsız kriptanaliz, uygulama denetimi, benchmark veya yeni güvenlik ispatı yapılmadı.

## 1. Hedefi bilimsel olarak tanımlamak

“Evrenin en iyi” veya “mükemmel” şifrelemesini ölçen evrensel bir sıralama yok. Güvenlik; saldırganın hesaplama gücüne, erişim türüne, anahtar yönetimine, kullanılan matematiksel varsayımlara ve uygulamaya bağlıdır. Hız, anahtar boyutu, donanım gereksinimi ve farklı varsayımlarla koruma arasında da ödünleşimler vardır.

Proje için önerim: **Varsayımları açık, kuantum sonrası yapıtaşları kullanan, yanlış kullanımı zorlaştıran, bağımsız uygulanabilen ve dışarıdan incelenebilen bir kütüphane.** Bu bir tasarım hedefidir; bugün elde edilmiş bir güvenlik sonucu değildir.

İki araştırma yolu ayrı ilerlemeli:

1. **Üretime aday mühendislik:** Standart algoritmalar, açık biçimler, güvenli API, birlikte çalışabilirlik ve uygulama incelemesi.
2. **Özgün kriptografi:** Yeni problem veya yapı önerileri, ayrıntılı tanımlar, indirgemeler, parametre analizi ve kamuya açık kriptanaliz. Bu alandaki sonuçlar değerlendirilmeden varsayılan korumaya dönüştürülmemeli.

İlk yol ikinci yolu engellemez. Yeni bir algoritmanın faydasını karşılaştırabilmek için de sağlam bir referans tabanı gerekir.

## 2. Kuantum tehdidi tam olarak nedir?

Shor'un çalışması çarpanlara ayırma ve ayrık logaritma için kuantum üzerinde polinom zamanda algoritmalar verir. Yeterli ölçek ve hata düzeltmeye sahip bir kuantum bilgisayar varsayımında RSA ve alışılmış ayrık logaritma temelli anahtar paylaşımı/imza sistemleri risk altındadır. RSA anahtarını büyütmek veya yalnızca eğri değiştirmek bu yapısal sorunu gidermez. [Shor](https://arxiv.org/abs/quant-ph/9508027)

Grover'ın algoritması farklıdır: Yapısız bir N elemanlı aramada yaklaşık karekök ölçeğinde sorgu karmaşıklığı sağlar. İdeal anahtar aramasında 256 bit anahtar için yaklaşık 2^128 oracle çağrısı sezgisi buradan gelir. Bu sayı gerçek saldırının süresi, fiziksel kübit sayısı veya maliyeti değildir; tersinir devre, hata düzeltme ve paralelleştirme maliyetleri ayrıca değerlendirilir. [Grover](https://arxiv.org/abs/quant-ph/9605043), [NIST'in AES değerlendirmesi](https://csrc.nist.gov/Projects/post-quantum-cryptography/faqs)

Bu nedenle AES-256 anlamlı bir adaydır. Ancak “256 bit anahtar”, bütün sistemin her saldırıya karşı 256 bit güvenliği olduğu anlamına gelmez. Örneğin 128 bit doğrulama etiketi, anahtar aramasıyla aynı güvenlik ölçüsü değildir; sahtecilik sınırları deneme sayısı ve veri hacmiyle de değişir.

Bugün kaydedilip gelecekte çözülmesi istenen trafik için gizlilik süresi önemlidir. İleride aktif kuantum saldırganına karşı kimlik doğrulama da istiyorsak yalnızca anahtar paylaşımını değiştirmek yetmez; kimlik anahtarlarının güvenilir bağlanması da kuantum sonrası modele uymalıdır. [NIST PQC açıklaması](https://www.nist.gov/cybersecurity-and-privacy/what-post-quantum-cryptography)

## 3. Matematiksel dayanak I: kafesler, LWE ve Module-LWE

### Gürültülü doğrusal denklemler

LWE'nin öğretici biçimi:

```text
b = A·s + e  (mod q)

A: kamuya açık matris
s: gizli vektör
e: uygun dağılımdan örneklenen küçük hata vektörü
q: modül
```

Hatasız durumda uygun koşullarda doğrusal cebirle çözülebilen sistem, hata eklendiğinde farklı bir hesaplama problemine dönüşür. Arama sürümü gizli s'yi bulmayı, karar sürümü örneklerin düzgün rastgele örneklerden ayırt edilmesini sorar. “Gürültü varsa her sistem güvenlidir” sonucu çıkmaz; boyut, modül, örnek sayısı ve dağılımlar belirleyicidir. Regev'in çalışması belirli koşullarda en kötü durum kafes problemleriyle LWE arasında kuantum indirgemeleri kurar. Bu, her somut parametre seçiminin koşulsuz güvenlik ispatı değildir. [Regev](https://cims.nyu.edu/~regev/papers/qcrypto.pdf)

Module-LWE hesapları polinom halkaları üzerindeki modüllere taşır. ML-KEM'de kullanılan halka:

```text
R_q = Z_q[X] / (X^256 + 1),   q = 3329
```

Öğretici düzeyde yine `t = A·s + e` düşünülür; elemanlar artık halkadadır. Polinom/modül yapısı verimlilik sağlar, fakat varsayımın yapısını da belirler. Genel LWE ile Module-LWE'yi aynı güvenlik teoremi gibi kullanamayız. Modül kafeslerine ilişkin indirgemeler ayrı incelenir. [Langlois–Stehlé](https://eprint.iacr.org/2012/090), [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)

Saldırı araştırması en az şu başlıkları kapsamalı: primal ve dual kafes saldırıları, BKZ/sieving maliyet modelleri, hibrit tahmin saldırıları, çok hedefli saldırılar, cebirsel yapı ve çözme hatalarından bilgi edinme. Aynı parametre için farklı maliyet modellerinin farklı sonuç üretmesi beklenebilir. Lattice Estimator kendi belgelerinde model ve sürüm farklarını açıklar; bir çıktı “kırılmazlık belgesi” değildir. [Lattice Estimator](https://github.com/malb/lattice-estimator)

### Teorem ile gerçek sistem arasındaki mesafe

Bir indirgeme, saldırıyı başka bir problemi çözmeye dönüştürür; kullanılan varsayım ve model altında anlamlıdır. Random oracle modeli hash'i idealize eder; kuantum random oracle modeli kuantum sorgularını hesaba katar. Bunlar gerçek SHA-3 üzerinde bütün saldırıların imkânsız olduğunu göstermez.

Kyber'in tasarım belgesinde kuantum random oracle indirgemesinin sıkılığı ve çözme hatasının güvenlik sınırına katkısı özellikle tartışılır. Bu tarihsel belge ML-KEM'in soyunu anlamak içindir; eski Kyber kodu veya test vektörü FIPS 203 ile otomatik olarak aynı kabul edilmemeli. [Kyber tasarım belgesi, §4–5](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)

## 4. Matematiksel dayanak II: imzalar ve farklı varsayımlar

ML-DSA, kafes tabanlı bir dijital imzadır; güvenlik dayanakları MLWE ve SelfTargetMSIS'i içerir. İmza mesajı saklamaz: Mesajın belirli bir anahtar tarafından onaylandığının doğrulanmasına yarar. Anahtarın gerçek bir kişiye veya kuruma ait olduğunu ayrıca güvenilir şekilde öğrenmek gerekir. [FIPS 204, §3](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)

SIS'i anlamak için öğretici problem:

```text
Kamuya açık A için,
A·z = 0 (mod q) sağlayan, sıfır olmayan, yeterince kısa z bul.
```

Boyut ve norm sınırı olmadan bu ifade güvenlik tanımı değildir. ML-DSA'nın tamamını bu tek denkleme indirgemek de doğru olmaz; imzanın örnekleme, challenge, norm kontrolü ve kodlama kuralları bütünün parçasıdır.

SLH-DSA farklı bir aileden, hash tabanlı imzadır. WOTS+, FORS ve Merkle/hypertree yapıları kullanır; üst düzey API kullanıcıdan her imzada kalıcı bir sayaç yönetmesini istemez. Bu, rastgelelik, kullanım limitleri ve uygulama güvenliğinin önemsizleşmesi anlamına gelmez. Kafes varsayımlarına karşı çeşitlilik için değerlidir; imzaları daha büyüktür. [FIPS 205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)

Önerim: ML-DSA'yı genel imza adayı olarak, SLH-DSA'yı seyrek imzalanan sürüm manifestleri ve güven kökleri gibi işler için değerlendirmek. Bunlar kullanım alanına ilişkin proje önerileridir.

HQC ise kod tabanlı bir KEM'dir; ekibin açıklaması dayanağı Quasi-Cyclic Syndrome Decoding olarak verir. Öğretici sendrom çözme probleminde, `H·e^T = y` sağlayan ve Hamming ağırlığı sınırlı bir hata vektörü aranır. Bu ifade HQC'nin tam spesifikasyonu veya güvenlik ispatı değildir. [HQC ekibi](https://pqc-hqc.org/)

NIST, HQC'yi 11 Mart 2025'te standardizasyon için seçti. İncelenen NIST durum sayfası seçilmiş olduğunu belirtiyor; bu araştırmada tamamlanmış bir HQC FIPS standardı doğrulanmadı. Bu nedenle kararlı çekirdeğe girecek tamamlanmış standart gibi davranmıyorum. [NIST seçim açıklaması](https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption), [NIST durum sayfası](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/Post-Quantum-Cryptography-Standardization?data1=v2)

## 5. Adaylar ve somut boyutlar

Boyutlar aşağıdaki standart tablolarından bayt cinsindendir; kapsayıcı biçim, sertifika veya protokol ek yükü dahil değildir. Gizli anahtarlar tabloların genişletilmiş gösterimidir; seed ile saklama farklı bir gösterimdir.

| Yapıtaşı | İşlev | NIST kategorisi | Açık anahtar | Gizli anahtar | KEM ciphertext / imza |
|---|---|---:|---:|---:|---:|
| ML-KEM-768 | Ortak sır kurma | 3 | 1184 | 2400 | 1088 |
| ML-KEM-1024 | Ortak sır kurma | 5 | 1568 | 3168 | 1568 |
| ML-DSA-65 | İmza | 3 | 1952 | 4032 | 3309 |
| ML-DSA-87 | İmza | 5 | 2592 | 4896 | 4627 |
| SLH-DSA-SHAKE-256s | İmza | 5 | 64 | 128 | 29792 |

Kaynaklar: [FIPS 203, Tablo 3](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf), [FIPS 204, Tablo 2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf), [FIPS 205, §9 ve Tablo 2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf).

ML-KEM ortak sırrı her iki parametre setinde de 32 bayttır. 768/1024 adları anahtarın bit uzunluğu veya kuantum güvenliğinin bit sayısı değildir. Kategori 5 de “256 kuantum güvenlik biti” demek değildir. Kategoriler referans saldırı maliyetleriyle tanımlanır; bütün protokole doğrudan taşınamaz.

Bu projedeki güvenlik önceliği nedeniyle **ML-KEM-1024 ve ML-DSA-87 başlangıç değerlendirme adaylarıdır**. Mobilde gecikme, bellek ve pil ölçülmeden her ortam için üstün oldukları söylenemez. Kategori 3 seçeneği de ölçüm ve politika tartışmasına açık tutulmalı.

## 6. KEM + KDF + AEAD: gerekli ayrım

Genel bir KEM arayüzü:

```text
(pk, sk) = KeyGen()
(ct_kem, shared_secret) = Encaps(pk)
shared_secret' = Decaps(sk, ct_kem)
```

KEM bir dosyayı doğrudan şifreleyen API değildir. Ortak sır üretir. Uygun KDF anahtarları türetir; AEAD veriyi şifreler ve bütünlük denetimi sağlar. KEM kimlik doğrulamayı veya karşı tarafın anahtarı aldığının teyidini kendiliğinden sağlamaz. [NIST SP 800-227](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-227.pdf)

HKDF'nin Extract ve Expand aşamaları bu ayrım için incelenebilir. Proje düzeyindeki türetmede amaç etiketleri, sürüm, profil ve uygulama bağlamı açıkça tanımlanmalı. Farklı amaçların anahtarları ayrılmalı. HKDF eksik entropiyi veya tahmin edilebilir bir parolayı güçlü rastgele anahtara dönüştürmez. [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html)

AES-256-GCM için nonce yönetimi zorunlu bir tasarım unsurudur. Aynı anahtar altında tekrar önlenmeli; uygulama her çağrıda rastgele nonce seçmekle yetinmemeli. Tasarımımız anahtar başına veri/işlem sınırlarını ve yeniden anahtarlamayı da belirtmeli. Doğrulama tamamlanmadan plaintext çağırana verilmemeli. [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)

Nonce hata riskini azaltan bir seçenek olarak AES-256-GCM-SIV ayrıca karşılaştırılabilir. Tekrar halinde felaket etkisini sınırlandırmak için tasarlanmıştır; tekrarın zararsız olduğu anlamına gelmez. Aynı girdilerin tekrarının anlaşılması gibi sızıntılar ve kullanım sınırları vardır. Seçim, bağımsız uygulama desteği ve performansla beraber yapılmalı. [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452.html)

Parolayla anahtar koruma gerekiyorsa Argon2id ayrı bir katman olmalı. Bellek ve süre ayarları hedef cihazda ölçülmeli; rastgele salt kullanılmalı; saldırgan kontrollü aşırı kaynak ayarlarına sınır konmalı. Parolanın düşük tahmin maliyeti, yüksek güvenlikli KEM seçilmesiyle düzelmez. [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)

## 7. Hibrit tasarım: yararlı, fakat otomatik bir güvenlik çarpanı değil

### Klasik + kuantum sonrası

X25519 + ML-KEM gibi bir birleşim, doğru inşa altında farklı saldırılara karşı geçiş koruması sunabilir. X25519 kuantuma dayanıklı ikinci bir katman değildir. Kuantum saldırganı klasik kısmı çözebiliyorsa gizlilik için kuantum sonrası kısma ve birleşimin güvenliğine dayanırız.

Güncel durum önemli: TLS için ECDHE–ML-KEM birleşimleri Ağustos 2026 tarihli **RFC 10024** içinde yayımlanmış. Belgede güvenlik analizinin TLS 1.3 transcript'ine bağlı olduğu ve aynı hibritleştirmenin başka protokollerde güvenli varsayılamayacağı açıkça belirtiliyor. TLS içindeki bir sıralamayı alıp genel kütüphanede yeni bir KEM gibi sunmamalıyız. [RFC 10024, §6](https://www.rfc-editor.org/rfc/rfc10024.html)

Genel amaçlı birleşim için X-Wing de araştırma adayıdır. X25519 ve ML-KEM-768 kullanır; özgül bir güvenlik analizi vardır. İncelenen `draft-connolly-cfrg-xwing-kem-11` sayfası bunu aktif bireysel Internet-Draft olarak gösteriyor; yayımlanmış RFC diye sunulmamalı. [X-Wing makalesi](https://eprint.iacr.org/2024/039), [sürüm 11 taslağı](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-11)

### İki kuantum sonrası aile

ML-KEM + HQC gibi bir birleşim, kafes ve kod varsayımları arasında çeşitlilik sağlayabilecek bir araştırma yönüdür. Ortak RNG, hash, derleyici veya anahtar saklama hataları iki tarafı birlikte etkileyebilir. Ek algoritma ek saldırı yüzeyi ve biçim karmaşıklığı da getirir.

KEM birleştirici literatürü, en az bir bileşen güvenliyken birleşimin güvenli kalmasını hangi tanımlar ve koşullar altında sağlayabileceğimizi inceler. `Hash(ss1 || ss2)` veya `ss1 XOR ss2` ifadesini tek başına yazmak yeterli analiz değildir. Ciphertext'ler, açık anahtarlar, kodlama, saldırganın seçebildiği girdiler ve hata davranışı dikkate alınmalı. [Giacon–Heuer–Poettering](https://eprint.iacr.org/2018/024)

Bu nedenle bu rapor yeni bir combiner tarifi vermiyor. Seçilen somut yapı için kaynak teoremi, güvenlik modeli, giriş kodlaması ve uygulama eşleşmesi ayrı bir inceleme teslimatı olmalı.

### Çift imza

ML-DSA ve SLH-DSA'nın birlikte kullanıldığı deneysel bir politikada, aynı kanonik mesaj ve bağlam üzerinde **iki imzanın da doğrulanması** hedeflenebilir. “İkisinden biri geçerli” politikası güçlü olanı atlatabilir. Güven köklerinin bağlanması, profil silme saldırıları ve ortak bileşenler ayrıca incelenmeli. Bu fikir mevcut bir birleşik protokolün kanıtı değildir.

## 8. Bilinen saldırılardan çıkarılacak dersler

**SIKE/SIDH:** Castryck–Decru çalışması SIDH için etkili bir anahtar kurtarma saldırısı sundu. Buradaki ders, kuantum sonrası adayın klasik matematiksel bir saldırıyla da bozulabileceğidir. Sonucu bütün izojeni tabanlı kriptografiye genelleştirmek doğru değildir. [Saldırı makalesi](https://eprint.iacr.org/2022/975.pdf)

**KyberSlash:** Belirli Kyber uygulamalarında sırra bağlı bölme süreleri üzerinden anahtar kurtarma gösterildi. Bu, Module-LWE probleminin çözüldüğünü göstermez. Güvenli matematik ile güvenli makine kodu farklı değerlendirmelerdir. “Kaynak kodunda if yok” demek sabit zamanlılık kanıtı değildir. [KyberSlash araştırması](https://kyberslash.cr.yp.to/kyberslash-20250115.pdf), [çalıştırılabilir gösterimler](https://kyberslash.cr.yp.to/demos.html)

**Hata oracle'ları:** ML-KEM'in implicit rejection davranışı korunmalı. Doğru uzunluktaki geçersiz ciphertext'in içeride reddedildiğini dışarıya bir bayrakla bildirmek izin verilen davranış değildir. Yanlış uzunluk gibi açık biçim hatalarıyla gizli doğrulama sonucunun ayrımı standarttan izlenmeli. [FIPS 203, §6.3](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)

**Bileşimin sınırları:** HPKE belgesi, alıcının uzun dönem anahtarı ele geçirildiğinde geçmiş ciphertext'ler için forward secrecy sağlamadığını açıklar. Replay ve metadata gizleme de kendiliğinden kazanılmaz. HPKE'deki “hybrid” ifadesi KEM/KDF/AEAD yapısını ifade eder; mutlaka klasik + kuantum sonrası birleşim anlamına gelmez. [RFC 9180, §9](https://www.rfc-editor.org/rfc/rfc9180.html)

## 9. Uygulama seçimi ve biçimsel doğrulamanın sınırı

Önce var olan sağlayıcılar karşılaştırılmalı. mlkem-native; C bellek/tamsayı güvenliği ve belirli assembly kodları için doğruluk/sabit zamanlılık çalışmalarını belgeliyor. SOUNDNESS dosyası kanıt kapsamını ve açık kalan varsayımları ayrıca açıklıyor. “Formel doğrulanmış” etiketini bütün kütüphane, bütün derleyiciler ve fiziksel yan kanallar için sınırsız garantiye dönüştüremeyiz. [mlkem-native](https://github.com/pq-code-package/mlkem-native/blob/main/README.md), [kanıt kapsamı](https://github.com/pq-code-package/mlkem-native/blob/main/SOUNDNESS.md)

liboqs karşılaştırma, birlikte çalışabilirlik ve prototip için değerlidir. Ancak incelenen kendi README'si üretimde veya hassas veriyi korumakta kullanılmasını önermediğini açıkça söylüyor. Bu nedenle yalnızca “PQC destekliyor” diye yüksek güvenlikli üretim sağlayıcısı olarak seçilmemeli. [liboqs uyarısı](https://github.com/open-quantum-safe/liboqs)

Bu araştırma belirli bir sağlayıcı sürümünü onaylamaz. Seçim aşamasında commit/sürüm, imzalı yayın, hedef mimari, derleyici, güvenlik duyuruları, lisans ve test sonuçları sabitlenmeli.

## 10. Önerilen yön ve henüz çözülmemiş kararlar

Benim başlangıç önerim, standart ML-KEM/ML-DSA işlemleri ve güvenli simetrik şifreleme arayüzüyle küçük bir çekirdek tasarlamak. Tam bir oturum protokolü ve yeni bir public-key envelope aynı teslimatta aceleyle standardize edilmemeli.

Araştırma açıkları: Yüksek seviyeli şifreleme profilinin tam spesifikasyonu, seçilecek combiner, alıcı kimliğinin doğrulanma yöntemi, nonce/key yaşam döngüsü, key commitment ihtiyacı, mobil/masaüstü sağlayıcı seçimi ve ticari kullanım kısıtının kesin lisans metni.

FIPS 203 ve FIPS 204 yayın sayfalarında errata bağlantıları var. Bunların varlığı doğrulandı; xlsx içerikleri bu çalışmada ayrıntılı işlenmedi. Uygulama öncesi incelemede spesifikasyonla beraber ele alınmalılar. HQC/FN-DSA için gelecekte tamamlanması beklenen bir standardı tamamlanmış kabul etmedim. [FIPS 203 yayın kaydı](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204 yayın kaydı](https://csrc.nist.gov/pubs/fips/204/final)

Sonraki somut çalışma, [kütüphane planındaki](KUTUPHANE-PLANI.md) güvenlik sözleşmesini ve deneyleri tamamlamak. **Bugünkü sonuç yeni ve kırılmaz bir algoritma değil; hangi varsayımlara güveneceğimizi, hangi iddiaları sınayacağımızı ve hangi hatalardan kaçınacağımızı belirleyen araştırma temelidir.**
