# Birincil kaynak dizini ve araştırma notları

> İlk literatür taramasının tarihli kaydı. Sonraki uygulamada kullanılan sabit ACVP korpusu, test bağımlılıkları ve ölçümler [doğrulama raporunda](DOGRULAMA.md) kayıtlıdır.

**İnceleme tarihi:** 21 Ekim 2026. Bağlantılar ilgili kurum, araştırmacı, standart yayımlayıcısı veya projenin kendi kaynağına gider. İkincil haberler ve sosyal medya, teknik kararların dayanağı olarak kullanılmadı.

Bu dizin bütün literatürün tarandığı anlamına gelmez. Standartların ilgili bölümleri, yayın durumları ve araştırmaların ilgili açıklamaları incelendi; aşağıdaki makalelerin bütün ispatları bağımsız yeniden doğrulanmadı. Kaynak kodu denetimi yapılmadı. Bağlantıların değişen içeriği yerine uygulama aşamasında sürüm/commit sabitlenmeli.

## Standartlar ve güncel durum

| # | Kaynak | Araştırmada kullanımı |
|---|---|---|
| 1 | [FIPS 203 — ML-KEM PDF](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) | Halka, parametreler, boyutlar, implicit rejection; özellikle §6.3 ve Tablo 3 |
| 2 | [FIPS 203 yayın kaydı](https://csrc.nist.gov/pubs/fips/203/final) | Final statüsü ve errata bağlantısının varlığı |
| 3 | [FIPS 204 — ML-DSA PDF](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) | MLWE/SelfTargetMSIS, dış API ve Tablo 2 |
| 4 | [FIPS 204 yayın kaydı](https://csrc.nist.gov/pubs/fips/204/final) | Final statüsü ve errata bağlantısının varlığı |
| 5 | [FIPS 205 — SLH-DSA PDF](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf) | Hash tabanlı yapı, anahtar yapısı ve Tablo 2 |
| 6 | [SP 800-227 — KEM önerileri](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-227.pdf) | KEM, kimlik doğrulama ve §4.6 bileşik yapılar |
| 7 | [NIST PQC durum sayfası](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/Post-Quantum-Cryptography-Standardization?data1=v2) | ML-KEM/ML-DSA/SLH-DSA final; HQC seçilmiş; FIPS 206 geliştirme bilgisi |
| 8 | [NIST HQC seçim açıklaması, 11 Mart 2025](https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption) | Kod tabanlı alternatif seçiminin gerekçesi; ileriye dönük tarih tahminleri gerçekleşmiş sayılmadı |
| 9 | [NIST PQC FAQ](https://csrc.nist.gov/Projects/post-quantum-cryptography/faqs) | Grover/AES, kategori yorumları ve güncel uygulama açıklamaları |
| 10 | [NIST: What Is Post-Quantum Cryptography?](https://www.nist.gov/cybersecurity-and-privacy/what-post-quantum-cryptography) | Kuantum tehdidi ve geçiş çerçevesi |

## Matematik, saldırılar ve güvenlik analizleri

| # | Kaynak | Araştırmada kullanımı |
|---|---|---|
| 11 | [Shor — Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms](https://arxiv.org/abs/quant-ph/9508027) | Kuantum üzerinde çarpanlara ayırma/ayrık logaritma |
| 12 | [Grover — A fast quantum mechanical algorithm for database search](https://arxiv.org/abs/quant-ph/9605043) | Yapısız aramada karekök sorgu karmaşıklığı |
| 13 | [Regev — On Lattices, Learning with Errors, Random Linear Codes, and Cryptography](https://cims.nyu.edu/~regev/papers/qcrypto.pdf) | LWE ve en kötü durum kafes problemlerine ilişkin indirgeme |
| 14 | [Langlois–Stehlé — Worst-Case to Average-Case Reductions for Module Lattices](https://eprint.iacr.org/2012/090) | Genel/ideal/modül kafes varsayımlarının ayrımı |
| 15 | [Kyber spesifikasyonu v3.02, 4 Ağustos 2021](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf) | Tarihsel tasarım, QROM ve çözme hatası tartışması; güncel FIPS'in yerine kullanılmadı |
| 16 | [Giacon–Heuer–Poettering — KEM Combiners](https://eprint.iacr.org/2018/024) | Bileşenlerden en az biri güvenliyken güvenli kalan yapıların koşulları |
| 17 | [Barbosa ve diğerleri — X-Wing](https://eprint.iacr.org/2024/039) | Özgül klasik+PQC birleşimi ve güvenlik analizi |
| 18 | [Castryck–Decru — An efficient key recovery attack on SIDH](https://eprint.iacr.org/2022/975.pdf) | Matematiksel kriptanaliz örneği; bütün izojeni ailesine genellenmedi |
| 19 | [KyberSlash araştırma makalesi](https://kyberslash.cr.yp.to/kyberslash-20250115.pdf) | Uygulamadaki sırra bağlı bölme süreleri |
| 20 | [KyberSlash gösterimleri](https://kyberslash.cr.yp.to/demos.html) | Anahtar kurtarma gösterimlerinin kapsamı; burada çalıştırılmadı |
| 21 | [HQC ekibi](https://pqc-hqc.org/) | QCSD dayanağı; sayfadaki performans sayıları kendi ölçümümüz gibi kullanılmadı |

## Protokol ve yardımcı yapıtaşları

| # | Kaynak | Araştırmada kullanımı |
|---|---|---|
| 22 | [RFC 10024 — PQ/T Hybrid Key Agreement for TLS 1.3](https://www.rfc-editor.org/rfc/rfc10024.html) | Ağustos 2026 yayımlanmış belge; özellikle §6'daki TLS transcript bağımlılığı |
| 23 | [RFC 9954 — Hybrid Key Exchange in TLS 1.3](https://www.rfc-editor.org/rfc/rfc9954.html) | Temmuz 2026 tarihli bilgilendirici TLS hibrit tasarım çerçevesi |
| 24 | [X-Wing Internet-Draft sürüm 11](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-11) | İncelenen sayfada aktif bireysel taslak; RFC diye etiketlenmedi |
| 25 | [RFC 9180 — HPKE](https://www.rfc-editor.org/rfc/rfc9180.html) | KEM/KDF/AEAD ayrımı; forward secrecy, replay ve metadata sınırları |
| 26 | [RFC 5869 — HKDF](https://www.rfc-editor.org/rfc/rfc5869.html) | Extract/Expand ve anahtar türetme |
| 27 | [NIST SP 800-38D — GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final) | AEAD/GCM standardı ve nonce gereksinimlerine temel |
| 28 | [RFC 8452 — AES-GCM-SIV](https://www.rfc-editor.org/rfc/rfc8452.html) | Nonce tekrarına dayanıklılığın anlamı ve sınırları |
| 29 | [RFC 9106 — Argon2](https://www.rfc-editor.org/rfc/rfc9106.html) | Paroladan anahtar üretme için ayrı bellek maliyetli katman |

## Uygulamalar, doğrulama ve lisans terimleri

| # | Kaynak | Araştırmada kullanımı |
|---|---|---|
| 30 | [Lattice Estimator](https://github.com/malb/lattice-estimator) | Saldırı aileleri, maliyet modeli farkı ve commit kaydetme gereği; çalıştırılmadı |
| 31 | [mlkem-native README](https://github.com/pq-code-package/mlkem-native/blob/main/README.md) | Sağlayıcı adayı ve projenin kendi doğrulama kapsamı açıklaması |
| 32 | [mlkem-native SOUNDNESS](https://github.com/pq-code-package/mlkem-native/blob/main/SOUNDNESS.md) | Formel doğrulamanın varsayımları ve kapsam dışı alanları |
| 33 | [liboqs README](https://github.com/open-quantum-safe/liboqs) | Prototip/araştırma amacı ve üretim/hassas veri kullanımına ilişkin kendi uyarısı |
| 34 | [Open Quantum Safe — liboqs](https://openquantumsafe.org/liboqs/) | Ortak API, test ve benchmark altyapısının rolü |
| 35 | [NIST ACVP vektör dizini](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files) | İleride sabitlenecek resmi test korpusunun başlangıç kaynağı; dosyalar henüz indirilmedi |
| 36 | [OSI — Open Source Definition](https://opensource.org/osd) | Madde 6: kullanım alanına göre kısıtlama yasağı; ticari kullanım tercihiyle terminoloji ayrımı |
| 37 | [OSI FAQ](https://opensource.org/faq) | Açık kaynak yazılımın ticari amaçla kullanılabilmesine ilişkin açıklama |

## Doğrulama sınırları ve izlenecek değişiklikler

- FIPS 203/204 errata dosyalarının bağlantısı ve güncelleme notları görüldü; elektronik tabloların içeriği burada ayrıntılı çözülmedi.
- HQC için standardizasyona seçim doğrulandı; final HQC FIPS belgesi bu taramada doğrulanmadı. Eski haberdeki hedef tarih güncel tamamlanma kanıtı değildir.
- FIPS 206/FN-DSA mevcut çekirdeğe final standart olarak eklenmedi.
- Arama sonuçları eski TLS taslaklarına götürebiliyor. ECDHE–ML-KEM için son durum RFC 10024 kaynağından kontrol edildi. Ayrı X-Wing taslağının durumu bununla karıştırılmadı.
- Hiçbir araç kurulmadı, saldırı demonstrasyonu çalıştırılmadı, güvenlik gücü tahmini veya cihaz benchmark'ı üretilmedi.
- Bu inceleme bütün CVE'leri veya 2026'daki tüm akademik yayınları kapsayan sistematik bir derleme değildir. Sağlayıcı seçimi öncesinde güncel güvenlik duyuruları ve parametre analizleri ayrıca taranmalı.
- GitHub deposu oluşturulmadı veya yayın yapılmadı. Nihai lisans metni hazırlanmadı; kullanıcının ticari kullanım yasağı tercihi tasarım niyeti olarak kaydedildi.
