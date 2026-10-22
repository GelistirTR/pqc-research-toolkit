# Güvenlik durumu

Alpha.12 hesap parolası hash/doğrulama API'si ekler. Yalnız iki allowlisted Argon2id profili ve kanonik PHC kabul edilir. Kasa ve hesap parolaları ortak modül-örneği Argon2 bütçesini paylaşır; diğer worker/süreçler sınır dışıdır. Parola politikası, DB güvenliği, kullanıcı varlığı sızıntısı, rate limit ve auth oturumu uygulama sorumluluğudur. [Hesap API sözleşmesi](docs/ACCOUNT-PASSWORDS.md), [mesajlaşma tasarım kapısı](docs/MESSAGING-DESIGN.md).

Bu alpha, bağımsız kriptografik tasarım veya uygulama denetiminden geçmedi. Hassas üretim verileri için hazır olduğu iddia edilmiyor. NIST standart algoritmaları kullanılması kütüphanenin veya dağıtılan Node modülünün FIPS sertifikalı olduğu anlamına gelmez.

Desteklenen ilk çalışma zamanı Node.js 24.22.1+ / 24.x, yerelde test edilen ortam Windows x64'tür. Dağıtılan runtime'ın OpenSSL ve Node güvenlik yamaları işletmecinin sorumluluğundadır. Node'un KEM API'sinin belgelenen kararlılık durumu da bağımlılık kararında dikkate alınmalıdır: [Node 24 crypto](https://nodejs.org/docs/latest-v24.x/api/crypto.html).

Sınırlar ve tam alpha akışı: [CORE-SPEC](docs/CORE-SPEC.md). Bu sürüm replay koruması, forward secrecy, ele geçirme sonrası toparlanma, alıcı kimliği keşfi, anonimlik veya donanım yan kanal garantisi sağlamaz. Bellek temizleme best-effort düzeyindedir; güvenilir JS süreci ve runtime varsayılır.

0.2'deki [dosya](docs/FILE-FORMAT.md) ve [anahtar kasası](docs/KEY-VAULT.md) kapsayıcıları da deneysel tasarımlardır. Dosya hedefi ancak tüm doğrulama sonrası oluşturulur; doğrulanmış parçalar bu sırada özel geçici klasörde plaintext olarak diske yazılır. Process/OS çökmesi veya temizlik hatasında geçici kopyalar kalabilir. Windows'ta üst klasör ACL'leri belirleyicidir. Mevcut hedefler değiştirilmez ve hard link desteği gereklidir. Parola koruması zayıf parolayı veya çevrimdışı tahmini ortadan kaldırmaz. Alpha.5 kasa KDF'sini modül örneği başına 2 başlatılmış ve 16 FIFO bekleyen işle sınırlar; taşma `RESOURCE_LIMIT` döndürür. Bu süreç/worker geneli bir bütçe değildir; servis katmanında ayrıca rate ve toplam kaynak sınırı gerekir.

Proje deposu: [GelistirTR/pqc-research-toolkit](https://github.com/GelistirTR/pqc-research-toolkit). Güvenlik açığı ayrıntılarını, özel anahtarları veya gerçek kullanıcı verilerini public issue'lara eklemeyin. GitHub Security sekmesinde özel bildirim seçeneği varsa onu kullanın; bu seçenek yoksa mevcut özel iletişim kanalından proje sahibine ulaşın. Kalıcı özel bildirim kanalının kurulması yayın sonrası önceliktir.

Test başarısı, rastgelelik testleri ve benchmark sonuçları bir güvenlik kanıtı değildir. Yeni yüksek seviyeli format veya hibrit birleşim, tasarımı ve güvenlik argümanı incelenmeden kararlı API'ye eklenmemelidir.

Alpha.8 minimum runtime'ı Node 24.22.1'e yükseltir. Alpha.11 birleşik seed+expanded özel anahtarı varsayılan olarak reddeder; açık SDK geçiş seçeneği seed'i otoritatif kabul eder fakat companion tutarlılığı iddiası taşımaz. Tarihli kaynak doğrulaması, temsil/politika uyumluluğu ve güncelleme yükümlülüğü [runtime politikasındadır](docs/RUNTIME-POLICY.md).

Alpha.11 işlem havuzu isteğe bağlı ve örnek başına bir admission sınırıdır; doğrudan SDK çağrılarını, diğer havuzları veya worker/süreçleri kısıtlamaz. Aktif iptalde görev yerleşmeden rezervasyon bırakılmaz. Callback sinyali gerçek operasyona aktarmalıdır; yoksa yan etkiler tamamlandıktan sonra ABORTED alınabilir. Zorla süreç kapanması son hedefi oluşturmadan staging plaintext bırakabilir; bu durum gerçek alt süreç sonlandırmasıyla gözlendi. [Yerel inceleme](docs/SECURITY-REVIEW-ALPHA11.md) bağımsız denetim değildir.
