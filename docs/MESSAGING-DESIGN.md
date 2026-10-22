# Mesajlaşma modülü: tasarım kapısı — 22 Ekim 2026

Bu belge uygulanmış bir sohbet protokolü değildir. Mevcut SDK KEM/KDF/AEAD ve ayrı imza primitive'leri sunar; süreç içi mesaj örneği vardır. İletişim ağı, oturum deposu, prekey sunucusu, replay koruması veya ratchet uygulanmadı. Kullanıcı hedefi geliştiricilerin uygulamalara gömebildiği SDK'dır.

## Araştırma kararı

Tek bir statik alıcı anahtarına her mesajı şifrelemek ile tam güvenli mesajlaşma farklı kabul ölçütleridir. [Signal PQXDH](https://signal.org/docs/specifications/pqxdh/) revizyon 3, çevrimdışı alıcı için başlangıç anahtar anlaşması ve kimlik bağlamasını ele alır; kendi belgesinde kimlik doğrulamanın bu revizyonda klasik ayrık log varsayımına bağlı olduğunu belirtir. [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) revizyon 4, mesaj anahtarları, sıra dışı teslim ve post-quantum/triple-ratchet bölümlerini ayrı tanımlar. Bunlar 22 Ekim 2026'da okunan birincil tasarım kaynaklarıdır; kütüphanemiz bu protokolleri uygulamış veya bunlarla uyumlu sayılmaz.

Bu tur için karar: JSON sarmalayıcıya "tam protokol" adı vermek yerine, mevcut bir protokol/sağlayıcı seçimi ve sürümlü uyumluluk incelemesi tamamlanana kadar yüksek seviyeli sohbet API'sini kararlılaştırmamak. Mevcut ML-KEM handle'ını PQXDH örneğindeki KEM'e otomatik takmak için güvenlik/encoding eşdeğerliği varsayılmayacak.

## Uygulama öncesi teslimatlar

| Alan | Verilecek somut karar / test |
| --- | --- |
| Kimlik | Kullanıcı/cihaz anahtarı, bağımsız doğrulama ve anahtar değişimi; sunucunun yanlış anahtar sunması |
| Oturum kurulumu | Çevrimdışı alıcı, imzalı/tek kullanımlık prekey, tüketimin atomikliği ve replay |
| Mesaj durumu | Gönderici/alıcı yön bağlaması, sayaç, out-of-order/duplicate ve azami skipped-key bütçesi |
| Ratchet | Sağlayıcı/protokol sürümü, yeniden anahtarlama, ele geçirme sonrası sınırlar; hangi kuantum saldırgan modeli |
| Kalıcı durum | Transaction/crash recovery, aynı anahtar durumundan iki mesaj üretmeme, yedek/rollback ve çok cihaz |
| Ağ ve ayrıştırma | Sürümlü kanonik encoding, azami envelope/alan boyutu, bilinmeyen sürüm ve keyfi yük reddi |
| Kaynak sınırı | Oturum/cihaz başına limit, KEM/ratchet kuyruğu, tekrarlı/sıra dışı paket DoS testleri |
| Doğrulama | Resmi/bağımsız test vektörleri, iki uçlu uyumluluk ve bağımsız tasarım/uygulama incelemesi |

Önce bire bir ve tek cihaz kapsamı için protokol/sağlayıcı kararı hazırlanmalı; grup sohbeti ve çok cihaz ayrı aşama olmalıdır. API adları ve wire format bu karar olmadan sabitlenmez. İlk kabul koşulu; iki istemci çevrimdışı başlangıç, duplicate/out-of-order teslim ve çökme/yeniden başlatma senaryolarını geçerken kaynak bütçesini korumasıdır. Bunlar bu alpha'nın tamamlanmış özellikleri değildir.
