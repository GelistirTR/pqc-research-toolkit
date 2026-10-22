# Deneysel dosya biçimi v1

**Uygulama:** 0.3.0-alpha.12 (wire format v1 değişmedi) · **Durum:** Bağımsız tasarım denetimi ve bileşim ispatı yoktur. HPKE veya genel bir ağ protokolü değildir.

## İşlev ve güven modeli

`encryptFile` tek bir güvenilir ML-KEM-1024 alıcısına dosya şifreler. `decryptFile` dosyayı ayrı bir hedefe çözer. Bu API alıcının açık anahtarını kimin yayımladığını doğrulamaz; göndericiyi tanıtmaz, replay veya forward secrecy sağlamaz. İmza çekirdeği ayrı kalır.

Çağıran `inputPath`, `outputPath` ve beklenen `context` değerlerini sağlar. İsteğe bağlı `aad`, uygulamanın beklediği ilave veridir. Context/AAD şifreli dosyadan otomatik güvenilir kabul edilerek okunmaz. Klasörler ve aynı süreçteki kod güvenilir olmalıdır.

Dosya üst sınırı **64 GiB**; parça boyutu **64 KiB–4 MiB arası ikinin kuvveti**, varsayılan **1 MiB**. Bunlar bu alpha uygulamasının sınırlarıdır; bütün bu boyutlarda performans ölçüldüğü anlamına gelmez. Okuma/yazma parça parça yapılır; bütün dosya bir Buffer içine alınmaz.

## Sabit başlık

Bütün tamsayılar unsigned big-endian. Başlık tam **1656 bayt**:

| Ofset | Uzunluk | Alan |
|---:|---:|---|
| 0 | 8 | Magic: hex `50514346494c4500` (`PQCFILE` + NUL) |
| 8 | 1 | Sürüm: 1 |
| 9 | 1 | Suite: 1 |
| 10 | 2 | Reserved: sıfır olmak zorunda |
| 12 | 4 | Parça boyutu |
| 16 | 8 | Toplam plaintext bayt sayısı |
| 24 | 32 | Alıcı kanonik DER SPKI'sinin SHA-256 özeti |
| 56 | 1568 | Standart ML-KEM-1024 ciphertext |
| 1624 | 32 | Rastgele dosya salt'ı |

Başlık düz metindir: dosya boyutu, profil, parça boyutu ve alıcı fingerprint'i gizlenmez. Fingerprint kimlik doğrulaması veya anonimlik sağlamaz.

## Kök ve kayıt anahtarları

Önce ML-KEM ortak sırrı kurulur. Aşağıda `frame(label, value)` şu biçimdir:

```text
ASCII(label) || uint32_be(value.length) || value
```

Etiketlerin sonundaki `\0` tek NUL baytını gösterir.

```text
rootContext = frame("pqc-research-core/file/v1/root\0", context)
rootInfo = frame(
  "pqc-research-core/alpha1/ml-kem-1024/hkdf-sha512/aes256gcm\0",
  rootContext
)
root = HKDF-SHA-512(shared_secret, file_salt, rootInfo, 32)

bound = SHA-512(
  header || frame("context\0", context) || frame("aad\0", aad)
)

recordKey(i) = HKDF-SHA-512(
  root,
  empty_salt,
  ASCII("pqc-research-core/file/v1/record\0") || uint64_be(i),
  32
)

descriptor(i, kind, length) = uint64_be(i) || uint8(kind) || uint32_be(length)
recordAAD = bound || descriptor(i, kind, length)
```

Her kaydın AES-256-GCM anahtarı ayrıdır. Her kayıt için nonce 12 sıfır baytıdır ve tag 16 bayttır. Sabit nonce ancak kayıt anahtarları ayrı olduğu ve dosya kökü taze KEM/salt ile üretildiği için kullanılır; bu kural normal tek kullanımlık mesaj API'sinin nonce kuralını değiştirmez. Dosya yeniden şifrelenirse yeni KEM encapsulation ve salt üretilir; eski kökten devam etme API'si yoktur.

## Kayıt sırası

1. **Başlık doğrulama:** Başlıktan hemen sonra 16 bayt tag gelir. Kayıt indeksi 0, kind 0, length 0 ve plaintext boştur. Böylece boş dosyada dahi başlık/context/AAD doğrulanır.
2. **Veri:** Her veri kaydı `uint32_be(length) || ciphertext || tag` biçimindedir. İndeksler 1'den başlar, kind 1'dir. Son veri kaydı dışındakiler tam parça boyutundadır; sonuncusu kalan plaintext uzunluğundadır.
3. **Zorunlu son kayıt:** `uint32_be(0) || tag`. İndeks N+1, kind 2 ve plaintext boştur. Başka sıfır uzunluklu veri kaydı kabul edilmez.

N veri kaydı için toplam dosya uzunluğu:

```text
1656 + 16 + plaintext_size + (N + 1) * 20
N = ceil(plaintext_size / chunk_size)
```

Çözücü, bu kesin uzunluğu ve beklenen her parça uzunluğunu denetler. Kesme, ek bayt, parça çoğaltma, sıra değiştirme ve dosyalar arası kayıt ekleme testleri vardır. Başka bir dosyanın geçerli başlığını ve bütün içeriğini yerine koymayı engellemek için uygulama beklenen belge kimliğini context/AAD içinde bağlamalıdır; bütün dosyanın replay edilmesi bu biçim tarafından engellenmez.

## Dosyaya güvenli yazma

Çıktı aynı üst klasörde `.pqc-stage-*` altında `output.tmp` dosyasına yazılır. POSIX'te klasör owner-only, dosya `0600` izinleriyle oluşturulur. Windows'ta NTFS ACL'leri üst klasörden devralınır; sayısal POSIX modu herkese karşı gizlilik garantisi değildir.

Çözme sırasında yalnızca etiketi doğrulanmış parçalar geçici dosyaya yazılır. **Dosyanın bütünlüğü tamamen doğrulanana kadar hedef ad oluşturulmaz.** Son kayıt doğrulandıktan sonra dosya sync/close edilir; aynı volume üzerinde exclusive hard link ile hedef ad yayımlanır. Hedef mevcutsa işlem reddedilir. Hard link desteklemeyen dosya sistemlerinde daha zayıf copy/rename fallback'i yapılmaz.

Normal başarı, yakalanan hata ve iptalde geçici dosya/klasör temizlenir. OS/izin/I/O arızası veya process/makine çökmesi temizlik garantisini bozar; özel geçici klasörde kısmi plaintext kalabilir. Bu, yalnızca bellekte şifre çözme değildir. Güvenilir ve erişimi sınırlı yerel klasör kullanılmalı; disk/OS yedeklerinin güvenliği ayrıca ele alınmalıdır. Sync çağrısı bütün dizin metadata'sının power-loss karşısında kalıcı olduğunu kanıtlamaz. Hard link sonrası temizlik hatası halinde hedef tam olarak oluşmuş olsa bile API hata verebilir; çağıran I/O hatalarını ele almalıdır.

Alpha.7'de temizlik close/unlink/rmdir adımlarının tamamını sırayla dener; önceki adımın hatası kalan denemeleri atlatmaz. Bir veya daha fazla adım hata bildirirse `CLEANUP_FAILED` döner; alttaki hatalar non-enumerable `cause` içindeki `AggregateError.errors` dizisinde saklanır. Bu hata önceki doğrulama/iptal hatasının yerine geçebilir. CLI yalnız sabit mesajı yazar ve çıktı klasöründeki `.pqc-stage-*` verilerinin incelenmesini ister. Hedef hard link daha önce yayımlandıysa geri alınmaz. Temizlik hatası, açık metnin kesin kaldığı veya kesin silindiği anlamına gelmez; silme denemesi başarılı olsa da close hatası bildirilmiş olabilir. Hata halinde dosyanın varlığını tek başına başarı kabul etmeyin.

Kaynak dosyanın işlem öncesi ve sonrası boyut/mtime/ctime değerleri karşılaştırılır. Bu, desteklenen normal dosya değişikliklerini yakalar; düşman yerel yöneticiye karşı snapshot veya kilitleme garantisi değildir.

`AbortSignal` başta, parçalar arasında ve yayınlamadan önce kontrol edilir. Yayınlama tamamlandıktan sonra gelen iptal başarıyı geri almaz. KEM/Argon2/native işlemler ortasında zorla iptal veya kesin gecikme sınırı vaat edilmez.

## Hatalar ve açık kalan işler

- `INVALID_FILE`: Magic/sürüm/suite/reserved veya dosya/parça boyutu alanları desteklenmiyor.
- `AUTHENTICATION_FAILED`: Doğru biçimli fakat doğrulanamayan veri; kesilmiş/uzatılmış dosya veya kayıt bütünlüğü hatası.
- `CLEANUP_FAILED`: Geçici çıktı temizliği bir veya daha fazla hata bildirdi; çıktı klasörü incelenmeli. Yayımlanmış hedef geri alınmaz.
- `OUTPUT_EXISTS`, `INPUT_CHANGED`, `ABORTED`, `IO_ERROR`: İşlem/dosya durumu hataları. Native dosya sistemi hataları da dönebilir.

Biçim ve uygulama alpha aşamasındadır. Bağımsız dosya okuyucusu, platformlar arası fixture, kaynak tüketimi ölçümleri, tasarım incelemesi ve sağlayıcı yan kanal analizi kararlı sürüm öncesi yapılmalıdır. Testteki bağımsız okuyucu Noble KEM/HKDF kullanır, AES-GCM için yine native sağlayıcıya dayanır; bütün yığının bağımsız güvenlik denetimi değildir.
