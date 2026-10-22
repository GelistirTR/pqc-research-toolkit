# Üçüncü taraflar

Projenin kendi kodunun PolyForm Noncommercial 1.0.0 lisansı, üçüncü tarafların kendi lisanslarını değiştirmez. Paket veya kaynak dağıtılırken aşağıdaki bağımlılıkların ve test varlıklarının özgün lisans/atıf koşulları korunmalıdır.

## Çalışma zamanı

- Node.js `node:crypto` ve Node ile gelen OpenSSL kullanılır. Normal npm tarball Node/OpenSSL binary'si içermez. Windows portable ZIP ise değiştirilmemiş Node 24.22.1 x64 binary'sini `runtime/node.exe` olarak içerir. Node ve bileşenlerinin tam lisans/atıf metni portable ZIP'teki `runtime/LICENSE.txt` içinde korunur; kaynak kopyası [third_party/node-v24.22.1/LICENSE.txt](third_party/node-v24.22.1/LICENSE.txt), [resmî sürüm kaynağı](https://raw.githubusercontent.com/nodejs/node/v24.22.1/LICENSE). Kaynak ve özet kaydı aynı klasördeki `provenance.json` dosyasındadır. Projenin ticari olmayan lisansı Node/OpenSSL veya bu bileşenlerin kendi izinlerini değiştirmez.

## Geliştirme ve test bağımlılıkları

- `@noble/post-quantum` 0.7.1 — MIT, Copyright (c) 2024 Paul Miller. Tam metin kurulumda `node_modules/@noble/post-quantum/LICENSE` içindedir.
- `@noble/hashes` 2.4.0 — MIT; tam metin ilgili paketin `LICENSE` dosyasında.
- TypeScript — Apache-2.0; tam metin ilgili paketin `LICENSE.txt` dosyasında.
- `@types/node` 24.10.0 — MIT; yalnızca geliştirme/tür kontrolü için kullanılır. Geçişli `undici-types` sürümü lockfile'da kayıtlıdır.
- Geçişli bağımlılıkların tam sürüm ve bütünlük değerleri `package-lock.json` içindedir. Geliştirme bağımlılıkları çalışma zamanı kriptografi sağlayıcısı olarak kullanılmaz.

## Test verileri

- NIST ACVP alt kümesi: `usnistgov/ACVP-Server`, commit `975de31eb83d87039ec88934fdc47d8c312b892d`. Kaynak URL'leri ve indirilen dosyaların SHA-256 özetleri `test/fixtures/nist-acvp.json` içindedir. Özel anahtar alanları yalnızca yayımlanmış, **kamuya açık test anahtarlarıdır**.
- AES-GCM örnekleri: [NIST AES_GCM.pdf](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf), GCM-AES256 örnek 1 ve 2. Sayılar test fixture'ı olarak aktarılmıştır.
- Argon2id vektörü: [RFC 9106 §5.3](https://www.rfc-editor.org/rfc/rfc9106.html#section-5.3). Sabit girdiler ve çıktı doğruluk testi için kullanılır.

Üçüncü taraf kaynak kodunu kopyalayan veya başka binary paketleyen dağıtımlar da ilgili özgün lisans metinlerini ve gerekli atıfları korumalıdır.

Kaynak ağacındaki `third_party/node-v24.16.0` dosyaları önceki yerel arşivlerin geçmiş provenance/lisans kaydıdır; güncel portable paket 24.22.1 kaydını kullanır.
