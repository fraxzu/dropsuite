# Panduan Testing DropSuite

Panduan untuk mencoba semua fitur DropSuite secara manual, dari instalasi sampai fitur terakhir. Kerjakan berurutan: bagian awal menyiapkan lalu lintas (traffic) yang dipakai bagian berikutnya.

> Uji hanya target milik sendiri, target latihan yang memang disediakan untuk diuji, atau target yang izinnya tertulis. Daftar target aman ada di bagian 2.

---

## 0. Lokasi file

| Apa | Lokasi |
|---|---|
| Installer (salinan siap pakai) | `C:\Users\Fraxzu\Downloads\DropSuite-Installer\DropSuite_0.1.0_x64-setup.exe` |
| Installer (hasil build asli) | `C:\Users\Fraxzu\Downloads\dropsuite-rc\fraxzu-v0.1.0\target\release\bundle\nsis\DropSuite_0.1.0_x64-setup.exe` |
| Aplikasi setelah diinstal | `%LOCALAPPDATA%\DropSuite\dropsuite.exe` (ada juga shortcut di Start Menu dan Desktop) |
| Data aplikasi (history, CA, pengaturan) | `%APPDATA%\com.dropsuite.desktop` dan `%LOCALAPPDATA%\com.dropsuite.desktop` |
| Server uji lokal | `C:\Users\Fraxzu\Downloads\rea_software\target\release\mock_upstream.exe` |

**Membuat installer baru setelah mengubah kode** (dari folder `rea_software`, di Git Bash):

```sh
(cd frontend && npm run build)
CARGO_TARGET_DIR='C:\Users\Fraxzu\Downloads\dropsuite-rc\<nama-build>\target' node frontend/node_modules/@tauri-apps/cli/tauri.js build
```

Pakai nama folder baru setiap kali build, supaya installer lama tidak tertimpa. Installer baru ada di `<nama-build>\target\release\bundle\nsis\`.

---

## 1. Instal dan copot

- [ ] Jalankan installer, lalu ikuti langkahnya. Tidak perlu hak admin karena diinstal per pengguna.
- [ ] **Windows SmartScreen** mungkin muncul ("Windows protected your PC") karena installer belum ditandatangani (unsigned). Klik **More info → Run anyway**. Ini normal untuk build lokal.
- [ ] Cek **Settings → Apps → Installed apps**: DropSuite tampil dengan ikon DropSuite dan pengembang **Fraxzu**.
- [ ] Buka DropSuite dari Start Menu. Jendela gelap tanpa bingkai Windows akan muncul.
- [ ] Buka aplikasi kedua kali saat yang pertama masih jalan. Seharusnya tidak muncul jendela kedua, karena aplikasinya single-instance.
- [ ] (Di akhir sesi) Copot lewat Installed apps → Uninstall. Entri hilang dari daftar dan folder `%LOCALAPPDATA%\DropSuite` terhapus.

---

## 2. Target uji yang aman

| Target | Kegunaan |
|---|---|
| **Server uji lokal** `http://127.0.0.1:9090` | Paling aman, tanpa internet. Jalankan `mock_upstream.exe` (lihat di bawah). Rute: `/api/login`, `/api/status`, `/not-found` (404), dan rute lain (respons default). |
| `http://testphp.vulnweb.com` | Situs latihan milik Acunetix yang memang dibuat rentan untuk diuji. HTTP biasa, cocok untuk Proxy, Scanner, dan Fuzzer. |
| OWASP Juice Shop | Aplikasi latihan yang sengaja rentan. Paling aman dijalankan sendiri secara lokal (Docker: `docker run -p 3000:3000 bkimminich/juice-shop`). |

**Menjalankan server uji lokal** (PowerShell, biarkan jendelanya tetap terbuka):

```powershell
& "C:\Users\Fraxzu\Downloads\rea_software\target\release\mock_upstream.exe"
```

**Mengirim request lewat DropSuite dengan curl** (PowerShell; pakai `curl.exe`, bukan `curl`):

```powershell
curl.exe -x http://127.0.0.1:8080 http://127.0.0.1:9090/api/status
```

> Browser biasanya **melewati proxy untuk alamat localhost/127.0.0.1**. Untuk server uji lokal, pakai `curl.exe -x`. Untuk situs sungguhan, pakai browser bawaan DropSuite.

---

## 3. Listener (tombol Start dan gerigi)

- [ ] Klik **Start** di bar atas. Status berubah jadi berjalan di `127.0.0.1:8080`.
- [ ] Klik ikon **gerigi** (Listener settings): alamat, port, dan folder log terlihat.
- [ ] Ganti port ke `8090`, simpan, Start ulang. `curl.exe -x http://127.0.0.1:8090 http://127.0.0.1:9090/` berhasil. Kembalikan ke `8080`.
- [ ] Klik **Stop**. curl ke proxy sekarang gagal ("connection refused"). Start lagi.
- [ ] Kirim request ke proxy itu sendiri: `curl.exe -x http://127.0.0.1:8080 http://127.0.0.1:8080/`. Hasilnya **508** (pencegah loop), bukan hang.

---

## 4. Proxy dan HTTP History

Kirim beberapa request dulu:

```powershell
curl.exe -x http://127.0.0.1:8080 http://127.0.0.1:9090/api/status
curl.exe -x http://127.0.0.1:8080 http://127.0.0.1:9090/not-found
curl.exe -x http://127.0.0.1:8080 -X POST -H "Content-Type: application/json" -d "{\"user\":\"alice\",\"password\":\"rahasia123\"}" http://127.0.0.1:9090/api/login
curl.exe -x http://127.0.0.1:8080 -H "Authorization: Bearer token-asli-123" -H "Cookie: session=abc123" http://127.0.0.1:9090/api/status
```

- [ ] Keempat request langsung muncul di **HTTP history** dengan method, host, path, status (200/404), ukuran, dan waktu.
- [ ] Klik satu baris. Inspector menampilkan tab request dan response (header, body, durasi).
- [ ] **Pencarian:** tekan `/`, ketik `login`. Hanya baris login yang tersisa.
- [ ] **Filter** method (POST) dan status (404) bekerja.
- [ ] **Keyboard:** `j`/`k` pindah baris, `Esc` menghapus pilihan.
- [ ] **Redaksi kredensial:** pada request ber-`Authorization` dan `Cookie`, nilainya tersamarkan di history. Pada request login, field `password` juga tersamarkan. Token asli tidak tersimpan.
- [ ] **Browser bawaan:** di Proxy, isi URL `http://testphp.vulnweb.com`, buka browser. Jendela "DropSuite Browser (Proxy Active)" terbuka dan setiap halaman yang dibuka masuk ke history.
- [ ] **Export HAR:** ekspor history. File `.har` tersimpan dan bisa dibuka (misalnya di DevTools browser → Network → Import).
- [ ] **Data bertahan:** tutup DropSuite lalu buka lagi. History masih ada.
- [ ] **Clear history:** klik tombol **Clear** (di sebelah HAR). Muncul konfirmasi; setelah OK, history kosong, dan Site map serta Scanner ikut kosong setelah Rescan. Tab Replay (Repeater) tidak terhapus.

---

## 5. HTTPS interception (Root CA dan allowlist)

- [ ] Pada profil baru belum ada CA. Buka browser bawaan ke situs HTTPS yang ada di allowlist. Hasilnya error **502** dengan petunjuk "HTTPS interception needs a root CA". DropSuite tidak membuat CA sendiri.
- [ ] Di Listener settings, klik **Generate Root CA**. Fingerprint CA tampil.
- [ ] Tambahkan host uji ke **allowlist** (misalnya `example.com`), simpan.
- [ ] Buka `https://example.com` di browser bawaan. Halaman tampil normal dan isi request/response HTTPS terbaca di history.
- [ ] Buka situs HTTPS lain yang **tidak** ada di allowlist. Koneksinya hanya diteruskan (tunnel) tanpa didekripsi, jadi isinya tidak terbaca.
- [ ] Tutup dan buka DropSuite lagi. Allowlist yang disimpan masih ada, termasuk entri `::1`.
- [ ] **Export Public CA** menyalin sertifikat publik (PEM) ke clipboard. Kunci privat tidak pernah ikut diekspor.
- [ ] **Remove CA**, lalu buka lagi situs yang ada di allowlist. Hasilnya kembali **502**. Generate lagi: fingerprint-nya berbeda dari sebelumnya.

> Browser bawaan menerima sertifikat DropSuite tanpa mengubah trust store Windows. Kalau ingin memakai browser lain, impor CA hanya ke profil browser khusus testing (misalnya profil Firefox terpisah), jangan ke Windows, lalu hapus setelah selesai.

---

## 6. Intercept

- [ ] Nyalakan **Intercept**. Kirim `curl.exe -x http://127.0.0.1:8080 http://127.0.0.1:9090/api/status`. curl tertahan dan request muncul di panel Intercept.
- [ ] **Forward** tanpa diubah: curl menerima respons 200.
- [ ] Kirim lagi, ubah path jadi `/not-found`, lalu Forward. curl menerima 404.
- [ ] Kirim lagi, lalu **Drop**. curl langsung tertutup tanpa respons, dan server uji tidak menerima apa-apa.
- [ ] Kirim tiga request sekaligus (tiga jendela PowerShell), lalu **Forward all** / **Drop all**.
- [ ] Ubah request menjadi teks asal-asalan, lalu Forward. Hasilnya **400 Bad Request**.
- [ ] Nyalakan **intercept response**. Respons ikut tertahan. Ubah status atau body-nya, lalu Forward. curl menerima versi yang diubah.
- [ ] Biarkan satu request tertahan selama lebih dari **60 detik**. curl menerima **504 Gateway Timeout**. Response yang ditahan terlalu lama justru diteruskan otomatis.
- [ ] Matikan Intercept saat ada request tertahan. Semua request yang tertahan langsung diteruskan.

---

## 7. Target: Site map, Scope, Match & Replace

- [ ] **Site map** menampilkan pohon host dan path dari history (127.0.0.1:9090, testphp.vulnweb.com, dan lain-lain).
- [ ] **Scope:** buat aturan Include untuk `127.0.0.1` port `9090`, aktifkan **drop out-of-scope**. Request ke target lain sekarang ditolak (403), tidak diteruskan.
- [ ] Nyalakan Intercept, tahan request yang in-scope, ubah tujuannya ke host di luar scope, lalu Forward. Hasilnya **403**: scope dicek ulang setelah request diedit.
- [ ] **Match & Replace:** buat aturan yang menambah atau mengganti header (misalnya `User-Agent` → `DropSuite-Test`). Kirim request, lalu cek di history atau di server uji bahwa header berubah.
- [ ] Matikan atau hapus aturan scope dan match & replace sebelum lanjut.

---

## 8. Replay

- [ ] Pilih satu baris di history, lalu klik **Send to Replay** di Inspector. Tab Replay baru terbuka dengan pesan "Nothing has been sent".
- [ ] Ubah method, URL, header, atau body, lalu **Send** (atau `Ctrl+Enter`). Respons tampil.
- [ ] Kirim beberapa kali dengan perubahan berbeda. **Riwayat percobaan** per tab tersimpan, dan dua respons bisa dibandingkan berdampingan.
- [ ] Shortcut: `Ctrl+T` tab baru, `Ctrl+D` duplikat tab, `Ctrl+W` tutup tab.
- [ ] Tab **Issues** pada respons menandai masalah pasif seperti header keamanan yang hilang atau cookie tanpa flag. Coba pada respons dari testphp.vulnweb.com.
- [ ] Kirim ke `http://169.254.169.254/` (alamat metadata cloud). Hasilnya **"Not sent: restricted address"** dan tidak ada koneksi keluar.

---

## 9. Fuzzer

Gunakan hanya ke server uji lokal atau target latihan.

- [ ] Buka **Fuzzer** dan isi template request, misalnya `http://127.0.0.1:9090/api/status?id=1`. Pilih teks yang mau diganti (misalnya `1`), lalu **Add position**. Teks dibungkus `{{ }}`.
- [ ] **Sniper** dengan payload **List** (3-5 kata), lalu **Start attack**. Hasil mengalir satu per satu dengan status dan panjang respons.
- [ ] Payload **Number range** (misalnya 1-20).
- [ ] Dua posisi dan **Cluster bomb**. Jumlah request = jumlah payload set 1 × payload set 2.
- [ ] **Presets** memuat daftar bawaan.
- [ ] Atur concurrency dan delay. Kecepatan serangan berubah.
- [ ] Klik satu baris hasil. Request persis itu terbuka di tab Replay.
- [ ] Target yang di luar scope atau beralamat terlarang ditolak, tidak dikirim.

---

## 10. Decoder dan Comparer

- [ ] **Decoder:** encode lalu decode Base64, URL, Hex, dan HTML. Hasilnya kembali ke teks semula.
- [ ] **JWT decode:** tempel token JWT, lalu header dan payload terbaca.
- [ ] **Use as input** untuk merantai langkah (misalnya URL-decode, lalu Base64-decode).
- [ ] **Comparer:** tempel dua teks yang sedikit berbeda ke A dan B. Baris yang berubah, dihapus, dan ditambah diberi tanda.

---

## 11. Scanner (pasif)

- [ ] Jelajahi beberapa halaman testphp.vulnweb.com lewat browser bawaan.
- [ ] Buka **Scanner**. Temuan dikelompokkan per jenis dan tingkat keparahan, beserta jumlah request dan host yang terdampak.
- [ ] Buka **Affected requests** pada satu temuan.
- [ ] Jelajahi halaman lain, lalu **Rescan**. Hasilnya ikut bertambah.
- [ ] Scanner hanya membaca history dan tidak mengirim request apa pun. Jumlah baris history tidak bertambah selama scan.
- [ ] **Clear (Scanner):** klik **Clear** di sebelah Rescan. Temuan di layar hilang. Ini hanya membersihkan tampilan, tidak menghapus history, jadi **Rescan** memunculkannya lagi. Untuk benar-benar menghapus datanya, pakai Clear di tab Proxy.

---

## 12. Drop AI (opsional, butuh API key sendiri)

- [ ] Buka **Drop AI** di bar atas. Pilih provider (OpenAI-compatible atau Anthropic-compatible), isi base URL dan API key, lalu simpan.
- [ ] **Detect** menampilkan daftar model. Pilih satu, lalu **Test** untuk mengecek koneksi.
- [ ] **Analyze with AI** pada satu request di Proxy atau Replay. Ada pratinjau isi yang akan dikirim, dan rahasia (token, cookie) tersamarkan, sebelum benar-benar dikirim.
- [ ] Di tab Issues atau Scanner: **Triage with AI** dan **Draft report** menghasilkan laporan Markdown.

---

## 13. Lain-lain

- [ ] Tombol **?** (Help) membuka panduan singkat di dalam aplikasi.
- [ ] Jendela bisa digeser lewat bar atas, dimaksimalkan dengan klik ganda, diminimalkan, dan ditutup.
- [ ] Ubah ukuran jendela sampai minimum (960×600). Tata letak tidak rusak.

---

## Melaporkan bug

Catat untuk setiap masalah:
1. Bagian dan langkah di panduan ini (misalnya "6. Intercept, langkah ke-4").
2. Yang dilakukan, yang diharapkan, dan yang terjadi.
3. Screenshot, dan bila perlu file log dari folder log (lihat di Listener settings).

## Active scan (uji aktif)

Mode **Active** di Scanner mengirim request sungguhan, satu titik suntik per kali, ke situs yang
Anda punya izin untuk menguji. Empat pemeriksaan: reflected XSS (confidensi tinggi hanya bila
marker pantul tanpa di-encode), SQL error-based, path traversal, dan open redirect. Setiap temuan
menyertakan bukti (potongan respons) dan tingkat keyakinan. Berjalan berurutan dengan delay,
berhenti saat target membalas 403/429 beruntun, dan patuhi batas request maksimum.
