# Panduan Uji "Challenge / Cloudflare" untuk Pemula

Panduan ini untuk menguji satu fitur baru DropSuite: **melewati halaman pengecekan bot** (seperti layar Cloudflare "Checking your browser" atau "Verify you are human").

Ditulis untuk orang yang baru kenal DropSuite dan Burp. Tidak perlu tahu istilah teknis — semua dijelaskan dengan bahasa biasa.

---

## 1. Ini sebenarnya menguji apa?

Bayangkan situs web dijaga **satpam bot** (Cloudflare). Sebelum Anda masuk, satpam kadang memberi tes kecil: centang kotak "I'm human", atau tunggu beberapa detik. Kalau lolos, satpam memberi Anda **kartu akses** (namanya cookie `cf_clearance`). Selama kartu itu masih dipegang, Anda bebas masuk tanpa dites lagi.

Masalahnya: alat seperti DropSuite biasanya tidak bisa mengerjakan tes satpam itu. Fitur baru ini menyelesaikannya begini:
1. DropSuite membuka **jendela browser kecil** supaya **Anda** yang mengerjakan tes satpam (klik centang, dll).
2. Setelah lolos, DropSuite **mengambil kartu akses** (cookie) dari jendela itu.
3. Mulai sekarang DropSuite memakai kartu itu, jadi request berikutnya bisa tembus.

**Yang kita buktikan di panduan ini:** setelah Anda selesaikan tes satpam dan impor kartunya, request berikutnya **masuk ke halaman asli**, bukan balik ke layar satpam lagi.

---

## 2. Penting dulu (jangan dilewati)

- **Hanya untuk situs milik Anda sendiri**, atau situs yang Anda punya izin tertulis untuk diuji. Melewati satpam bot di situs orang lain itu melanggar. Di panduan ini kita pakai situs Anda sendiri.
- **Situs Anda sekarang (lumens.my.id) belum pakai Cloudflare**, jadi tidak ada satpam untuk diuji. Bagian 3 menjelaskan cara memasang satpam di situs Anda sendiri, supaya ada yang diuji.
- **Tunggu aba-aba "versi baru sudah dipasang".** Fitur ini belum ada di DropSuite yang terpasang sekarang. Saya akan build dan pasang versi barunya dulu, lalu memberi tahu Anda. Sebelum itu, langkah di bawah belum akan muncul di aplikasi.

---

## 3. Menyiapkan "satpam" di situs Anda sendiri (sekali saja)

Supaya ada challenge untuk diuji, pasang situs Anda di belakang Cloudflare gratis, lalu nyalakan mode tes.

1. Buat akun gratis di cloudflare.com, lalu tambahkan domain Anda (ikuti wizard-nya; Anda akan diminta mengganti "nameserver" di tempat beli domain). Ini bagian paling teknis, dan cukup dilakukan sekali.
2. Setelah domain aktif di Cloudflare, buka menu **Security**.
3. Nyalakan **"I'm Under Attack Mode"** (mode "sedang diserang"). Mode ini membuat Cloudflare menampilkan layar pengecekan ke **setiap** pengunjung — persis yang kita butuhkan untuk menguji.
4. Buka situs Anda di browser biasa (Chrome) untuk memastikan layar "Checking your browser…" benar-benar muncul. Kalau muncul, satpam sudah aktif.

> Kalau terlalu ribet menyiapkan Cloudflare, lewati saja uji ini. Fitur lain DropSuite tetap bisa diuji dengan [PANDUAN-TESTING.md](PANDUAN-TESTING.md). Uji challenge ini sifatnya khusus.

**Setelah selesai menguji, matikan lagi "I'm Under Attack Mode"** supaya pengunjung asli Anda tidak kena layar pengecekan terus.

---

## 4. Langkah uji di DropSuite (bagian utama)

Ikuti urut. Di tiap langkah sudah ditulis Anda harus klik apa dan hasil yang benar seperti apa.

### Persiapan
- [ ] **1.** Buka DropSuite. Di bar atas, klik **Start**. Tulisan berubah jadi "Listening on 127.0.0.1:8080".
- [ ] **2.** Klik ikon **Listener** (pojok kanan atas). Klik **Generate Root CA**. Muncul sidik jari (fingerprint) CA. (Ini izin agar DropSuite bisa membaca isi lalu lintas HTTPS. Butuh sekali saja.)
- [ ] **3.** Masih di Listener, pada kotak **allowlist**, ketik alamat situs Anda (contoh: `situsanda.com`). Simpan. (Allowlist = daftar situs yang boleh "dibuka isinya" oleh DropSuite.)

### Memicu challenge
- [ ] **4.** Buka tab **Replay** di bar atas.
- [ ] **5.** Di kolom URL, ketik alamat situs Anda (contoh: `https://situsanda.com/`). Klik **Send** (atau tekan `Ctrl+Enter`).
- [ ] **6.** Lihat hasil di sebelah kanan. Kalau satpam aktif, muncul **banner** yang menyebut nama vendor, misalnya **"Cloudflare challenge"**. Inilah tanda request Anda dicegat satpam, bukan dijawab halaman asli.

> Kalau banner tidak muncul dan langsung dapat halaman asli, berarti satpam tidak aktif. Balik ke Bagian 3 dan pastikan "I'm Under Attack Mode" menyala.

### Menyelesaikan tes satpam
- [ ] **7.** Klik tombol **Open browser** (di dekat banner). Sebuah **jendela browser kecil** terbuka menampilkan layar satpam.
- [ ] **8.** **Kerjakan tesnya di jendela itu** — biasanya centang kotak "I'm human" lalu tunggu, atau cukup tunggu beberapa detik sampai layar hilang dan halaman asli muncul. (Ini bagian yang harus manusia; DropSuite tidak bisa menggantikannya.)
- [ ] **9.** Setelah halaman asli muncul di jendela itu, **tutup jendelanya**.

### Memakai kartu akses
- [ ] **10.** Kembali ke DropSuite. Klik tombol **Import cookies**. (DropSuite menyalin "kartu akses" dari jendela tadi.) Biasanya muncul notifikasi kecil bahwa cookie berhasil diimpor.
- [ ] **11.** Klik **Send** sekali lagi pada request yang sama.

### Membaca hasilnya
- [ ] **12. LULUS** kalau hasil kali ini adalah **halaman asli situs Anda** (status 200, atau isi halaman sungguhan), **bukan** banner challenge lagi. Berarti kartu akses berhasil dipanen dan dipakai. 🎉
- [ ] **13. BELUM LULUS** kalau masih muncul banner challenge. **Ini belum tentu fiturnya rusak** — baca Bagian 5.

---

## 5. Kalau langkah 12 masih kena challenge (penting)

Jangan langsung menyimpulkan fiturnya gagal. Ada satu keterbatasan yang sudah diketahui:

Kartu akses (`cf_clearance`) kadang terikat pada "sidik jari browser" yang menyelesaikannya. Saat DropSuite mengirim ulang request, Cloudflare yang **sangat ketat** bisa tetap menolak sampai fitur lanjutan **HTTP/2 + peniruan ClientHello** selesai dibuat. Fitur lanjutan itu sedang dikerjakan (langkah berikutnya).

Jadi hasil "masih kena challenge" bisa berarti:
- Situs Cloudflare Anda di-set terlalu ketat, **atau**
- Memang perlu menunggu fitur HTTP/2 selesai.

Yang **sudah membuktikan fitur ini bekerja** walau langkah 12 belum tembus:
- Banner challenge muncul dengan benar di langkah 6 (deteksi jalan).
- Jendela browser terbuka dan Anda bisa menyelesaikan tes di langkah 8.
- Notifikasi "cookie diimpor" muncul di langkah 10 (pemanenan jalan).

Kalau tiga hal itu terjadi, bagian mekanis fitur sudah benar.

---

## 6. Masalah yang sering muncul

| Gejala | Penyebab & solusi |
|---|---|
| Jendela di langkah 7 kosong / error sertifikat | Root CA belum dibuat. Ulangi langkah 2. |
| Banner challenge tidak pernah muncul | Satpam tidak aktif. Nyalakan "I'm Under Attack Mode" (Bagian 3). |
| Situs tidak terbuka sama sekali | Alamat salah, atau situs belum ada di allowlist (langkah 3). |
| "Import cookies" tidak ada efeknya | Pastikan di langkah 9 halaman asli benar-benar sudah muncul di jendela sebelum ditutup. Kalau jendela ditutup saat masih di layar satpam, belum ada kartu untuk dipanen. |
| Pengunjung asli situs Anda kena layar pengecekan terus | Anda lupa mematikan "I'm Under Attack Mode". Matikan di Cloudflare → Security. |

---

## 7. Yang perlu Anda catat untuk saya

Saat menguji, catat singkat:
1. Di langkah berapa berhenti / bermasalah.
2. Apa yang muncul vs apa yang Anda harapkan.
3. Screenshot kalau bisa (terutama banner di langkah 6 dan hasil di langkah 12).

Dari catatan itu saya bisa tahu apakah yang perlu diperbaiki ada di fitur DropSuite, atau hanya soal pengaturan Cloudflare.
