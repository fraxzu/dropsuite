# Panduan uji challenge / Cloudflare

Panduan ini menjelaskan cara menguji fitur **penanganan halaman pengecekan bot** (layar
"Checking your browser" atau "Verify you are human" dari Cloudflare).

Ditulis untuk pemakaian sehari-hari: setiap langkah menyebut apa yang diklik, apa yang harus
muncul, dan apa artinya kalau tidak muncul.

---

## 1. Yang sedang diuji

Cloudflare memasang tes kecil sebelum situs dibuka. Kalau lolos, Cloudflare memberi cookie
`cf_clearance`, semacam kartu akses berdurasi pendek. Selama kartu itu dipegang, request
berikutnya tidak dites lagi.

DropSuite tidak punya mesin JavaScript, jadi tesnya dikerjakan di jendela browser bawaan
aplikasi. Alurnya:

1. Request kena challenge → banner menyebut vendornya.
2. **Open browser** → jendela dibuka, host itu di-*tunnel* (tidak di-MITM) supaya sidik jari
   TLS browser tetap asli dan tes bisa lolos.
3. Anda menyelesaikan tes. Cloudflare menulis `cf_clearance` ke cookie jendela itu.
4. **Import cookies** → cookie dari jendela disalin ke cookie jar untuk host tersebut.
5. Request dikirim ulang; jar menempelkan cookie, target meloloskan.

**Poin penting:** cookie di langkah 4 **berasal dari jendela challenge itu sendiri**. Tidak ada
yang diambil dari internet, dari browser lain, atau dari akun mana pun. DropSuite membaca cookie
store jendela lewat WebView2 untuk host yang sama, lalu menyimpannya.

---

## 2. Sebelum mulai

- Uji hanya situs milik sendiri atau yang ada izinnya.
- Aplikasi harus versi terbaru. Kalau muncul `not allowed by ACL`, yang terpasang lebih tua.
- Root CA harus sudah dibuat (Listener → **Generate Root CA**) agar HTTPS bisa dibaca.
- Untuk situs yang diuji, jangan masukkan host-nya ke allowlist MITM kalau ingin uji challenge , 
  jendela challenge men-tunnel sendiri, dan tunnel butuh host tidak di-MITM.

---

## 3. Langkah uji

1. **Start** listener. Pastikan berubah menjadi "Listening on 127.0.0.1:8080".
2. Buka tab **Replay**, isi URL situs, klik **Send**.
3. Kalau kena challenge, muncul banner vendor di panel respons. Kalau tidak muncul padahal
   situs jelas memblokir, lihat Bagian 6.
4. Klik **Open browser**. Jendela baru terbuka dengan judul "Challenge Browser (tunneled)".
5. **Selesaikan tesnya** di jendela itu: centang kotak, atau tunggu sampai halaman asli muncul.
   Ini bagian yang memang harus manusia.
6. Setelah halaman asli tampil, biarkan jendela tetap terbuka, kembali ke DropSuite, klik
   **Import cookies**.
7. Baca notifikasinya:
   - `cf_clearance imported (…)` → berhasil, lanjut langkah 8.
   - `<n> cookie(s) from the window: __cf_bm, _cfuvid. No cf_clearance yet` → tesnya belum
     selesai. Kembali ke langkah 5, pastikan halaman asli benar-benar terbuka, lalu import lagi.
8. Klik **Send** sekali lagi.

---

## 4. Membaca hasil

Pada baris fakta respons ada jumlah `jar: N` = berapa cookie jar yang benar-benar terkirim.

| Hasil | Arti |
|---|---|
| `200` + halaman asli, `jar: 1` atau lebih | Lolos. Cookie dipakai. |
| `200` tapi halaman tetap layar challenge | Cookie terkirim tetapi ditolak, biasanya karena sidik jari (lihat Bagian 5) |
| `403`, `jar: 0` | Tidak ada cookie yang cocok. Lihat Bagian 6. |
| `403`, `jar: 1+` | Cookie dikirim, masih ditolak |

---

## 5. Kalau tetap diblokir walau `jar` lebih dari 0

`cf_clearance` terikat pada IP, User-Agent, dan sidik jari TLS saat tes diselesaikan. Yang biasa
membuatnya ditolak:

- **User-Agent berubah.** Pasang preset browser (Chrome/Firefox) **sebelum** membuka jendela, dan
  jangan mengubahnya sesudahnya. UA berbeda = cookie dianggap milik client lain.
- **Cookie kedaluwarsa.** Masa berlakunya pendek (biasanya sekitar 30 menit). Impor ulang.
- **IP berubah** (VPN dinyalakan/dimatikan di tengah jalan).
- **Situs memakai setting ketat.** Peniruan ClientHello TLS belum ada, jadi situs dengan Bot
  Fight Mode ketat masih bisa menolak walau cookie valid. Ini batasan yang diketahui, bukan
  kerusakan.

---

## 6. Kalau tidak ada cookie yang terkirim

`jar: 0` berarti jar tidak punya cookie yang cocok. Periksa berurutan:

1. **Switch jar mati.** Listener → bagian "Browser fingerprint" → centang
   "Attach jar cookies to Replay and Fuzzer".
2. **Skema URL.** Replay memakai `http://` sementara cookie dari challenge bertanda `Secure` →
   tidak dikirim. Pakai `https://`.
3. **Host berbeda.** Cookie disimpan untuk host tempat tes diselesaikan. `presidenri.go.id` dan
   `www.presidenri.go.id` adalah dua host berbeda; selesaikan tes dan impor pada host yang sama
   dengan yang Anda Replay.
4. **Path cookie tidak cocok.** Lihat daftar jar di Listener; kolom path tampil di sana. Replay
   harus memakai path yang sama atau di bawahnya.
5. **Cookie sudah kedaluwarsa.** Daftar jar akan mengosongkannya; impor ulang.

Kalau sudah benar semua tetapi `jar` tetap 0, kirim isi daftar jar (nama, host, path), jangan
nilai cookie-nya.

---

## 7. Masalah lain

| Gejala | Penyebab & solusi |
|---|---|
| Jendela challenge kosong / error sertifikat | Root CA belum dibuat. Listener → Generate Root CA. |
| `not allowed by ACL` | Aplikasi terpasang lebih tua dari daftar izin command. Pasang installer terbaru. |
| "No challenge window is open" saat import | Jendela sudah ditutup. Buka lagi, selesaikan tes, lalu import sebelum menutup jendela. |
| Banner challenge tidak pernah muncul | Deteksi butuh penanda vendor. Kalau situs memblokir tanpa penanda, lihat status dan `jar` saja. |
| Pengunjung asli ikut kena layar cek | Anda menyalakan "I'm Under Attack Mode" di Cloudflare; matikan setelah selesai. |

---

## 8. Yang perlu dicatat saat melaporkan masalah

1. Langkah berapa yang gagal.
2. Nilai `jar: N` pada respons.
3. Nama cookie yang muncul di notifikasi import.
4. Preset yang dipakai dan skema URL.

## Fingerprint otomatis

Saat `cf_clearance` berhasil diimpor, User-Agent jendela challenge ikut dicatat untuk host itu
("fingerprint pinned", berlaku satu jam). Replay lalu memakai User-Agent dan client hints yang
sama, bukan `User-Agent: DropSuite/0.1` dari editor, dan menandai header profilnya sebagai
paksa-ganti. Tanpa ini `cf_clearance` hampir pasti ditolak karena terikat UA.

Kalau `cf_clearance` hilang dari jar, pin tetap ada sampai kedaluwarsa; impor ulang untuk
memperbarui keduanya.
