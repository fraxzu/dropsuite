                                                                                                                                    # DropSuite Pro + Drop AI — Rencana Fitur Open Source

Oct 20, 2026 · @hashizume · _diperbarui 20 Okt 2026: status disinkronkan ke kode riil (verifikasi engine → command → transport → UI)_

Target: jadikan DropSuite setara Burp Suite Professional tapi open source, plus **Drop AI** — asisten AI BYOK di mana user menaruh model & API key sendiri (OpenAI-compatible dan Anthropic-compatible). Dokumen ini memetakan setiap fitur Burp ke DropSuite, menandai mana yang sudah jadi, dan menyusun roadmap.

## Ringkasan

Kita bangun **DropSuite Pro** — toolkit pentest web setara Burp Suite Professional, tapi open source — dan **Drop AI**, asisten AI BYOK (Bring Your Own Key) yang terpasang di dalamnya. Burp Pro berbayar $499/tahun per kursi; target kita memberi fungsi inti yang sama tanpa biaya lisensi, dengan AI yang memakai model & API key milik user sendiri.

Fondasinya ternyata **jauh lebih maju dari perkiraan dokumen versi awal.** Selain engine proxy + intersepsi HTTPS + CA eksplisit + destination policy + sanitasi/redaksi + History SQLite (semua terverifikasi RC1, acceptance 33/33, replay 10/10), verifikasi 20 Okt 2026 menunjukkan **lima tool Burp inti sudah jadi dan ter-wire sampai UI**, bukan sekadar ada di engine:

- **Intercept penuh (hold → edit → forward/drop)** — `interception.rs` (`InterceptAction::Forward { modified_wire }` + `Drop`), 8 command Tauri, `InterceptPanel.tsx`, plus test `intercept_forward_*`.
- **Repeater** dengan tab persisten + riwayat attempt — `save_repeater_tab` / `list_repeater_attempts`, `ReplayWorkspace.tsx`, test `repeater_persistence_test`.
- **Scope**, **Match & Replace**, **Site map** — `scope.rs` / `match_replace.rs` / `sitemap.rs`, masing-masing punya command get/set, terdaftar di `main.rs`, dipanggil via `transport.ts`, tampil di `TargetWorkspace.tsx` / `SiteMap.tsx`.

Artinya Proxy/Intercept, Repeater, Target/Site map, Scope, dan Match&Replace — kira-kira separuh tool harian pentester — **sudah di tangan.** Yang benar-benar kurang tinggal empat lapisan + satu pembeda.

Empat hal yang perlu dibangun, diurut sesuai rasio dampak/usaha (menumpang inti yang sudah lulus verifikasi lebih dulu):

1. **Intruder (fuzzer)** — fuzzing/brute-force terotomasi. Paling murah karena menumpang jalur kirim `replay.rs` yang sudah bawa guard SSRF, timeout, dan sanitasi. Begitu jadi, tab **Fuzzer** (kini `[planned]`) langsung hidup. Wajib ikut acceptance criteria di bawah agar jadi _responsible tool_, bukan flooder.
2. **Decoder / Comparer** — utilitas murni (Base64/URL/hex/JWT, diff dua request). Risiko nol ke engine, cepat jadi, langsung memperkaya toolbox.
3. **Drop AI (BYOK)** — ✅ **MVP SELESAI.** `dropai.rs` (OpenAI- & Anthropic-compatible, key DPAPI, call via reqwest langsung — bukan lewat proxy), panel Settings (tombol **Drop AI** di chrome: provider/base-url/model/temp/max-tokens, simpan key, **Test**), dan fitur pertama **"Suggest payloads"** di Fuzzer dengan **preview-before-send + redaksi default**. Sisa fitur (Explain request/response, Triase temuan scanner, Draft laporan) menyusul.
4. **Scanner pasif** — hook read-only di jalur proxy (header keamanan hilang, cookie tanpa flag, reflected input). Tanpa kirim request tambahan → risiko nol. Scanner aktif menyusul setelah keputusan HTTP/2.

Bagian berikut memetakan tiap tool Burp ke DropSuite dengan status, menggambar arsitektur target, merinci desain Drop AI, dan menyusun roadmap bertahap.

> **Catatan ruang lingkup & legal:** bangun ulang fungsionalitas itu sah; **jangan menyalin kode, nama, ikon, atau aset Burp/PortSwigger**. "BApp", "BChecks", "Bambdas", "Montoya" adalah istilah milik PortSwigger — pakai nama sendiri (mis. "DropChecks", "DropApps"). Detail di bagian Keputusan Terbuka.

## Peta fitur Burp Pro → DropSuite

Setiap tool Burp Professional dipetakan ke padanan DropSuite, dengan status jujur: apa yang engine kita sudah punya, dan apa yang perlu dibangun. Status "Sudah ada" mengacu pada komponen terverifikasi di RC1.

| Tool / fitur Burp | Fungsi | Padanan DropSuite | Status | Prioritas |
| --- | --- | --- | --- | --- |
| **Proxy + Intercept** | Tangkap, tahan, ubah lalu lintas HTTP/HTTPS/WebSocket | Engine proxy + intersepsi HTTPS + CA + `interception.rs` (`dropsuite-core`) | ✅ **SELESAI** untuk HTTP/HTTPS termasuk hold→edit→forward/drop (ter-wire + test); WebSocket & HTTP/2 belum | — |
| **HTTP/2 + WebSocket** | Dukung h2 (banyak target modern) & ws | Belum ada; sengaja ditunda — lihat "Keputusan terbuka" | ⏸️ **Ditunda sadar** (bukan dilupakan) | Sedang |
| **Target scope** | Batasi tool ke host/path in-scope | `scope.rs` + `get/set_scope_config` + UI `TargetWorkspace` | ✅ **SELESAI** (termasuk drop out-of-scope / Zero Egress) | — |
| **Built-in browser** | Browser bawaan pra-konfigurasi proxy | Embedded WebView2 zero-install (lihat smoke-test TLS); diarahkan ke listener | ✅ **Sebagian besar jadi** (browser tertanam + trust leaf in-memory) | Sedang |
| **Target site map** | Pohon host/URL hasil rekon | `sitemap.rs` + `get_sitemap` + `SiteMap.tsx` di `TargetWorkspace` | ✅ **SELESAI** (pohon tampil di tab Target) | — |
| **Repeater** | Kirim ulang & edit request manual berulang | `replay.rs` + tab persisten + riwayat attempt + `ReplayWorkspace.tsx` | ✅ **SELESAI** (tab + riwayat + test) | — |
| **Intruder** | Fuzzing/brute-force dengan payload set & posisi | `intruder.rs` (Sniper + Cluster Bomb) di atas jalur kirim `replay.rs` + 4 command + `FuzzerWorkspace.tsx` | ✅ **SELESAI** (engine + UI + 9/9 acceptance test) | — |
| **Scanner (pasif)** | Deteksi isu sambil browsing | Belum ada; hook di jalur proxy yang sudah ada | Perlu dibangun | Tinggi |
| **Scanner (aktif)** | Audit aktif per-URL/parameter | Belum ada | Perlu dibangun | Tinggi |
| **Crawler** | Pemetaan attack surface otomatis (render JS) | Belum ada; butuh browser headless | Perlu dibangun | Sedang |
| **OAST / Collaborator** | Deteksi out-of-band (blind SSRF, async SQLi) | Belum ada; butuh server interaksi eksternal | Perlu dibangun (server terpisah) | Sedang |
| **Custom checks (BChecks)** | Bahasa cek kustom sederhana | Belum ada; rancang "DropChecks" (YAML/DSL) | Perlu dibangun | Sedang |
| **Sequencer** | Uji kualitas keacakan token | Belum ada; analisis entropi | Perlu dibangun | Rendah |
| **Decoder / Encoder** | Konversi encoding (base64, URL, hex, JWT, HTML) | `lib/codec.ts` + `DecoderWorkspace.tsx` (tab Decoder, Alt+5) | ✅ **SELESAI** (murni lokal, bisa chain) | — |
| **Comparer** | Diff dua request/response | `lib/diff.ts` + `ComparerWorkspace.tsx` (tab Comparer, Alt+6) | ✅ **SELESAI** (line diff mandiri) | — |
| **HTTP message editor** | Editor kaya + pretty-print JSON/XML/HTML | Belum ada (UI) | Perlu dibangun | Sedang |
| **Match & replace** | Aturan ubah otomatis request/response | `match_replace.rs` + `get/set_match_replace_config` + UI `TargetWorkspace` | ✅ **SELESAI** (rule aktif dari UI) | — |
| **CSRF PoC generator** | Buat PoC CSRF otomatis | Belum ada | Perlu dibangun | Rendah |
| **DOM analysis (DOM Invader)** | Temukan DOM XSS dari sisi klien | Belum ada; butuh instrumentasi browser | Perlu dibangun | Rendah |
| **API scanning** | Scan OpenAPI/GraphQL/SOAP dari definisi | Belum ada | Perlu dibangun | Sedang |
| **Authenticated scanning** | Scan area ber-login | Bergantung pada scanner + manajemen sesi | Perlu dibangun | Sedang |
| **Project files / logging** | Log persisten semua aktivitas | History SQLite + snapshot sudah ada | Sebagian (perlu format proyek tunggal) | Sedang |
| **Organizer** | Simpan & anotasi request menarik | Belum ada | Perlu dibangun | Rendah |
| **Search / filter / sort** | Saring lalu lintas & hasil | Belum ada (UI) | Perlu dibangun | Sedang |
| **Report generation** | Laporan otomatis + remediasi | Belum ada | Perlu dibangun | Sedang |
| **Extensibility (Montoya API)** | Ekstensi pihak ketiga | Belum ada; rancang API ekstensi sendiri | Perlu dibangun | Sedang |
| **Burp AI (di Repeater)** | Asisten AI validasi/analisis | **Drop AI (BYOK)** — `dropai.rs` (OpenAI/Anthropic) + key DPAPI + panel Settings + "Suggest payloads" di Fuzzer | ✅ **MVP SELESAI** (config+key+test+suggest; Explain/Triase/Report nyusul) | — |

Intinya (revisi 20 Okt): bukan ~25%, tapi **mendekati separuh tool Burp inti sudah ✅ SELESAI dan ter-wire sampai UI** — Proxy/Intercept (hold-edit-fwd/drop), Repeater, Site map, Scope, Match&Replace, plus browser tertanam. Sisanya empat lapisan (Intruder, Decoder/Comparer, Scanner, ekstensi) + pembeda Drop AI, plus dua _known gap_ yang ditunda sadar: HTTP/2 dan WebSocket. Fokus kerja berikutnya: **Intruder dulu.**

## Arsitektur target

Strateginya: **jangan sentuh inti yang sudah lulus verifikasi**, tambahkan lapisan layanan baru di atasnya. Semua tool baru (Scanner, Intruder, Crawler, Drop AI) berjalan lewat `dropsuite-core` yang sudah ada, sehingga kebijakan keamanan — destination policy, redaksi rahasia, CA eksplisit — otomatis berlaku untuk mereka tanpa ditulis ulang.

&#91;embedded content: arsitektur target · 3 lapisan, inti terverifikasi di bawah\]

Keuntungan bentuk ini: setiap modul baru mewarisi jaminan keamanan inti (mis. Scanner tak bisa menembak endpoint metadata cloud karena lewat destination policy yang sama). Server OAST sengaja berdiri terpisah dari host karena perlu menerima koneksi masuk dari internet — itu komponen jaringan tersendiri, bukan bagian dari engine lokal.

## Intruder — desain & acceptance criteria (build berikutnya)

Intruder dibangun sebagai `crates/dropsuite-core/src/intruder.rs` (di **engine**, bukan di app) supaya otomatis mewarisi guard inti, dan **memakai ulang primitif kirim `replay.rs`** — bukan menyalin logikanya. Intruder adalah pengirim request otomatis massal; satu salah desain mengubahnya jadi SSRF cannon / flooder. Karena itu enam hal berikut adalah **acceptance criteria wajib (jadikan test, sesuai budaya RC 168-pass), bukan opsi**:

1. **Reuse jalur kirim Replay, jangan fork.** Harus lewat primitif yang sama yang sudah membawa `is_restricted_destination` (blokir `169.254.169.254` / cloud metadata), timeout, dan sanitasi memori. Dilarang membuat jalur kirim baru yang melewati guard ini.
2. **Hormati Scope.** Intruder hanya menembak host **in-scope**; target out-of-scope ditolak sebelum kirim. Ini yang mencegah tak sengaja menghajar pihak ketiga.
3. **Concurrency limit + throttle.** Batas request simultan (default 5–10, cap keras) **dan** opsi jeda antar-request. Keduanya, bukan salah satu.
4. **Hard cancel/stop.** Pakai pola `cancel_replay` yang sudah ada; serangan bisa dihentikan seketika.
5. **Batas memori attempt.** Payload × respons bisa meledak — stream hasil dan cap jumlah attempt yang disimpan; jangan tahan semua di RAM/DB tanpa batas.
6. **MVP attack type: Sniper + Cluster Bomb saja.** Menutup mayoritas kasus; Pitchfork / Battering Ram menyusul.

Komponen yang perlu dibuat: enum attack type, parser penanda posisi (pakai delimiter **sendiri** mis. `{{...}}` atau `‹...›` — **bukan** `§...§` milik Burp), generator payload (list/wordlist, number range, brute-force), dan worker loop ber-concurrency-limit yang memanggil send-path Replay. Di frontend: aktifkan tab **Fuzzer** yang kini `[planned]`.

## Drop AI (BYOK)

Burp AI mengirim data ke layanan PortSwigger dan memakai sistem kredit berbayar. **Drop AI membalik modelnya: user menaruh model & API key sendiri.** Tidak ada server kita di tengah, tidak ada kredit, tidak ada biaya dari kita. Ini juga keunggulan privasi — data uji tidak pernah lewat pihak ketiga selain provider yang user pilih sendiri.

### Desain provider

Satu abstraksi `LlmProvider` dengan dua implementasi bawaan. Keduanya umum dan menutup hampir semua model di pasar:

1. **OpenAI-compatible** — `POST {base_url}/chat/completions`, header `Authorization: Bearer <key>`. Karena banyak penyedia (OpenAI, Groq, Together, OpenRouter, Ollama, LM Studio, vLLM lokal) meniru skema ini, satu implementasi melayani semuanya; user cukup mengganti `base_url` dan `model`.
2. **Anthropic-compatible** — `POST {base_url}/v1/messages`, header `x-api-key: <key>` dan `anthropic-version`. Format pesan & respons berbeda dari OpenAI, jadi perlu adaptor sendiri.

Konfigurasi yang user isi di UI Settings:

| Field | Contoh | Catatan |
| --- | --- | --- |
| Provider | `openai-compatible` / `anthropic-compatible` | Memilih adaptor |
| Base URL | `https://api.openai.com/v1` atau `http://localhost:11434/v1` | Bisa endpoint lokal |
| Model | `gpt-4o`, `claude-sonnet-4-5`, `llama-3.1-70b` | String bebas |
| API key | `sk-...` | Disimpan terenkripsi |
| Parameter | suhu, max tokens | Opsional |

### Penyimpanan key (penting)

Ikuti pola CA yang sudah ada: **key disimpan DPAPI-protected di mesin user** (seperti `root-ca.key.dpapi`), tidak pernah ditulis ke log, History, atau snapshot. Redaksi rahasia yang sudah ada di engine harus mencakup header `Authorization`/`x-api-key` agar key tak bocor ke diagnostik. Panggilan keluar ke endpoint AI lewat jalur jaringan normal — tapi karena endpoint lokal (`localhost`, `127.0.0.1`) diizinkan oleh destination policy sementara endpoint cloud publik juga perlu diizinkan, panggilan AI harus lewat klien HTTP terpisah, bukan lewat proxy listener (persis seperti Replay yang mengirim langsung).

### Fitur Drop AI (bertahap)

- **Jelaskan request/response** — di Repeater, kirim request+response terpilih ke model, minta analisis kerentanan. Ini padanan "Burp AI in Repeater".
- **Sarankan payload** — untuk Intruder, minta model membuat payload set berdasarkan konteks parameter.
- **Triase temuan scanner** — tandai kemungkinan false positive, jelaskan isu, sarankan remediasi.
- **Draft laporan** — ubah temuan jadi paragraf laporan.
- **Kontrol penuh di tangan user** — setiap pengiriman ke AI bersifat eksplisit (tombol), bisa dimatikan total, dan menampilkan data apa yang akan dikirim sebelum mengirim.

> **Batas penting:** karena ini alat uji keamanan, data yang dikirim ke model bisa memuat kredensial/PII dari target. UI wajib menampilkan preview payload sebelum kirim, dan default-nya meredaksi rahasia yang terdeteksi kecuali user memilih mengirim mentah.

## Roadmap bertahap

Urutan dipilih agar tiap fase menghasilkan rilis yang berguna, dan agar yang paling cepat dibangun (menumpang inti yang ada) datang lebih dulu. Tidak ada estimasi tanggal karena bergantung pada tim; yang pasti adalah urutan ketergantungan.

&#91;embedded content: roadmap · 4 fase, tiap fase bisa dirilis sendiri\]

**Urutan direvisi (20 Okt).** Fase 1 lama (Repeater + site map + intercept + scope) **sudah SELESAI** — jadi titik mulai bergeser maju:

1. ~~**Intruder**~~ — ✅ **SELESAI** (engine `intruder.rs` + 4 command + tab Fuzzer; 9/9 acceptance test; keenam guardrail terpenuhi).
2. ~~**Decoder / Comparer**~~ — ✅ **SELESAI** (tab Decoder Alt+5 + Comparer Alt+6; Base64/URL/Hex/HTML/JWT + line diff; murni lokal).
3. **Drop AI (BYOK)** — pembeda utama; "Suggest Payloads" nyambung ke Intruder yang baru jadi.
4. **Scanner pasif** — hook read-only di jalur proxy, tanpa request tambahan.
5. **Scanner aktif + HTTP/2** — perlu keputusan arsitektur dulu (lihat Keputusan terbuka); scanner yang menulis ulang request harus sadar protokol.
6. **Sistem ekstensi, server OAST, generator laporan** — fitur skala besar, paling akhir.

**Kenapa H1 tetap dipertahankan (bukan pindah ke Hyper).** Security proxy butuh parser **transparan dan "bodoh"** yang bisa meneruskan request malformed apa adanya (request smuggling, desync, CL/TE conflict) — justru kelas bug yang jadi inti pentest. Library seperti `hyper` akan menormalkan/menolak request semacam itu dan membunuh kemampuan tersebut. Burp pun mempertahankan stack HTTP tulisan tangan demi alasan yang sama. Jadi `http1.rs` tetap dipakai. **HTTP/2 nanti ≠ harus telan Hyper**: bisa pakai crate `h2` sebagai framer sendiri sambil tetap pegang kontrol byte, atau h2 di-blind-passthrough (tak didekripsi) seperti non-allowlisted sekarang. Ditunda, **tidak** dilupakan.

## Keputusan terbuka

Hal-hal yang perlu kamu putuskan sebelum atau selama pengembangan:

1. **Lisensi open source.** Burp Community dulu memakai lisensi non-komersial yang membatasi. Untuk benar-benar open source, pilih lisensi permisif (MIT/Apache-2.0) atau copyleft (GPL/AGPL). AGPL mencegah orang menjual versi tertutup berbasis kode kita; MIT paling bebas. Ini keputusan strategis, bukan teknis.
2. **Nama & merek.** Jangan pakai istilah milik PortSwigger (BApp, BChecks, Bambdas, Montoya, Collaborator). Dokumen ini memakai nama sementara (DropApps, DropChecks, OAST server). Perlu dipastikan "DropSuite" sendiri tidak bentrok merek.
3. **Cakupan Fase 1.** Apakah MVP cukup Repeater + site map + intercept, atau kamu mau Drop AI ikut di Fase 1 karena itu pembeda utama? (Lihat komentar di dokumen.)
4. **Browser headless untuk crawler.** Pilihan: embed Chromium (berat, \~150MB, tapi render JS penuh seperti Burp) atau mulai dengan crawler non-JS yang ringan. Memengaruhi ukuran rilis.
4b. **HTTP/2 — kapan & bagaimana.** Ditunda sadar (H1 menutup 95%+ kebutuhan _sekarang_), tapi ini _known gap_ nyata untuk klaim "Pro": makin banyak target h2-only, dan ada kelas bug (desync/smuggling) yang khas h2. Keputusan: pakai crate `h2` sebagai framer transparan sendiri, atau blind-passthrough h2 tanpa dekripsi? Ambil keputusan ini **sebelum** scanner aktif, karena scanner yang menulis ulang request harus sadar protokol. Jangan adopsi `hyper` (merusak transparansi — lihat Roadmap).
5. **Server OAST.** Butuh domain + server yang menerima koneksi masuk DNS/HTTP. Apakah kita sediakan instance publik (seperti Collaborator), biarkan user self-host, atau tunda ke Fase 4+? Ada biaya operasional jika kita host.
6. **Target platform.** RC1 saat ini Windows (DPAPI, WebView2). Apakah open source ini tetap Windows-only dulu, atau lintas platform (Linux/macOS) — yang berarti mengganti DPAPI dengan keyring OS lain.

### Catatan keamanan yang harus dijaga

Semua modul baru **wajib lewat engine inti** agar mewarisi jaminannya: destination policy (tak bisa menembak endpoint metadata cloud), redaksi rahasia, dan CA eksplisit. Khususnya Scanner dan Intruder yang mengirim banyak request otomatis — mereka harus memakai `is_restricted_destination` yang sama, dan key Drop AI harus masuk daftar redaksi. Jangan pernah menonaktifkan cek keamanan demi kecepatan scanner.

> Dokumen ini peta rencana, bukan kode. Sudah SELESAI & terverifikasi end-to-end: fase dasar, **Intruder/Fuzzer**, **Decoder/Comparer**, dan **Drop AI (BYOK) MVP** (config+key DPAPI+test+Suggest payloads). **Langkah berikutnya:** perluas Drop AI (Explain di Replay, Triase, Draft laporan) atau mulai **Scanner pasif**. Yang masih besar & belum: Scanner, HTTP/2, sistem ekstensi, OAST, reporting.
