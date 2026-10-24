# Roadmap DropSuite — Gabungan

Dua agen jalan paralel di folder sumber yang sama (`rea_software`),
dikoordinasikan lewat git. Terakhir diperbarui: 2026-10-24.

## Pembagian peran

- **DeepSeek — semua backend/mesin + command IPC.** Rust core (proxy, scanner,
  OAST, HTTP/2, dll) dan command Tauri yang menyajikannya ke UI. Termasuk semua
  fitur di Jalur A **dan** fitur Jalur B yang butuh backend.
- **Claude/Fraxzu — semua UI + shipping.** React/CSS/UX: panel, tombol, tampilan
  hasil, dan menyambungkan UI ke command DeepSeek. Plus urusan rilis (GitHub,
  release, code signing, lisensi) yang bukan fitur.

**Titik serah-terima = command IPC.** DeepSeek bikin fitur + expose command +
commit; Claude lihat di git lalu bangun UI-nya.

**Aturan:**
- DeepSeek daftarkan tiap command baru di **3 tempat** (`main.rs`, `build.rs`,
  `capabilities/main-window.json`) atau kena error ACL. Simpan file **UTF-8**.
- DeepSeek boleh bikin UI *stub* kasar, tapi **desain & polish UI = Claude**.
- Komunikasi lewat git (commit + pesan jelas), jangan saling menimpa.

---

## Jalur A — DeepSeek (teks asli, tidak diubah)

- [x] **Step 1-2: challenge detect, presets, jar, challenge browser**
- [x] **Step 3a: h2 ALPN + h2 upstream for Replay/Fuzzer**
- [ ] **Step 3b: h2 upstream for intercepted proxy traffic (stream request/response, chunked to client)**
- [ ] **Step 4: TLS ClientHello mimicry**
- [ ] **Step 5: active scanner with evidence/confidence + OOB server**

> Step 3b & 4 menyentuh `proxy.rs` (jalur paling sensitif: zero-egress, blokir
> metadata cloud). Jaga semua test keamanan tetap hijau sebagai gerbang.

### Backend untuk quick win (DeepSeek, UI-nya oleh Claude)
- [ ] Mesin **wordlist custom** untuk Content Discovery & Fuzzer (baca file) — *saat ini cuma 144 path bawaan*
- [ ] Fuzzer: mode **Pitchfork** & **Battering ram** + **Grep match/extract**
- [ ] Backend **Save / Load project** (engagement terpisah per target)
- [ ] (opsional) **WebSocket inspection**

> **Active scanner** = milik DeepSeek penuh (Step 5). Claude yang bikin UI-nya.

---

## Jalur B — Claude (UI + shipping)

### B1. Shipping — jadikan "aplikasi beneran" (prioritas sekarang)
- [ ] Push repo ke **GitHub** (privat dulu) — *repo & commit sudah siap, tinggal `gh auth login` + push*
- [ ] **Rilis pertama** di GitHub Releases (tag versi) → mengaktifkan auto-update
- [ ] **Code signing** installer → hilangkan peringatan SmartScreen
- [ ] **Pilih lisensi** (MIT / Apache-2.0 / GPL)
- [ ] Checklist sebelum public: keluarkan installer Burp + `docs/P0_REA_FINDINGS.md`, kosongkan URL default

### B2. UI untuk fitur DeepSeek (begitu command-nya siap)
- [ ] UI **active scanner** (daftar temuan, severity, evidence/confidence)
- [ ] UI **wordlist custom** (tombol "load wordlist" / file picker)
- [ ] UI **Fuzzer** Pitchfork/Battering ram + kolom Grep match/extract
- [ ] UI **Save / Load project**
- [ ] UI **OAST / WebSocket** (kalau DeepSeek garap backend-nya)
- [ ] Polish UI umum, aksesibilitas, konsistensi

---

## Sudah selesai

Proxy, HTTPS interception, Intercept, HTTP History + Clear, Site map, Scope,
Match & Replace, Replay multi-tab, Fuzzer (Sniper + Cluster bomb), Content
discovery, Decoder, Comparer, Passive Scanner, Drop AI, fingerprint/challenge/
cookie jar, HTTP/2 untuk Replay/Fuzzer, tampilan WIB, teks bisa disalin,
Settings (versi, cek update, start at login, logs/data folder, popup update).
