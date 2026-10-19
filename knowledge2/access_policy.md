# Kebijakan Pembukaan Akses Network

## Syarat Wajib Server

Sebelum akses dibuka, SOURCE dan DESTINATION wajib memenuhi tiga kontrol sekaligus:
EDR aktif, PAM aktif, dan VA aktif (server discan berkala).
Jika salah satu kontrol belum terpenuhi pada salah satu server, permintaan DITOLAK
sampai server tersebut diperbaiki. Syarat ini berlaku untuk semua environment (PROD, UAT, DEV)
dan lebih ketat daripada compliance harian.

## Kelengkapan Permintaan

Permintaan akses harus memuat: IP source, IP destination, port, protocol, justifikasi bisnis,
pemilik aplikasi, dan masa berlaku. Server yang tidak terdaftar di CMDB tidak boleh diberi akses
sebelum didaftarkan.

## Prinsip Least Privilege

- Gunakan port spesifik, bukan range port.
- Gunakan IP spesifik, bukan subnet atau any.
- Akses sementara wajib punya tanggal kedaluwarsa, maksimal 30 hari.
- Akses permanen wajib direcertify setiap 6 bulan.

## Aturan Zona

- Source dari DMZ atau public-facing dilarang mengakses database secara langsung. Akses harus lewat server APP.
- Akses ke database hanya boleh berasal dari segment APP.
- Akses lintas environment yang melibatkan PROD (misalnya DEV ke PROD) memerlukan persetujuan khusus.

## Dampak Vulnerability

- Destination dengan vulnerability Critical tidak boleh disetujui penuh. Persetujuan hanya dengan syarat patch sesuai SLA atau mitigasi sementara.
- Source dengan vulnerability Critical berisiko menjadi titik lateral movement, sehingga perlu syarat perbaikan.
- Server yang belum pernah discan VA dianggap berisiko dan perlu discan sebelum akses diberikan.

## Tingkat Keputusan

- DENY: ada pelanggaran wajib (kontrol tidak lengkap, port dilarang, zona dilarang, aset tidak terdaftar).
- REVIEW_REQUIRED: skor risiko tinggi (60 ke atas) atau port tidak ada di pedoman, perlu review manual oleh Security.
- APPROVE_WITH_CONDITIONS: skor 30 sampai 59 atau ada vulnerability Critical, disetujui dengan syarat.
- APPROVE: skor di bawah 30 tanpa pelanggaran.
