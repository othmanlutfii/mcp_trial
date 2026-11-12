# SLA Remediasi Vulnerability

## Level Temuan VA

Setiap temuan vulnerability dari Tenable.sc dengan **VPR >= 8**
dikategorikan **Critical**, dan temuan di luar kriteria tersebut
dikategorikan **Non-Critical**.

VPR digunakan untuk menentukan level temuan, bukan untuk menentukan temuan mana yang perlu ditindaklanjuti.
Seluruh temuan, baik Critical maupun Non-Critical, wajib diremediasi sesuai SLA pada ketentuan bagian Batas Waktu Perbaikan.

Apabila IP pada form tidak ditemukan di Tenable.sc atau belum pernah
di-scan, sampaikan bahwa status VA tidak dapat dinilai, server harus di-scan VA terlebih dahulu.

## Batas Waktu Perbaikan

| Level Temuan | Kriteria | SLA |
|---|---|---|
| Critical | VPR >= 8 | 90 hari |
| Non-Critical | Selain kriteria Critical | 180 hari |

Untuk aplikasi yang akan go-live, seluruh temuan Critical maupun
Non-Critical wajib diselesaikan sebelum release ke production.

## Rekomendasi Tindak Lanjut

Sampaikan rekomendasi berikut kepada requestor apabila terdapat temuan VA:

> Temuan VA wajib diremediasi oleh tim pengelola server dan aset owner sesuai SLA level temuannya.
> Validasi temuan, tentukan patch atau perbaikan konfigurasi yang sesuai, dan dokumentasikan komitmen perbaikan dalam Berita Acara Komitmen Perbaikan.

## Jika Temuan Belum Diremediasi

- **Critical**: tidak dapat diajukan accept risk. Temuan Critical yang melewati SLA 90 hari dieskalasikan kepada system owner, General Manager CISO, dan SORX4.
- **Non-Critical**: apabila belum dapat diremediasi, dapat diajukan accept risk dengan Berita Acara Komitmen Perbaikan yang disetujui pejabat setingkat Pemimpin Divisi pemilik aplikasi. Temuan tetap wajib diremediasi sesuai komitmen.

## Ketentuan Remediasi

1. Patch atau update yang digunakan harus berasal dari sumber resmi.
2. Lakukan pengujian sebelum diimplementasikan.
3. Setelah remediasi, ajukan re-scan ke CISO untuk memastikan temuan
   tertutup.


<!-- # SLA Remediasi Vulnerability

## Temuan VA dengan VPR di Atas 8

Setiap temuan vulnerability dari Tenable.sc dengan **VPR >= 8** dikategorikan **Critical** dan temuan di luar kriteria tersebut dikategorikan **Non-Critical**. 
Seluruh temuan wajib ditindaklanjuti untuk diremediasi.
Untuk server, tim server pemilik aset bertanggung jawab memvalidasi temuan, menyusun rencana perbaikan, dan menjadwalkan pemasangan patch atau mitigasi.
Temuan pada endpoint diteruskan kepada tim pemilik endpoint yang bertanggung jawab.

Rekomendasi tindak lanjut:

> Temuan VA dengan VPR >= 8 wajib diremediasi oleh tim server pemilik aset.
> Validasi temuan, tentukan patch atau mitigasi yang sesuai, dan lakukan
> pemindaian VA ulang setelah perbaikan untuk memastikan temuan telah tertutup.

VPR digunakan untuk menentukan level temuan, bukan untuk menentukan temuan mana yang perlu ditindaklanjuti. Seluruh temuan, baik Critical maupun Non-Critical, wajib diremediasi sesuai SLA pada tabel berikut.
Jika remediasi tidak dapat diselesaikan dalam SLA, ikuti ketentuan pada bagian Jika Patch Tidak Bisa Segera Dipasang.

## Batas Waktu Perbaikan

| Severity | Kriteria | SLA |
|---|---|---|
| Critical | VPR >= 8 | 90 hari |
| Non-Critical | Selain kriteria Critical | 180 hari |

## Jika Patch Tidak Bisa Segera Dipasang

Ajukan exception ke tim Security dengan menyertakan mitigasi sementara, misalnya
pembatasan akses lewat firewall, virtual patching di WAF/IPS, atau menonaktifkan service yang rentan.
Exception maksimal 30 hari dan wajib disetujui Head of Security.

## Langkah Umum Patching

1. Backup atau snapshot server.
2. Terapkan patch di UAT terlebih dahulu bila tersedia.
3. Jadwalkan change window untuk PROD.
4. Lakukan patch, restart service, lalu verifikasi.
5. Jalankan scan VA ulang untuk memastikan temuan tertutup.

## Ketentuan Remediasi

1. Patch atau update yang digunakan harus berasal dari sumber resmi.
2. Lakukan pengujian sebelum diimplementasikan.
3. Setelah remediasi, ajukan re-scan ke CISO untuk memastikan temuan tertutup. -->