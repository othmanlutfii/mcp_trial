# SLA Remediasi Vulnerability

## Batas Waktu Perbaikan

| Severity | Server PROD | Server Non-PROD |
|---|---|---|
| Critical | 7 hari | 14 hari |
| High | 14 hari | 30 hari |
| Medium | 30 hari | 60 hari |
| Low | 90 hari | 90 hari |

## Prioritas Perbaikan

Urutan prioritas: (1) Critical pada server PROD public-facing, (2) Critical pada PROD internal,
(3) High pada PROD, (4) sisanya sesuai SLA.

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
