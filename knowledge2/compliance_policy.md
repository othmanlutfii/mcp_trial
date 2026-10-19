# Kebijakan Compliance Aset

## Syarat Compliance per Environment

Setiap server wajib memenuhi kontrol keamanan berikut sesuai environment-nya.

- **PROD**: wajib EDR, PAM, dan VA (ketiganya harus aktif).
- **UAT**: wajib EDR dan VA.
- **DEV**: wajib EDR.

Server yang tidak memenuhi syarat dianggap NON-COMPLIANT dan harus diperbaiki.

## Penjelasan Kontrol

- **EDR** (Endpoint Detection and Response): agen deteksi ancaman pada server.
- **PAM** (Privileged Access Management): akses admin harus melalui vault PAM, tidak boleh login langsung.
- **VA** (Vulnerability Assessment): server wajib discan minimal setiap bulan.

## Server Public-Facing

Server dengan segment DMZ atau ip_category public-facing wajib EDR tanpa terkecuali,
serta wajib dilakukan scan VA setiap minggu.
