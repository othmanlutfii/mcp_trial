# Kebijakan Compliance Aset

## Overview

Kebijakan: Kebijakan Compliance Aset.
Tujuan: menetapkan kontrol keamanan yang wajib dipenuhi setiap server sesuai environment dan segmennya.
Kontrol yang dibahas: EDR, PAM, VA.
Environment: PROD, UAT, DEV. Segmen: LAN, Server Farm, DMZ.
Prinsip umum 1: kewajiban kontrol ditentukan oleh environment (PROD, UAT, DEV) dan dimodifikasi oleh segmen jaringan server (LAN, Server Farm, DMZ).
Prinsip umum 2: server yang tidak memenuhi syarat dianggap NON-COMPLIANT dan harus diperbaiki.
Tidak dinyatakan: kewajiban kontrol untuk environment Pre-Prod tidak disebutkan dalam kebijakan ini.

## Syarat Compliance per Environment

### Aturan C-1: Environment PROD

Kebijakan: Kebijakan Compliance Aset. Kategori: Syarat Compliance per Environment.
Environment: PROD.
Kontrol wajib: EDR, PAM, dan VA (ketiganya harus aktif).
Pengecualian: lihat Aturan C-5 (segmen LAN).
Ringkasan: Server PROD wajib memiliki EDR, PAM, dan VA aktif sekaligus.

### Aturan C-2: Environment UAT

Kebijakan: Kebijakan Compliance Aset. Kategori: Syarat Compliance per Environment.
Environment: UAT.
Kontrol wajib: EDR dan VA.
Kontrol tidak wajib: PAM.
Pengecualian: lihat Aturan C-5 (segmen LAN).
Ringkasan: Server UAT wajib memiliki EDR dan VA aktif. PAM tidak wajib.

### Aturan C-3: Environment DEV

Kebijakan: Kebijakan Compliance Aset. Kategori: Syarat Compliance per Environment.
Environment: DEV.
Kontrol wajib: EDR.
Kontrol tidak wajib: PAM dan VA.
Ringkasan: Server DEV hanya wajib memiliki EDR aktif.

### Aturan C-4: Status NON-COMPLIANT

Kebijakan: Kebijakan Compliance Aset. Kategori: Syarat Compliance per Environment.
Kondisi: server tidak memenuhi kontrol wajib sesuai environment dan segmennya.
Status: NON-COMPLIANT.
Tindakan: server harus diperbaiki.
Ringkasan: Server yang tidak memenuhi kontrol wajib dianggap NON-COMPLIANT dan harus diperbaiki.

## Pengecualian Berdasarkan Segmen

### Aturan C-5: Segmen LAN

Kebijakan: Kebijakan Compliance Aset. Kategori: Pengecualian Segmen.
Segmen: LAN.
Kontrol tidak wajib: PAM dan VA.
Kontrol yang tetap berlaku: EDR (kewajiban EDR tidak dikecualikan).
Berlaku untuk: semua environment.
Ringkasan: Server di segmen LAN tidak wajib PAM dan VA. EDR tetap wajib.

### Aturan C-6: Server Farm atau DMZ Non-Production

Kebijakan: Kebijakan Compliance Aset. Kategori: Pengecualian Segmen.
Segmen: Server Farm atau DMZ.
Environment: non-production (UAT dan DEV).
Kontrol tidak wajib: PAM.
Dampak: UAT di Server Farm/DMZ wajib EDR dan VA. DEV di Server Farm/DMZ wajib EDR. PROD di Server Farm/DMZ tidak mendapat pengecualian, tetap wajib EDR, PAM, dan VA.
Ringkasan: Server non-production di Server Farm atau DMZ tidak wajib PAM.

## Matriks Kontrol Wajib

### Aturan C-7: Ringkasan Kontrol Wajib per Environment dan Segmen

Kebijakan: Kebijakan Compliance Aset. Kategori: Ringkasan.
Server Farm atau DMZ, PROD: EDR, PAM, VA.
Server Farm atau DMZ, UAT: EDR, VA.
Server Farm atau DMZ, DEV: EDR.
LAN, semua environment: EDR (PAM dan VA tidak wajib).
Ringkasan: Matriks di atas menunjukkan kontrol wajib akhir setelah menggabungkan syarat per environment dengan pengecualian segmen.

## Penjelasan Kontrol

### Kontrol EDR

Kebijakan: Kebijakan Compliance Aset. Kategori: Penjelasan Kontrol.
Kontrol: EDR (Endpoint Detection and Response).
Definisi: agen deteksi ancaman pada server.

### Kontrol PAM

Kebijakan: Kebijakan Compliance Aset. Kategori: Penjelasan Kontrol.
Kontrol: PAM (Privileged Access Management).
Definisi: akses admin harus melalui vault PAM, tidak boleh login langsung.

### Kontrol VA

Kebijakan: Kebijakan Compliance Aset. Kategori: Penjelasan Kontrol.
Kontrol: VA (Vulnerability Assessment).
Definisi: server wajib discan minimal setiap bulan.