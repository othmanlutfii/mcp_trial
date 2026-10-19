# Pedoman Port

## Port Dilarang (PROHIBITED)

Port berikut tidak boleh dibuka karena protokolnya tidak terenkripsi atau terlalu berisiko.

| Port | Layanan | Alternatif |
|---|---|---|
| 21 | FTP | Gunakan SFTP (port 22) |
| 23 | Telnet | Gunakan SSH (port 22) |
| 69 | TFTP | Gunakan SFTP atau HTTPS |
| 135, 139 | RPC dan NetBIOS | Gunakan SMB signed terbatas (445) bila perlu |

## Port Terbatas (RESTRICTED)

Port berikut hanya boleh dibuka dengan justifikasi, IP spesifik, dan masa berlaku.

| Port | Layanan | Catatan |
|---|---|---|
| 22 | SSH | Hanya dari jump server atau PAM, gunakan key-based |
| 3389 | RDP | Tidak boleh dari zona publik, wajib lewat PAM atau jump host |
| 445 | SMB | Hanya antar server internal satu zona, nonaktifkan SMBv1 |
| 5985, 5986 | WinRM | Hanya dari server manajemen, utamakan 5986 (HTTPS) |

## Port Database

Port database: 1433 (MSSQL), 1521 (Oracle), 3306 (MySQL), 5432 (PostgreSQL).
Hanya boleh diakses dari segment APP dengan IP server aplikasi yang spesifik.
Dilarang diakses langsung dari DMZ, public-facing, atau workstation pengguna.
Akses administrasi database harus melalui PAM.

## Port Diizinkan (ALLOWED)

Port web standar: 80 (HTTP, sebaiknya redirect ke HTTPS), 443 (HTTPS), 8080 dan 8443 (aplikasi web).
Tetap berlaku prinsip least privilege dan syarat wajib server.

## Port Tidak Dikenal

Port di luar daftar ini memerlukan penjelasan layanan dan review manual oleh Security.
