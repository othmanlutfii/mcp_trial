# Alur review permintaan pembukaan akses

Dokumen ini menelusuri satu input dari saat diketik sampai jawaban ditampilkan.
Contoh yang digunakan:

> Buka akses dari 10.10.17.120 ke 10.80.35.246 port 443

## Ringkasan jalur

```text
Pengguna
  -> main.py
  -> secbot/graph.py: build_graph() dan run_once()
  -> secbot/graph.py: router node
  -> secbot/router.py: ekstrak IP/port dan pilih access_review
  -> secbot/graph.py: access_review node
  -> secbot/agents/access_agents.py: tiga tahap review
       1. Assessment Agent -> assess_connection (perhitungan kode)
       2. Policy Agent -> search_knowledge (pencarian kebijakan)
       3. Reviewer Agent -> menyusun jawaban dari hasil tahap 1 dan 2
  -> pesan jawaban disimpan di state LangGraph
  -> secbot/graph.py: run_once() mencetak jawaban
```

## Langkah demi langkah

### 1. Input diterima aplikasi

Jika aplikasi dijalankan dengan `python main.py`, pintu masuknya adalah
[main.py](./main.py), yang memanggil `secbot.graph.main()`. Dalam mode interaktif,
teks yang diketik dikirim ke `run_once()` di [secbot/graph.py](./secbot/graph.py).
Mode sekali jalan juga mengirim pertanyaan yang sama ke fungsi tersebut.

`run_once()` meneruskan pertanyaan sebagai pesan pengguna ke grafik LangGraph.
Grafik dibuat oleh `build_graph()`, dan alur setiap pesan dimulai dari node
`router`.

### 2. Router mengenali permintaan akses

Node router di [secbot/graph.py](./secbot/graph.py) mengambil teks pesan terakhir
dan memanggil `router.decide()` di [secbot/router.py](./secbot/router.py).

Untuk contoh ini, router:

1. Mengambil IP valid secara berurutan: `10.10.17.120` lalu `10.80.35.246`.
   IP pertama dianggap source, IP kedua destination.
2. Mengenali `443` dari pola `port 443`.
3. Memastikan port berada dalam rentang `1–65535`.
4. Mendapatkan permintaan lengkap: source, destination, dan port sudah ada.
   Protocol tidak ditulis, jadi diisi default `tcp`.
5. Memilih rute `access_review`. Karena datanya lengkap, router tidak perlu
   bertanya kepada LLM untuk menentukan rute.

Request yang diserahkan ke node berikutnya secara konseptual adalah:

```python
{
    "src_ip": "10.10.17.120",
    "dst_ip": "10.80.35.246",
    "port": 443,
    "protocol": "tcp",
}
```

### 3. Node review memeriksa kelengkapan

Node `access_review` di [secbot/graph.py](./secbot/graph.py) mengecek apakah
source, destination, dan port sudah tersedia. Jika belum lengkap, node meminta
pengguna melengkapinya dan menyimpan data sementara sebagai `pending_request`.
Untuk contoh ini semua field wajib tersedia, sehingga review dilanjutkan dengan
pemanggilan `review_access()`.

### 4. Assessment menghitung fakta dan risiko

Fungsi `review_access()` di [secbot/agents/access_agents.py](./secbot/agents/access_agents.py)
membuat Assessment Agent. Agen diminta memanggil tool
`assess_connection` satu kali.

Perhitungan utama dilakukan oleh kode di
[secbot/agents/access_tools.py](./secbot/agents/access_tools.py), bukan oleh LLM:

- Validasi kedua IP, port, dan protocol.
- Cari data aset di [data/assets.json](./data/assets.json).
- Cari data vulnerability di [data/vulns.json](./data/vulns.json).
- Periksa kontrol wajib EDR/PAM/VA, aturan port, zona/segment, dan severity.
- Hitung skor, level risiko, dan keputusan awal.

Jika agen tidak memanggil tool, `review_access()` memanggil tool itu secara
langsung agar hasil assessment tetap dihitung oleh kode. Jika input tidak valid,
tool mengembalikan error dan proses berhenti dengan pesan bahwa permintaan tidak
dapat dinilai.

#### Data yang ditemukan untuk contoh

| Peran | IP | Aset | Kontrol EDR/PAM/VA | Vulnerability |
|---|---|---|---|---|
| Source | `10.10.17.120` | `srv-core-app02`, Core Banking, DEV, APP | Semua aktif | High |
| Destination | `10.80.35.246` | `srv-idm-db04`, Identity Management, UAT, DB | Semua aktif | High |

Untuk port `443`, aturan di [secbot/policies.py](./secbot/policies.py)
menyebutnya sebagai HTTPS (`ALLOWED`). Destination berada di segmen DB, tetapi
port 443 bukan salah satu port database yang dibatasi khusus oleh aturan kode.
Kedua aset terdaftar dan seluruh kontrol wajib untuk gate akses aktif.

Skor contoh dihitung sebagai berikut:

| Temuan | Tambahan skor |
|---|---:|
| Vulnerability High pada source | 8 |
| Vulnerability High pada destination | 15 |
| **Total** | **23** |

Skor dibatasi maksimum 100. Skor 23 masuk level risiko `LOW` (di bawah 30).
Tidak ada hard block, skor di bawah 30, port dikenal/diizinkan, dan tidak ada
kondisi lain yang mengubah keputusan. Karena itu keputusan awal kode adalah
`APPROVE`.

### 5. Policy Agent mencari aturan knowledge base

Policy Agent di [secbot/agents/access_agents.py](./secbot/agents/access_agents.py)
menggunakan tool `search_knowledge` dari [secbot/tools.py](./secbot/tools.py).
Query-nya dibentuk dari hasil assessment, termasuk port, layanan, segment source
dan destination, serta environment.

Pencarian mengambil potongan dokumen paling relevan dari vector database
knowledge base, yang sumbernya berupa dokumen Markdown di folder `knowledge/`.
Hasil pencarian diminta untuk mencakup syarat pembukaan akses, pedoman port, dan
aturan zona. Bila indeks knowledge base belum dibuat, tool mengembalikan
keterangan bahwa ingest perlu dijalankan; hasilnya bukan berarti aturan dianggap
tidak ada.

### 6. Reviewer Agent menyusun jawaban

Reviewer Agent menerima dua masukan dari `review_access()`:

1. Data assessment mentah dari tool `assess_connection`, termasuk skor dan
   `preliminary_decision`.
2. Ringkasan aturan yang ditemukan Policy Agent.

LLM menyusun narasi, ringkasan, compliance, vulnerability, penilaian port/zona,
rekomendasi, dan referensi. Prompt reviewer melarangnya mengarang fakta dan
melarang keputusan akhir menjadi lebih longgar daripada keputusan awal kode.
Dengan demikian LLM merangkai penjelasan berdasarkan hasil tool; ia tidak
menghitung ulang skor risiko.

### 7. Jawaban dikembalikan dan ditampilkan

Teks hasil reviewer dikembalikan ke node `access_review` sebagai pesan AI.
LangGraph menyimpan pesan itu dalam state percakapan. Setelah grafik selesai,
`run_once()` mengambil pesan AI terakhir dan mencetaknya ke terminal sebagai
jawaban bot.

Untuk contoh ini, hasil assessment menetapkan **keputusan awal `APPROVE`, risiko
`LOW`, skor 23**. Kalimat rekomendasi dan format jawaban akhir dibuat oleh LLM,
sehingga redaksi persisnya dapat berbeda antar-provider/model.

## Bagian deterministik dan bagian LLM

| Bagian | Yang dikerjakan |
|---|---|
| Router | Ekstraksi IP/port dan pemilihan rute berdasarkan aturan; LLM hanya cadangan untuk klasifikasi yang tidak jelas |
| `assess_connection` | Validasi, lookup data, pemeriksaan kebijakan terkode, skor risiko, dan keputusan awal |
| Policy Agent | Meminta tool mencari aturan di knowledge base dan merangkum hasil pencarian |
| Reviewer Agent | Menarasikan assessment dan aturan menjadi jawaban yang mudah dibaca |

Jadi, keputusan angka dan keputusan awal berasal dari kode serta data aplikasi.
Model bahasa membantu klasifikasi cadangan, pencarian/ringkasan kebijakan, dan
penulisan jawaban akhir.
