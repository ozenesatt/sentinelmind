# RAG Corpus — SentinelMind AI

Bu klasör, AI katmanının (RAG) başvurduğu referans belgeleri barındırır.
Belgeler telif ve boyut nedeniyle repoya **commit edilmez** (`.gitignore`).
Aşağıdaki yöntemlerle her makinede yeniden indirilir.

## Belgeler

| Kaynak | Sürüm | Konum | Lisans / Not |
|---|---|---|---|
| MITRE ATT&CK Enterprise | master (en güncel) | `corpus/mitre/enterprise-attack.json` | Açık — MITRE ATT&CK Terms of Use |
| KVKK (6698 sayılı Kanun) | konsolide metin | `corpus/kvkk/kvkk-6698.pdf` | Kamuya açık mevzuat |
| CIS Microsoft Azure Foundations | v6.0.0 | `corpus/cis/cis-azure-foundations.pdf` | CIS — kişisel kullanım serbest, yeniden dağıtılamaz |

## Otomatik indirme (MITRE + KVKK)

    python rag/download_corpus.py

## Manuel indirme (CIS)

CIS Benchmark lisans/form nedeniyle otomatik indirilemez:

1. https://downloads.cisecurity.org adresine git
2. "Microsoft Azure" bölümünü aç → "Microsoft Azure Foundations" seç
3. PDF'i indir, `corpus/cis/cis-azure-foundations.pdf` olarak kaydet