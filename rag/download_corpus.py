"""
SentinelMind AI — RAG corpus indirme scripti.

MITRE ATT&CK ve KVKK belgelerini otomatik indirir.
CIS Benchmark form/lisans gerektirdiği için manuel indirilir (bkz. README).

Kullanım:
    python rag/download_corpus.py
"""

import sys
import urllib.request
from pathlib import Path

# Script'in bulunduğu klasör (rag/), ona göre corpus yolu
BASE = Path(__file__).resolve().parent
CORPUS = BASE / "corpus"

# İndirilecek belgeler: (hedef yol, URL, beklenen minimum boyut - byte)
DOWNLOADS = [
    (
        CORPUS / "mitre" / "enterprise-attack.json",
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
        1_000_000,  # ~51 MB beklenir; 1 MB altı = hatalı yanıt
    ),
    (
        CORPUS / "kvkk" / "kvkk-6698.pdf",
        "https://www.mevzuat.gov.tr/MevzuatMetin/1.5.6698.pdf",
        50_000,  # ~450 KB beklenir
    ),
]

# Bazı devlet siteleri User-Agent olmadan yanıt vermez; tarayıcı gibi görün
HEADERS = {"User-Agent": "Mozilla/5.0 (SentinelMind RAG corpus fetcher)"}


def download(target: Path, url: str, min_size: int) -> bool:
    """Tek bir belgeyi indirir. Zaten varsa atlar. Başarı durumunu döner."""
    if target.exists() and target.stat().st_size >= min_size:
        print(f"[atla] {target.name} zaten var ({target.stat().st_size:,} byte)")
        return True

    target.parent.mkdir(parents=True, exist_ok=True)
    print(f"[indir] {target.name} <- {url}")
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read()
    except Exception as e:
        print(f"  HATA: indirilemedi ({e})")
        return False

    if len(data) < min_size:
        print(f"  HATA: dosya çok küçük ({len(data):,} byte) — hatalı yanıt")
        return False

    target.write_bytes(data)
    print(f"  OK: {len(data):,} byte kaydedildi")
    return True


def main() -> int:
    ok = True
    for target, url, min_size in DOWNLOADS:
        if not download(target, url, min_size):
            ok = False

    # CIS manuel — sadece hatırlat
    cis = CORPUS / "cis" / "cis-azure-foundations.pdf"
    if not cis.exists():
        print("\n[manuel] CIS Azure Foundations eksik.")
        print("  https://downloads.cisecurity.org -> Microsoft Azure Foundations")
        print(f"  indir ve şuraya koy: {cis}")

    if not ok:
        print("\nBazı belgeler indirilemedi. KVKK'yı tarayıcıdan manuel deneyebilirsin.")
        return 1
    print("\nCorpus hazır.")
    return 0


if __name__ == "__main__":
    sys.exit(main())