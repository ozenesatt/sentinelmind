"""
SentinelMind AI — Filtreleme & Önceliklendirme Motoru
Sahiplik: Sıla (Tespit & AI)

Görev:
  1. Prowler OCSF bulgularını yükle
  2. PASS'leri ele, sadece FAIL bulguları al (gerçek bulgular)
  3. Her bulguya deterministik risk skoru (0-100) ver
  4. Skora göre önceliklendir (yüksekten düşüğe sırala)

Risk skoru modeli (CVSS Base + Environmental mantığının CSPM'e uyarlaması):
  Risk = Base(severity) + Exposure + Sensitivity   → 0-100'e sıkıştırılır

  - Base:        zafiyetin içsel ciddiyeti (Prowler severity)
  - Exposure:    dışarıya açıklık (internet-exposed = en güçlü risk sinyali)
  - Sensitivity: ihlal edilirse veri/kimlik riski (secrets, identity, encryption)

  Not: "compliance yoğunluğu" faktörü v2 için planlandı — bkz. README.
"""

import json
from pathlib import Path

DATA = Path("output/prowler-71-findings.ocsf.json")

# --- Skor tabloları (deterministik, açıklanabilir) ---

# Base: severity → puan
BASE_SCORE = {
    "Critical": 60,
    "High": 45,
    "Medium": 25,
    "Low": 10,
}

# Exposure: dışarıya açıklık sinyali (kategori bazlı)
EXPOSURE_SCORE = {
    "internet-exposed": 25,
}

# Sensitivity: ihlal halinde veri/kimlik riski (kategori bazlı)
SENSITIVITY_SCORE = {
    "secrets": 15,
    "identity-access": 15,
    "encryption": 10,
}

# Auditability: denetlenebilirlik / KVKK izi (log yoksa ihlal raporlanamaz)
AUDITABILITY_SCORE = {
    "logging": 8,
    "forensics-ready": 8,
}


def get_categories(finding: dict) -> list:
    """Bir bulgunun kategori listesini döner (unmapped.categories)."""
    return finding.get("unmapped", {}).get("categories", [])


def score_finding(finding: dict) -> dict:
    """
    Tek bir bulguya risk skoru hesaplar.
    Skorun yanında GEREKÇE de döner (açıklanabilirlik için).
    """
    severity = finding.get("severity", "Low")
    categories = get_categories(finding)

    # 1) Base — severity'den
    base = BASE_SCORE.get(severity, 10)

    # 2) Exposure — kategori bazlı, en yükseğini al
    exposure = max((EXPOSURE_SCORE.get(c, 0) for c in categories), default=0)

    # 3) Sensitivity — kategori bazlı, en yükseğini al
    sensitivity = max((SENSITIVITY_SCORE.get(c, 0) for c in categories), default=0)

    # 4) Auditability — KVKK denetlenebilirlik (log tutuluyor mu)
    auditability = max((AUDITABILITY_SCORE.get(c, 0) for c in categories), default=0)

    # Toplam, 0-100'e sıkıştır
    total = min(base + exposure + sensitivity + auditability, 100)

    # Gerekçe: her puanın nereden geldiği (analiste ve sunuma şeffaflık)
    rationale = []
    rationale.append(f"severity={severity} (+{base})")
    if exposure:
        rationale.append(f"exposure (+{exposure})")
    if sensitivity:
        rationale.append(f"sensitivity (+{sensitivity})")
    if auditability:
        rationale.append(f"auditability (+{auditability})")

    return {
        "score": total,
        "severity": severity,
        "categories": categories,
        "rationale": "; ".join(rationale),
        "event_code": finding.get("metadata", {}).get("event_code", "?"),
        "message": finding.get("message", "")[:100],
    }


def main():
    findings = json.loads(DATA.read_text(encoding="utf-8"))

    # 2) Filtrele: sadece FAIL
    fails = [f for f in findings if f.get("status_code") == "FAIL"]
    print(f"Toplam bulgu: {len(findings)} | FAIL: {len(fails)} | PASS: {len(findings) - len(fails)}")

    # 3) Skorla
    scored = [score_finding(f) for f in fails]

    # 4) Önceliklendir: skora göre yüksekten düşüğe
    scored.sort(key=lambda x: x["score"], reverse=True)

    # Sonucu göster
    print("\n" + "=" * 90)
    print("ÖNCELİKLENDİRİLMİŞ BULGULAR (yüksek → düşük risk)")
    print("=" * 90)
    for i, s in enumerate(scored, 1):
        print(f"{i:2}. [{s['score']:3}] {s['event_code']}")
        print(f"      {s['rationale']}")

    # Özet istatistik
    print("\n" + "=" * 90)
    print("ÖZET")
    print("=" * 90)
    high_risk = [s for s in scored if s["score"] >= 60]
    print(f"Yüksek risk (skor ≥ 60): {len(high_risk)} bulgu")
    print(f"En yüksek skor: {scored[0]['score']} ({scored[0]['event_code']})")
    print(f"En düşük skor:  {scored[-1]['score']} ({scored[-1]['event_code']})")


if __name__ == "__main__":
    main()