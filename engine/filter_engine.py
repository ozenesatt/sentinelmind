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
from collections import defaultdict

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

def get_resource_name(finding: dict) -> str:
    """
    Bir bulgunun etkilediği kaynağın adını döner.
    Yol: resources[0].data.metadata.name  (keşifte doğruladık)
    Bulunamazsa 'subscription-level' döner (bazı bulgular kaynak-bağımsızdır).
    """
    resources = finding.get("resources", [])
    if not resources:
        return "subscription-level"
    meta = resources[0].get("data", {}).get("metadata", {})
    return meta.get("name") or "subscription-level"

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
        "resource": get_resource_name(finding),
        "rationale": "; ".join(rationale),
        "event_code": finding.get("metadata", {}).get("event_code", "?"),
        "message": finding.get("message", "")[:100],
    }

def report_by_resource(scored_findings: list):
    """
    B GÖRÜNÜMÜ — Kaynağa göre risk profili.
    'Hangi kaynak en riskli?' sorusunu cevaplar.
    Her kaynağın: bulgu sayısı + toplam risk + en yüksek tekil skor.
    """
    from collections import defaultdict

    # kaynak -> o kaynağın bulguları (skorlarıyla)
    by_res = defaultdict(list)
    for s in scored_findings:
        by_res[s["resource"]].append(s)

    # Her kaynak için özet çıkar
    summaries = []
    for resource, items in by_res.items():
        total = sum(i["score"] for i in items)
        max_score = max(i["score"] for i in items)
        summaries.append({
            "resource": resource,
            "count": len(items),
            "total_risk": total,
            "max_score": max_score,
        })

    # En riskli kaynak üstte: toplam riske göre sırala
    summaries.sort(key=lambda x: x["total_risk"], reverse=True)

    print("\n" + "=" * 90)
    print("B GÖRÜNÜMÜ — KAYNAK BAZLI RİSK PROFİLİ (en riskli → en az)")
    print("=" * 90)
    for s in summaries:
        print(f"  {s['resource']}")
        print(f"     bulgu sayısı: {s['count']:2}  |  toplam risk: {s['total_risk']:4}  |  en yüksek tekil skor: {s['max_score']}")

def report_by_control(scored_findings: list):
    """A GÖRÜNÜMÜ — Kontrole göre gruplama. 'Aynı hata nerede tekrarlıyor?'"""
    by_code = defaultdict(list)
    for s in scored_findings:
        by_code[s["event_code"]].append(s)

    # Her kontrol için: kaç kaynak, hangi skor, hangi kaynaklar
    groups = []
    for code, items in by_code.items():
        groups.append({
            "event_code": code,
            "count": len(items),
            "score": items[0]["score"],  # aynı kontrol = aynı skor
            "resources": [i["resource"] for i in items],
        })

    # Önce en çok tekrar edenler, sonra skora göre
    groups.sort(key=lambda x: (x["count"], x["score"]), reverse=True)

    print("\n" + "=" * 90)
    print("A GÖRÜNÜMÜ — KONTROL BAZLI GRUPLAMA (tekrar eden hatalar üstte)")
    print("=" * 90)
    for g in groups:
        tekrar = f"{g['count']}x" if g["count"] > 1 else "1x"
        print(f"  [{g['score']:3}] [{tekrar}] {g['event_code']}")
        if g["count"] > 1:
            print(f"        etkilenen kaynaklar: {', '.join(g['resources'])}")

    # Özet: kaç tekil kontrol, kaç tanesi tekrarlıyor
    multi = [g for g in groups if g["count"] > 1]
    print(f"\n  Toplam {len(groups)} tekil kontrol, {len(multi)} tanesi birden fazla kaynakta.")

def main():
    findings = json.loads(DATA.read_text(encoding="utf-8"))

    # 2) Filtrele: sadece FAIL
    fails = [f for f in findings if f.get("status_code") == "FAIL"]
    print(f"Toplam bulgu: {len(findings)} | FAIL: {len(fails)} | PASS: {len(findings) - len(fails)}")

    # 3) Skorla
    scored = [score_finding(f) for f in fails]

    # 4) Önceliklendir: skora göre yüksekten düşüğe
    scored.sort(key=lambda x: x["score"], reverse=True)

    # B görünümü: kaynak bazlı risk profili
    report_by_resource(scored)

    # A görünümü: kontrol bazlı gruplama
    report_by_control(scored)

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