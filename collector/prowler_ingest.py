"""
Prowler OCSF JSON ciktisini events tablosuna aktarir.
Kullanim: python collector/prowler_ingest.py [dosya_yolu]
"""
import glob
import json
import os
import sys
from datetime import datetime

import psycopg2
from psycopg2.extras import Json
from dotenv import load_dotenv

load_dotenv()

SEVERITY_MAP = {1: 2, 2: 4, 3: 7, 4: 10, 5: 13}


def extract_mitre(finding: dict) -> list:
    compliance = finding.get("unmapped", {}).get("compliance", {})
    for key, value in compliance.items():
        if "MITRE" in key.upper():
            return list(value)
    return []


def to_event(finding: dict) -> tuple:
    info = finding.get("finding_info", {})
    meta = finding.get("metadata", {})
    resources = finding.get("resources") or [{}]
    res = resources[0]

    occurred_at = finding.get("time_dt")
    if occurred_at:
        occurred_at = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))

    return (
        "prowler",
        info.get("uid"),
        occurred_at,
        meta.get("event_code"),
        SEVERITY_MAP.get(finding.get("severity_id"), 0),
        info.get("title"),
        extract_mitre(finding),
        res.get("uid"),
        finding.get("status_code"),
        Json(finding),
    )


SQL = """
INSERT INTO events (
    source, external_id, occurred_at, rule_id, rule_level,
    rule_description, mitre_ids, resource_id, check_status, raw
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (external_id) DO UPDATE SET
    check_status = EXCLUDED.check_status,
    occurred_at  = EXCLUDED.occurred_at,
    raw          = EXCLUDED.raw
"""


def main():
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        matches = sorted(glob.glob("output/*.ocsf.json"))
        if not matches:
            sys.exit("Hata: output/ altinda .ocsf.json bulunamadi.")
        path = matches[-1]

    print(f"Okunuyor: {path}")
    with open(path, encoding="utf-8") as f:
        findings = json.load(f)

    conn = psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "sentinelmind"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD"),
    )

    inserted = skipped = 0
    with conn, conn.cursor() as cur:
        for finding in findings:
            row = to_event(finding)
            if not row[1]:
                skipped += 1
                continue
            cur.execute(SQL, row)
            inserted += 1

    conn.close()
    print(f"Yazilan: {inserted}, atlanan: {skipped}")


if __name__ == "__main__":
    main()