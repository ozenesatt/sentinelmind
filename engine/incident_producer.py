"""
SentinelMind incident producer.

Reads Prowler FAIL events from PostgreSQL, applies the deterministic
risk scoring engine, correlates high-risk events by resource_id,
and optionally writes idempotent incidents.

Default mode is dry-run.
Use --write for database changes.
"""

import argparse
import os
import uuid
from collections import defaultdict
from pathlib import Path

import psycopg2
from dotenv import load_dotenv

try:
    from engine.filter_engine import score_finding
except ModuleNotFoundError:
    from filter_engine import score_finding

HIGH_RISK_THRESHOLD = 60


def db_connect():
    load_dotenv(dotenv_path=Path(".env"))

    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "sentinelmind"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD"),
    )


def load_prowler_fail_events(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, external_id, resource_id, raw
            FROM events
            WHERE source = 'prowler'
              AND check_status = 'FAIL'
            ORDER BY id
            """
        )
        return cur.fetchall()


def build_candidates(rows):
    groups = defaultdict(list)

    for event_id, external_id, resource_id, finding in rows:
        scored = score_finding(finding)

        if scored["score"] < HIGH_RISK_THRESHOLD:
            continue

        group_key = resource_id or scored["resource"]

        groups[group_key].append(
            {
                "event_id": event_id,
                "external_id": external_id,
                "score": scored["score"],
                "event_code": scored["event_code"],
                "resource": scored["resource"],
            }
        )

    candidates = []

    for resource_id, items in groups.items():
        event_ids = sorted(item["event_id"] for item in items)
        risk_score = max(item["score"] for item in items)

        candidates.append(
            {
                "resource_id": resource_id,
                "resource": items[0]["resource"],
                "event_ids": event_ids,
                "risk_score": risk_score,
                "severity": "high",
                "controls": sorted(
                    {item["event_code"] for item in items}
                ),
            }
        )

    candidates.sort(key=lambda item: item["resource_id"])

    return candidates


def incident_exists(cur, event_ids):
    cur.execute(
        """
        SELECT id
        FROM incidents
        WHERE event_ids = %s::bigint[]
        LIMIT 1
        """,
        (event_ids,),
    )

    row = cur.fetchone()
    return row[0] if row else None


def write_candidates(conn, candidates):
    created = 0
    skipped = 0

    with conn:
        with conn.cursor() as cur:
            for candidate in candidates:
                existing_id = incident_exists(
                    cur,
                    candidate["event_ids"],
                )

                if existing_id:
                    print(
                        f"SKIP existing={existing_id} "
                        f"event_ids={candidate['event_ids']}"
                    )
                    skipped += 1
                    continue

                incident_id = uuid.uuid4()

                cur.execute(
                    """
                    INSERT INTO incidents (
                        id,
                        event_ids,
                        risk_score,
                        severity,
                        status
                    )
                    VALUES (
                        %s,
                        %s::bigint[],
                        %s,
                        %s,
                        'new'
                    )
                    """,
                    (
                        str(incident_id),
                        candidate["event_ids"],
                        candidate["risk_score"],
                        candidate["severity"],
                    ),
                )

                print(
                    f"CREATED id={incident_id} "
                    f"event_ids={candidate['event_ids']}"
                )
                created += 1

    return created, skipped


def print_candidates(candidates):
    print(f"Incident candidates: {len(candidates)}")
    print()

    for candidate in candidates:
        print(f"resource    = {candidate['resource']}")
        print(f"resource_id = {candidate['resource_id']}")
        print(f"event_ids   = {candidate['event_ids']}")
        print(f"risk_score  = {candidate['risk_score']}")
        print(f"severity    = {candidate['severity']}")
        print("controls:")

        for control in candidate["controls"]:
            print(f"  - {control}")

        print("-" * 80)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write incidents to PostgreSQL. Default is dry-run.",
    )
    args = parser.parse_args()

    conn = db_connect()

    try:
        rows = load_prowler_fail_events(conn)
        candidates = build_candidates(rows)

        print(f"Prowler FAIL events: {len(rows)}")
        print_candidates(candidates)

        if not args.write:
            print()
            print("DRY-RUN: database was not changed.")
            return

        created, skipped = write_candidates(conn, candidates)

        print()
        print(f"Created: {created}")
        print(f"Skipped existing: {skipped}")

    finally:
        conn.close()


if __name__ == "__main__":
    main()