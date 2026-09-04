"""
SentinelMind incident producer.

Reads Prowler FAIL events from PostgreSQL, applies the deterministic
risk scoring engine, correlates high-risk events by Azure resource_id,
and optionally writes idempotent incidents.

Correlation policy:
- If resource_id exists, findings for the same Azure resource are grouped.
- If resource_id is missing, no heuristic/fallback asset correlation is made.
  The event remains a standalone incident candidate.

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

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = PROJECT_ROOT / ".env"


def db_connect():
    """
    Open a PostgreSQL connection using configuration from the project .env file.

    Expected environment variables:
    - DB_HOST
    - DB_PORT
    - DB_NAME
    - DB_USER
    - DB_PASSWORD
    """
    load_dotenv(dotenv_path=ENV_FILE)

    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "sentinelmind"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD"),
    )


def load_prowler_fail_events(conn):
    """
    Load real Prowler FAIL events from PostgreSQL.

    Returns:
        List of tuples:
        (event_id, external_id, resource_id, raw_finding)
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                id,
                external_id,
                resource_id,
                raw
            FROM events
            WHERE source = 'prowler'
              AND check_status = 'FAIL'
            ORDER BY id
            """
        )

        return cur.fetchall()


def build_candidates(rows):
    """
    Convert Prowler FAIL events into high-risk incident candidates.

    Rules:
    - score_finding() remains the deterministic source of risk score.
    - Events below HIGH_RISK_THRESHOLD are ignored.
    - Events sharing the same non-empty resource_id are correlated.
    - Events without resource_id stay standalone to avoid false correlation.
    - Incident risk score is the maximum score among correlated events.
    - Severity is temporarily fixed to "high" for the MVP.

    The risk-score-to-severity mapping will be defined separately in
    the shared contract before supporting additional severity levels.
    """
    groups = defaultdict(list)

    for event_id, external_id, resource_id, finding in rows:
        scored = score_finding(finding)

        if scored["score"] < HIGH_RISK_THRESHOLD:
            continue

        if resource_id:
            # Correlate only by a real Azure resource identifier.
            group_key = ("resource_id", resource_id)
        else:
            # Do not guess asset identity from a display/resource name.
            # A resource_id-less event stays as its own candidate.
            group_key = ("event_id", event_id)

        groups[group_key].append(
            {
                "event_id": event_id,
                "external_id": external_id,
                "resource_id": resource_id,
                "score": scored["score"],
                "event_code": scored["event_code"],
                "resource": scored["resource"],
            }
        )

    candidates = []

    for _, items in groups.items():
        event_ids = sorted(
            item["event_id"]
            for item in items
        )

        risk_score = max(
            item["score"]
            for item in items
        )

        controls = sorted(
            {
                item["event_code"]
                for item in items
                if item["event_code"]
            }
        )

        candidates.append(
            {
                "resource_id": items[0]["resource_id"],
                "resource": items[0]["resource"],
                "event_ids": event_ids,
                "risk_score": risk_score,

                # Temporary MVP behavior.
                # Formal deterministic severity mapping is not yet
                # defined in docs/contracts.md.
                "severity": "high",

                "controls": controls,
            }
        )

    # Keep dry-run and test output deterministic.
    # resource_id may legitimately be None for standalone events.
    candidates.sort(
        key=lambda item: (
            item["resource_id"] or "",
            item["event_ids"],
        )
    )

    return candidates


def incident_exists(cur, event_ids):
    """
    Check whether an incident with exactly the same ordered event_ids
    already exists.

    This provides application-level idempotency.

    Note:
    A future production-hardening step can add a DB-level fingerprint
    or unique constraint to eliminate concurrent-write race conditions.
    """
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
    """
    Write new incident candidates to PostgreSQL.

    Existing incidents with the same event_ids are skipped.
    """
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
    """
    Print incident candidates for dry-run inspection.
    """
    print(f"Incident candidates: {len(candidates)}")
    print()

    for candidate in candidates:
        print(f"resource    = {candidate['resource']}")
        print(f"resource_id = {candidate['resource_id']}")
        print(f"event_ids   = {candidate['event_ids']}")
        print(f"risk_score  = {candidate['risk_score']}")
        print(f"severity    = {candidate['severity']}")
        print("controls:")

        if candidate["controls"]:
            for control in candidate["controls"]:
                print(f"  - {control}")
        else:
            print("  - none")

        print("-" * 80)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Generate high-risk Prowler incident candidates "
            "from SentinelMind PostgreSQL events."
        )
    )

    parser.add_argument(
        "--write",
        action="store_true",
        help=(
            "Write incidents to PostgreSQL. "
            "Without this flag the program runs in dry-run mode."
        ),
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

        created, skipped = write_candidates(
            conn,
            candidates,
        )

        print()
        print(f"Created: {created}")
        print(f"Skipped existing: {skipped}")

    finally:
        conn.close()


if __name__ == "__main__":
    main()
