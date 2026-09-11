import argparse
import json
import os
import re
import uuid

import psycopg2
from dotenv import load_dotenv
from psycopg2.extras import Json, RealDictCursor

load_dotenv()


NSG_RESOURCE_RE = re.compile(
    r"^/subscriptions/(?P<subscription_id>[^/]+)"
    r"/resourceGroups/(?P<resource_group>[^/]+)"
    r"/providers/Microsoft\.Network/networkSecurityGroups/"
    r"(?P<nsg_name>[^/]+)$",
    re.IGNORECASE,
)


def connect_db():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "sentinelmind"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD"),
    )


def parse_nsg_resource_id(resource_id):
    match = NSG_RESOURCE_RE.match(
        str(resource_id or "").strip()
    )

    if not match:
        raise ValueError(
            "Trusted event resource_id gecerli bir Azure NSG "
            "resource ID degil."
        )

    return match.groupdict()


def get_incident(incident_id):
    with connect_db() as conn:
        with conn.cursor(
            cursor_factory=RealDictCursor
        ) as cur:
            cur.execute(
                """
                SELECT
                    id,
                    event_ids,
                    risk_score,
                    severity,
                    status
                FROM incidents
                WHERE id = %s;
                """,
                (incident_id,),
            )
            row = cur.fetchone()

    if row is None:
        raise ValueError("Incident bulunamadi.")

    return dict(row)


def get_latest_analysis(incident_id):
    with connect_db() as conn:
        with conn.cursor(
            cursor_factory=RealDictCursor
        ) as cur:
            cur.execute(
                """
                SELECT
                    id,
                    incident_id,
                    payload,
                    pii_masked,
                    created_at
                FROM ai_analyses
                WHERE incident_id = %s
                ORDER BY created_at DESC, id DESC
                LIMIT 1;
                """,
                (incident_id,),
            )
            row = cur.fetchone()

    if row is None:
        raise ValueError(
            "Incident icin AI analysis bulunamadi."
        )

    return dict(row)


def get_events(event_ids):
    if not event_ids:
        raise ValueError(
            "Incident herhangi bir event icermiyor."
        )

    with connect_db() as conn:
        with conn.cursor(
            cursor_factory=RealDictCursor
        ) as cur:
            cur.execute(
                """
                SELECT
                    id,
                    source,
                    resource_id,
                    raw
                FROM events
                WHERE id = ANY(%s)
                ORDER BY id;
                """,
                (list(event_ids),),
            )
            rows = cur.fetchall()

    return [dict(row) for row in rows]


def validate_ssh_rule(rule):
    if str(rule.get("access", "")).lower() != "allow":
        raise ValueError(
            "Trusted rule Allow degil."
        )

    if str(rule.get("direction", "")).lower() != "inbound":
        raise ValueError(
            "Trusted rule Inbound degil."
        )

    protocol = str(
        rule.get("protocol", "")
    ).lower()

    if protocol not in {"tcp", "*"}:
        raise ValueError(
            "Trusted rule TCP veya wildcard degil."
        )

    destination_port = str(
        rule.get("destination_port_range", "")
    ).strip()

    if destination_port not in {"22", "22-22"}:
        raise ValueError(
            "Trusted rule SSH/TCP 22 hedeflemiyor."
        )

    source = str(
        rule.get("source_address_prefix", "")
    ).strip().lower()

    if source not in {
        "*",
        "0.0.0.0/0",
        "internet",
    }:
        raise ValueError(
            "Trusted rule Internet kaynakli SSH erisimi degil."
        )


def build_close_nsg_plan(
    incident,
    analysis,
    events,
):
    if analysis["pii_masked"] is not True:
        raise ValueError(
            "AI analysis pii_masked=True degil."
        )

    if str(analysis["incident_id"]) != str(
        incident["id"]
    ):
        raise ValueError(
            "AI analysis incident_id eslesmiyor."
        )

    payload = analysis["payload"] or {}

    if str(payload.get("incident_id")) != str(
        incident["id"]
    ):
        raise ValueError(
            "AI payload incident_id eslesmiyor."
        )

    actions = payload.get(
        "recommended_actions"
    ) or []

    close_actions = [
        action
        for action in actions
        if action.get("action_type")
        == "close_nsg_rule"
    ]

    if len(close_actions) != 1:
        raise ValueError(
            "Tam olarak bir close_nsg_rule onerisi bekleniyor."
        )

    ai_action = close_actions[0]
    ai_params = ai_action.get("params") or {}

    ai_resource_id = str(
        ai_params.get("resource_id") or ""
    ).strip()

    ai_rule_name = str(
        ai_params.get("rule_name") or ""
    ).strip()

    if not ai_resource_id:
        raise ValueError(
            "AI action resource_id icermiyor."
        )

    if not ai_rule_name:
        raise ValueError(
            "AI action rule_name icermiyor."
        )

    for event in events:
        if event.get("source") != "prowler":
            continue

        trusted_resource_id = str(
            event.get("resource_id") or ""
        ).strip()

        if (
            trusted_resource_id.lower()
            != ai_resource_id.lower()
        ):
            continue

        raw = event.get("raw") or {}

        for resource in raw.get(
            "resources",
            [],
        ):
            resource_uid = str(
                resource.get("uid") or ""
            ).strip()

            resource_type = str(
                resource.get("type") or ""
            ).lower()

            if (
                resource_uid.lower()
                != trusted_resource_id.lower()
            ):
                continue

            if (
                resource_type
                != "microsoft.network/networksecuritygroups"
            ):
                continue

            metadata = (
                resource
                .get("data", {})
                .get("metadata", {})
            )

            rules = metadata.get(
                "security_rules",
                [],
            )

            for rule in rules:
                trusted_rule_name = str(
                    rule.get("name") or ""
                ).strip()

                if trusted_rule_name != ai_rule_name:
                    continue

                validate_ssh_rule(rule)

                parsed = parse_nsg_resource_id(
                    trusted_resource_id
                )

                return {
                    "incident_id": str(
                        incident["id"]
                    ),
                    "analysis_id": str(
                        analysis["id"]
                    ),
                    "source_event_id": event["id"],
                    "action_type": "close_nsg_rule",
                    "params": {
                        "subscription_id": parsed[
                            "subscription_id"
                        ],
                        "resource_group": parsed[
                            "resource_group"
                        ],
                        "nsg_name": parsed[
                            "nsg_name"
                        ],
                        "rule_name": trusted_rule_name,
                        "analysis_id": str(
                            analysis["id"]
                        ),
                        "source_event_id": event[
                            "id"
                        ],
                        "source_resource_id":
                            trusted_resource_id,
                    },
                }

    raise ValueError(
        "AI onerisi trusted Prowler eventiyle "
        "dogrulanamadi."
    )


def find_existing_action(
    incident_id,
    analysis_id,
):
    with connect_db() as conn:
        with conn.cursor(
            cursor_factory=RealDictCursor
        ) as cur:
            cur.execute(
                """
                SELECT
                    id,
                    incident_id,
                    action_type,
                    params,
                    status,
                    approved_by,
                    executed_at,
                    result
                FROM actions
                WHERE incident_id = %s
                  AND params ->> 'analysis_id' = %s
                LIMIT 1;
                """,
                (
                    incident_id,
                    analysis_id,
                ),
            )
            row = cur.fetchone()

    return dict(row) if row else None


def create_pending_action(plan):
    existing = find_existing_action(
        plan["incident_id"],
        plan["analysis_id"],
    )

    if existing is not None:
        return existing, False

    action_id = uuid.uuid4()

    with connect_db() as conn:
        with conn.cursor(
            cursor_factory=RealDictCursor
        ) as cur:
            cur.execute(
                """
                INSERT INTO actions (
                    id,
                    incident_id,
                    action_type,
                    params,
                    status
                )
                VALUES (%s, %s, %s, %s, 'pending')
                RETURNING
                    id,
                    incident_id,
                    action_type,
                    params,
                    status,
                    approved_by,
                    executed_at,
                    result;
                """,
                (
                    str(action_id),
                    plan["incident_id"],
                    plan["action_type"],
                    Json(plan["params"]),
                ),
            )
            row = cur.fetchone()

    return dict(row), True


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Trusted AI recommendation to pending action bridge"
        )
    )

    parser.add_argument(
        "--incident-id",
        required=True,
    )

    parser.add_argument(
        "--create",
        action="store_true",
        help=(
            "Dogrulanmis plani actions tablosuna "
            "pending olarak yazar."
        ),
    )

    args = parser.parse_args()

    incident = get_incident(
        args.incident_id
    )

    analysis = get_latest_analysis(
        args.incident_id
    )

    events = get_events(
        incident["event_ids"]
    )

    plan = build_close_nsg_plan(
        incident,
        analysis,
        events,
    )

    print(
        json.dumps(
            plan,
            indent=2,
            ensure_ascii=False,
            default=str,
        )
    )

    existing = find_existing_action(
        plan["incident_id"],
        plan["analysis_id"],
    )

    if existing is not None:
        print()
        print(
            "EXISTING_ACTION: "
            f"{existing['id']} "
            f"status={existing['status']}"
        )
        return

    if not args.create:
        print()
        print(
            "DRY-RUN: pending action olusturulmadi."
        )
        return

    action, created = create_pending_action(
        plan
    )

    print()
    print(
        "PENDING_ACTION_CREATED"
        if created
        else "EXISTING_ACTION"
    )
    print(f"ID = {action['id']}")
    print(f"STATUS = {action['status']}")
    print(
        f"ACTION_TYPE = {action['action_type']}"
    )


if __name__ == "__main__":
    main()
