import argparse
import json
import os
import shutil
import subprocess
import sys

import psycopg2
from dotenv import load_dotenv
from psycopg2.extras import Json, RealDictCursor

load_dotenv()


def connect_db():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "sentinelmind"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD"),
    )


def get_action(action_id):
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
                    approved_by
                FROM actions
                WHERE id = %s;
                """,
                (action_id,),
            )
            row = cur.fetchone()

    return dict(row) if row else None


def validate_action(action):
    if action is None:
        sys.exit("Action bulunamadi.")

    if action["status"] != "approved":
        sys.exit(
            f"Action approved degil: "
            f"status={action['status']}"
        )

    if action["action_type"] != "close_nsg_rule":
        sys.exit(
            "Bu executor sadece "
            "close_nsg_rule destekliyor."
        )

    params = action["params"] or {}

    required = [
        "resource_group",
        "nsg_name",
        "rule_name",
    ]

    missing = [
        key
        for key in required
        if not params.get(key)
    ]

    if missing:
        sys.exit(
            "Eksik action parametresi: "
            + ", ".join(missing)
        )

    return params


def run_az(args):
    az_cli = shutil.which("az")

    if not az_cli:
        raise RuntimeError(
            "Azure CLI PATH icinde bulunamadi."
        )

    result = subprocess.run(
        [az_cli, *args],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or result.stdout.strip()
            or "Azure CLI hatasi"
        )

    return result.stdout


def get_rule(params):
    output = run_az(
        [
            "network",
            "nsg",
            "rule",
            "show",
            "--resource-group",
            params["resource_group"],
            "--nsg-name",
            params["nsg_name"],
            "--name",
            params["rule_name"],
            "--output",
            "json",
        ]
    )

    return json.loads(output)


def mark_executed(action_id, result):
    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE actions
                SET
                    status = 'executed',
                    executed_at = now(),
                    result = %s
                WHERE id = %s
                  AND status = 'approved';
                """,
                (
                    Json(result),
                    action_id,
                ),
            )

            if cur.rowcount != 1:
                raise RuntimeError(
                    "Action executed olarak "
                    "isaretlenemedi."
                )


def mark_failed(action_id, result):
    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE actions
                SET
                    status = 'failed',
                    result = %s
                WHERE id = %s
                  AND status = 'approved';
                """,
                (
                    Json(result),
                    action_id,
                ),
            )


def execute_close_nsg_rule(params):
    run_az(
        [
            "network",
            "nsg",
            "rule",
            "delete",
            "--resource-group",
            params["resource_group"],
            "--nsg-name",
            params["nsg_name"],
            "--name",
            params["rule_name"],
        ]
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "SentinelMind Azure remediation executor"
        )
    )

    parser.add_argument(
        "--action-id",
        required=True,
        help="actions tablosundaki UUID",
    )

    parser.add_argument(
        "--execute",
        action="store_true",
        help=(
            "Gercek Azure degisikligine izin verir. "
            "Verilmezse dry-run yapilir."
        ),
    )

    args = parser.parse_args()

    action = get_action(args.action_id)
    params = validate_action(action)

    try:
        rule = get_rule(params)
    except Exception as exc:
        sys.exit(
            f"Azure pre-check basarisiz: {exc}"
        )

    plan = {
        "action_id": str(action["id"]),
        "approved_by": action["approved_by"],
        "operation": "close_nsg_rule",
        "resource_group": params["resource_group"],
        "nsg_name": params["nsg_name"],
        "rule_name": params["rule_name"],
        "current_rule": {
            "access": rule.get("access"),
            "direction": rule.get("direction"),
            "protocol": rule.get("protocol"),
            "source": rule.get(
                "sourceAddressPrefix"
            ),
            "destination_port": rule.get(
                "destinationPortRange"
            ),
            "priority": rule.get("priority"),
        },
    }

    print(
        json.dumps(
            plan,
            indent=2,
            ensure_ascii=False,
            default=str,
        )
    )

    if not args.execute:
        print(
            "\nDRY-RUN: Azure'da degisiklik yapilmadi."
        )
        return

    print(
        "\nEXECUTE modu: "
        "NSG allow kurali silinecek."
    )

    try:
        execute_close_nsg_rule(params)

        result = {
            "operation": "close_nsg_rule",
            "resource_group": params[
                "resource_group"
            ],
            "nsg_name": params["nsg_name"],
            "rule_name": params["rule_name"],
            "outcome": "rule_deleted",
        }

        mark_executed(
            args.action_id,
            result,
        )

        print(
            "Remediation basarili. "
            "Action executed olarak kaydedildi."
        )

    except Exception as exc:
        failure = {
            "operation": "close_nsg_rule",
            "outcome": "failed",
            "error": str(exc),
        }

        try:
            mark_failed(
                args.action_id,
                failure,
            )
        except Exception:
            pass

        sys.exit(
            f"Remediation basarisiz: {exc}"
        )


if __name__ == "__main__":
    main()
