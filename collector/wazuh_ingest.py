"""
SentinelMind AI
Wazuh Indexer -> PostgreSQL events collector
"""

import getpass
import ipaddress
import os
import sys

import psycopg2
import requests
import urllib3
from dotenv import load_dotenv
from psycopg2.extras import Json

load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INDEXER_URL = os.getenv(
    "WAZUH_INDEXER_URL",
    "https://127.0.0.1:9200"
)

INDEXER_USER = os.getenv(
    "WAZUH_INDEXER_USER",
    "admin"
)

LOOKBACK_MINUTES = int(
    os.getenv("WAZUH_LOOKBACK_MINUTES", "30")
)

BATCH_SIZE = int(
    os.getenv("WAZUH_BATCH_SIZE", "500")
)

EVENT_ID_FILTER = os.getenv("WAZUH_EVENT_ID")


def nested(data, *keys):
    current = data

    for key in keys:
        if not isinstance(current, dict):
            return None

        current = current.get(key)

        if current is None:
            return None

    return current


def valid_ip(value):
    if not value:
        return None

    value = str(value).strip()

    if value in {"-", "::", "unknown", "N/A"}:
        return None

    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        return None


def build_query():
    filters = [
        {
            "range": {
                "@timestamp": {
                    "gte": f"now-{LOOKBACK_MINUTES}m",
                    "lte": "now"
                }
            }
        }
    ]

    if EVENT_ID_FILTER:
        filters.append(
            {
                "term": {
                    "data.win.system.eventID": EVENT_ID_FILTER
                }
            }
        )

    return {
        "size": BATCH_SIZE,
        "sort": [
            {
                "@timestamp": {
                    "order": "asc"
                }
            }
        ],
        "query": {
            "bool": {
                "filter": filters
            }
        }
    }


def fetch_alerts(password):
    url = f"{INDEXER_URL}/wazuh-alerts-*/_search"

    response = requests.post(
        url,
        auth=(INDEXER_USER, password),
        json=build_query(),
        verify=False,
        timeout=30
    )

    response.raise_for_status()

    result = response.json()

    return result.get("hits", {}).get("hits", [])


def to_event(hit):
    source = hit.get("_source", {})

    rule = source.get("rule", {})
    agent = source.get("agent", {})

    eventdata = (
        nested(source, "data", "win", "eventdata")
        or {}
    )

    mitre_ids = nested(rule, "mitre", "id") or []

    if isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]

    external_id = (
        f"wazuh:{hit.get('_index')}:{hit.get('_id')}"
    )

    occurred_at = (
        source.get("@timestamp")
        or source.get("timestamp")
    )

    src_ip = valid_ip(
        eventdata.get("ipAddress")
        or source.get("srcip")
        or source.get("src_ip")
    )

    username = (
        eventdata.get("targetUserName")
        or nested(source, "user", "name")
        or source.get("dstuser")
    )

    return (
        "wazuh",
        external_id,
        occurred_at,
        agent.get("id"),
        agent.get("name"),
        str(rule.get("id"))
        if rule.get("id") is not None
        else None,
        rule.get("level"),
        rule.get("description"),
        mitre_ids,
        src_ip,
        username,
        Json(source)
    )


SQL = """
INSERT INTO events (
    source,
    external_id,
    occurred_at,
    agent_id,
    agent_name,
    rule_id,
    rule_level,
    rule_description,
    mitre_ids,
    src_ip,
    username,
    raw
)
VALUES (
    %s, %s, %s, %s, %s, %s,
    %s, %s, %s, %s, %s, %s
)
ON CONFLICT (external_id) DO NOTHING
"""


def connect_db():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "sentinelmind"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD")
    )


def main():
    password = os.getenv("WAZUH_INDEXER_PASSWORD")

    if not password:
        password = getpass.getpass(
            "Wazuh Indexer password: "
        )

    print(
        f"Indexer: {INDEXER_URL} | "
        f"lookback={LOOKBACK_MINUTES} dakika | "
        f"event_id={EVENT_ID_FILTER or 'ALL'}"
    )

    try:
        hits = fetch_alerts(password)
    except requests.RequestException as exc:
        sys.exit(f"Indexer hatasi: {exc}")

    print(f"Indexer'dan alinan alert: {len(hits)}")

    if not hits:
        print("Yazilacak alert bulunamadi.")
        return

    inserted = 0

    conn = connect_db()

    try:
        with conn:
            with conn.cursor() as cur:
                for hit in hits:
                    cur.execute(
                        SQL,
                        to_event(hit)
                    )

                    if cur.rowcount == 1:
                        inserted += 1
    finally:
        conn.close()

    print(f"Yeni yazilan: {inserted}")
    print(
        f"Tekrar/atlanmis: "
        f"{len(hits) - inserted}"
    )


if __name__ == "__main__":
    main()