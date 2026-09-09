from datetime import datetime

from engine.failed_logon_correlation import (
    is_bruteforce_candidate,
)


def parse_timestamp(value: str) -> datetime:
    """
    Wazuh ISO timestamp degerini Python datetime'a cevirir.
    Ornek:
    2026-09-09T20:00:00.000+0000
    2026-09-09T20:00:00Z
    """

    value = value.strip()

    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    if (
        len(value) >= 5
        and value[-5] in {"+", "-"}
        and value[-3] != ":"
    ):
        value = value[:-2] + ":" + value[-2:]

    return datetime.fromisoformat(value)


def normalize_wazuh_failed_logon(
    event: dict,
) -> dict | None:
    """
    Gercek Wazuh Windows event yapisini
    SentinelMind correlation formatina cevirir.

    Yalnizca Event ID 4625 kabul edilir.
    """

    try:
        win = event["data"]["win"]

        event_id = int(
            win["system"]["eventID"]
        )

        if event_id != 4625:
            return None

        eventdata = win.get("eventdata", {})

        username = (
            eventdata.get("targetUserName")
            or eventdata.get("subjectUserName")
            or "unknown"
        )

        src_ip = (
            eventdata.get("ipAddress")
            or eventdata.get("sourceIp")
            or "unknown"
        )

        timestamp_value = (
            event.get("timestamp")
            or win["system"].get("systemTime")
        )

        if not timestamp_value:
            raise ValueError(
                "Wazuh event timestamp bulunamadi."
            )

        return {
            "event_id": 4625,
            "username": username,
            "src_ip": src_ip,
            "timestamp": parse_timestamp(
                timestamp_value
            ),
        }

    except (
        KeyError,
        TypeError,
        ValueError,
    ):
        return None


def is_wazuh_bruteforce_candidate(
    events: list[dict],
    threshold: int = 5,
    window_minutes: int = 5,
) -> bool:
    """
    Wazuh event listesini normalize eder ve
    SentinelMind brute-force correlation motoruna verir.
    """

    normalized = []

    for event in events:
        item = normalize_wazuh_failed_logon(
            event
        )

        if item is not None:
            normalized.append(item)

    return is_bruteforce_candidate(
        normalized,
        threshold=threshold,
        window_minutes=window_minutes,
    )