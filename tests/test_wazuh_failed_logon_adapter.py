from datetime import datetime, timedelta, timezone

from engine.wazuh_failed_logon_adapter import (
    is_wazuh_bruteforce_candidate,
    normalize_wazuh_failed_logon,
)


def build_wazuh_event(
    event_id: int,
    index: int,
):
    start = datetime(
        2026,
        9,
        9,
        20,
        0,
        tzinfo=timezone.utc,
    )

    timestamp = (
        start + timedelta(seconds=index * 30)
    ).isoformat()

    return {
        "timestamp": timestamp,
        "data": {
            "win": {
                "system": {
                    "eventID": str(event_id),
                },
                "eventdata": {
                    "targetUserName": "demo-user",
                    "ipAddress": "203.0.113.44",
                },
            }
        },
    }


def test_realistic_wazuh_4625_normalization():
    event = build_wazuh_event(
        4625,
        0,
    )

    normalized = normalize_wazuh_failed_logon(
        event
    )

    assert normalized is not None
    assert normalized["event_id"] == 4625
    assert normalized["username"] == "demo-user"
    assert normalized["src_ip"] == "203.0.113.44"

    print(
        "Wazuh 4625 normalization BASARILI"
    )


def test_wazuh_4624_is_ignored():
    event = build_wazuh_event(
        4624,
        0,
    )

    normalized = normalize_wazuh_failed_logon(
        event
    )

    assert normalized is None

    print(
        "Wazuh 4624 ignore BASARILI"
    )


def test_five_realistic_wazuh_4625_trigger():
    events = [
        build_wazuh_event(
            4625,
            index,
        )
        for index in range(5)
    ]

    assert (
        is_wazuh_bruteforce_candidate(events)
        is True
    )

    print(
        "5x Wazuh 4625 -> "
        "brute-force candidate BASARILI"
    )


def test_four_realistic_wazuh_4625_do_not_trigger():
    events = [
        build_wazuh_event(
            4625,
            index,
        )
        for index in range(4)
    ]

    assert (
        is_wazuh_bruteforce_candidate(events)
        is False
    )

    print(
        "4x Wazuh 4625 -> "
        "threshold alti BASARILI"
    )


if __name__ == "__main__":
    test_realistic_wazuh_4625_normalization()
    test_wazuh_4624_is_ignored()
    test_five_realistic_wazuh_4625_trigger()
    test_four_realistic_wazuh_4625_do_not_trigger()