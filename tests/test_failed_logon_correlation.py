from engine.failed_logon_correlation import is_bruteforce_candidate
from datetime import datetime, timedelta


THRESHOLD = 5
WINDOW_MINUTES = 5


def is_bruteforce_candidate(events: list[dict]) -> bool:
    failed_events = [
        event
        for event in events
        if int(event["event_id"]) == 4625
    ]

    if len(failed_events) < THRESHOLD:
        return False

    failed_events.sort(
        key=lambda event: event["timestamp"]
    )

    for index in range(len(failed_events)):
        start = failed_events[index]["timestamp"]

        matching = [
            event
            for event in failed_events[index:]
            if event["username"]
            == failed_events[index]["username"]
            and event["src_ip"]
            == failed_events[index]["src_ip"]
            and event["timestamp"]
            <= start + timedelta(minutes=WINDOW_MINUTES)
        ]

        if len(matching) >= THRESHOLD:
            return True

    return False


def build_events(count: int):
    start = datetime(
        2026,
        9,
        9,
        20,
        0,
        0,
    )

    return [
        {
            "event_id": 4625,
            "username": "demo-user",
            "src_ip": "203.0.113.44",
            "timestamp": (
                start + timedelta(seconds=i * 30)
            ),
        }
        for i in range(count)
    ]


def test_single_failed_logon_is_not_bruteforce():
    events = build_events(1)

    assert is_bruteforce_candidate(events) is False

    print(
        "Tek 4625 -> brute force DEGIL BASARILI"
    )


def test_four_failed_logons_are_not_bruteforce():
    events = build_events(4)

    assert is_bruteforce_candidate(events) is False

    print(
        "4x 4625 -> threshold alti BASARILI"
    )


def test_five_failed_logons_trigger_bruteforce():
    events = build_events(5)

    assert is_bruteforce_candidate(events) is True

    print(
        "5x 4625 -> brute force candidate BASARILI"
    )


if __name__ == "__main__":
    test_single_failed_logon_is_not_bruteforce()
    test_four_failed_logons_are_not_bruteforce()
    test_five_failed_logons_trigger_bruteforce()