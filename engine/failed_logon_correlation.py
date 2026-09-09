from datetime import timedelta


DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_MINUTES = 5


def is_bruteforce_candidate(
    events: list[dict],
    threshold: int = DEFAULT_THRESHOLD,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
) -> bool:
    """
    Ayni username + src_ip icin belirlenen zaman
    penceresinde yeterli sayida Windows 4625 olayi
    varsa brute-force adayi olarak isaretler.
    """

    failed_events = [
        event
        for event in events
        if int(event["event_id"]) == 4625
    ]

    if len(failed_events) < threshold:
        return False

    failed_events.sort(
        key=lambda event: event["timestamp"]
    )

    for index, first_event in enumerate(failed_events):
        start = first_event["timestamp"]

        matching = [
            event
            for event in failed_events[index:]
            if (
                event["username"] == first_event["username"]
                and event["src_ip"] == first_event["src_ip"]
                and event["timestamp"]
                <= start + timedelta(minutes=window_minutes)
            )
        ]

        if len(matching) >= threshold:
            return True

    return False