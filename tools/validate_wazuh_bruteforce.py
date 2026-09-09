import argparse
import json
from pathlib import Path

from engine.wazuh_failed_logon_adapter import (
    is_wazuh_bruteforce_candidate,
    normalize_wazuh_failed_logon,
)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "event_file",
        help="Gercek Wazuh event JSON dosyasi",
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--window",
        type=int,
        default=5,
        help="Dakika",
    )

    args = parser.parse_args()

    source = Path(args.event_file)

    if not source.exists():
        raise FileNotFoundError(
            f"Wazuh event dosyasi bulunamadi: {source}"
        )

    payload = json.loads(
        source.read_text(
            encoding="utf-8-sig"
        )
    )

    if isinstance(payload, dict):
        events = payload.get(
            "events",
            payload.get("hits", [payload]),
        )
    elif isinstance(payload, list):
        events = payload
    else:
        raise ValueError(
            "Wazuh JSON list veya object olmali."
        )

    normalized = []

    for event in events:
        item = normalize_wazuh_failed_logon(
            event
        )

        if item is not None:
            normalized.append(item)

    result = is_wazuh_bruteforce_candidate(
        events,
        threshold=args.threshold,
        window_minutes=args.window,
    )

    print("=" * 65)
    print("SENTINELMIND WAZUH BRUTE-FORCE VALIDATION")
    print("=" * 65)

    print(f"Input event sayisi : {len(events)}")
    print(f"4625 event sayisi  : {len(normalized)}")
    print(f"Threshold          : {args.threshold}")
    print(f"Window             : {args.window} dakika")

    print()

    if result:
        print("SONUC: BRUTE-FORCE CANDIDATE")
    else:
        print("SONUC: BRUTE-FORCE CANDIDATE DEGIL")

    print()
    print(
        "PII degerleri guvenlik nedeniyle "
        "ekrana yazdirilmadi."
    )


if __name__ == "__main__":
    main()