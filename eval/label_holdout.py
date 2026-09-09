import json
from pathlib import Path


DATA = Path("eval/holdout_findings.json")


def save(rows):
    DATA.write_text(
        json.dumps(
            rows,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


def main():
    if not DATA.exists():
        raise FileNotFoundError(
            "Holdout dataset bulunamadi. "
            "Once build_holdout_set.py calistir."
        )

    rows = json.loads(
        DATA.read_text(
            encoding="utf-8"
        )
    )

    remaining = sum(
        1
        for row in rows
        if row["expected_positive"] is None
    )

    print("=" * 70)
    print("SENTINELMIND HOLDOUT HUMAN LABELING")
    print("=" * 70)
    print(f"Toplam: {len(rows)}")
    print(f"Etiketlenmemis: {remaining}")
    print()
    print("y = high priority")
    print("n = high priority degil")
    print("s = atla")
    print("q = kaydet ve cik")
    print()
    print(
        "V2 risk score ve prediction "
        "bilerek gosterilmiyor."
    )

    for row in rows:
        if row["expected_positive"] is not None:
            continue

        print()
        print("-" * 70)
        print(
            f"Holdout ID : {row['holdout_id']}"
        )
        print(
            f"Event Code : {row['event_code']}"
        )
        print(
            f"Severity   : {row['severity']}"
        )
        print(
            f"Resource   : {row['resource']}"
        )
        print(
            f"Categories : {row['categories']}"
        )
        print(
            f"Message    : {row['message']}"
        )
        print("-" * 70)

        while True:
            answer = input(
                "Label [y/n/s/q]: "
            ).strip().lower()

            if answer == "y":
                row["expected_positive"] = True
                row["label_reason"] = input(
                    "Kisa gerekce: "
                ).strip()

                save(rows)
                break

            if answer == "n":
                row["expected_positive"] = False
                row["label_reason"] = input(
                    "Kisa gerekce: "
                ).strip()

                save(rows)
                break

            if answer == "s":
                break

            if answer == "q":
                save(rows)
                print("Kaydedildi.")
                return

            print(
                "Gecersiz secim. "
                "y / n / s / q kullan."
            )

    save(rows)

    remaining = sum(
        1
        for row in rows
        if row["expected_positive"] is None
    )

    print()
    print(
        f"Kalan etiketsiz kayit: {remaining}"
    )


if __name__ == "__main__":
    main()