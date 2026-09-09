import json
from pathlib import Path


DATA = Path("eval/labeled_findings.json")


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
    rows = json.loads(
        DATA.read_text(encoding="utf-8")
    )

    remaining = [
        row
        for row in rows
        if row["expected_positive"] is None
    ]

    print("=" * 70)
    print("SENTINELMIND HUMAN LABELING")
    print("=" * 70)
    print()
    print(f"Toplam kayit: {len(rows)}")
    print(f"Etiketlenmemis: {len(remaining)}")
    print()
    print("Kurallar:")
    print("  y = gercekten yuksek oncelikli / positive")
    print("  n = yuksek oncelikli degil / negative")
    print("  s = simdilik atla")
    print("  q = kaydet ve cik")
    print()
    print(
        "DIKKAT: risk_score ve predicted_positive "
        "bilerek ekranda gosterilmiyor."
    )

    for row in rows:
        if row["expected_positive"] is not None:
            continue

        print()
        print("-" * 70)
        print(f"Eval ID    : {row['eval_id']}")
        print(f"Event Code : {row['event_code']}")
        print(f"Severity   : {row['severity']}")
        print(f"Resource   : {row['resource']}")
        print(f"Categories : {row['categories']}")
        print(f"Message    : {row['message']}")
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

            print("Gecersiz secim. y / n / s / q kullan.")

    save(rows)

    remaining = sum(
        1
        for row in rows
        if row["expected_positive"] is None
    )

    print()
    print("=" * 70)
    print("LABELING OTURUMU TAMAMLANDI")
    print("=" * 70)
    print(f"Kalan etiketsiz kayit: {remaining}")


if __name__ == "__main__":
    main()