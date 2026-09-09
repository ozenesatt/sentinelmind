import json
from pathlib import Path


DATA = Path("eval/labeled_findings.json")


def calculate_metrics(rows: list[dict]) -> dict:
    tp = 0
    fp = 0
    fn = 0
    tn = 0

    for row in rows:
        expected = row["expected_positive"]
        predicted = row["predicted_positive"]

        if expected is True and predicted is True:
            tp += 1

        elif expected is False and predicted is True:
            fp += 1

        elif expected is True and predicted is False:
            fn += 1

        elif expected is False and predicted is False:
            tn += 1

    precision = (
        tp / (tp + fp)
        if (tp + fp) > 0
        else 0.0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn) > 0
        else 0.0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def main():
    rows = json.loads(
        DATA.read_text(encoding="utf-8")
    )

    unlabeled = [
        row
        for row in rows
        if row["expected_positive"] is None
    ]

    if unlabeled:
        raise RuntimeError(
            f"{len(unlabeled)} kayit henuz label edilmedi. "
            "Precision/recall hesaplanmadi."
        )

    metrics = calculate_metrics(rows)

    print("=" * 50)
    print("SENTINELMIND DETECTION EVALUATION")
    print("=" * 50)

    print(f"TP: {metrics['tp']}")
    print(f"FP: {metrics['fp']}")
    print(f"FN: {metrics['fn']}")
    print(f"TN: {metrics['tn']}")

    print()
    print(
        f"Precision: {metrics['precision']:.3f}"
    )
    print(
        f"Recall:    {metrics['recall']:.3f}"
    )
    print(
        f"F1 Score:  {metrics['f1']:.3f}"
    )


if __name__ == "__main__":
    main()