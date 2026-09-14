import json
from pathlib import Path


DATA = Path("eval/labeled_findings.json")


def metrics(rows, threshold):
    tp = fp = fn = tn = 0

    for row in rows:
        expected = row["expected_positive"]
        predicted = row["risk_score"] >= threshold

        if expected is True and predicted is True:
            tp += 1
        elif expected is False and predicted is True:
            fp += 1
        elif expected is True and predicted is False:
            fn += 1
        elif expected is False and predicted is False:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )

    return tp, fp, fn, tn, precision, recall, f1


def main():
    rows = json.loads(
        DATA.read_text(encoding="utf-8")
    )

    thresholds = [40, 45, 50, 55, 60]

    print("=" * 78)
    print("SENTINELMIND THRESHOLD EVALUATION")
    print("=" * 78)

    for threshold in thresholds:
        tp, fp, fn, tn, precision, recall, f1 = metrics(
            rows,
            threshold,
        )

        print(
            f"Threshold {threshold:>2} | "
            f"TP={tp:>2} FP={fp:>2} FN={fn:>2} TN={tn:>2} | "
            f"Precision={precision:.3f} "
            f"Recall={recall:.3f} "
            f"F1={f1:.3f}"
        )


if __name__ == "__main__":
    main()