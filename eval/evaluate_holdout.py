import argparse
import json
from pathlib import Path

from eval.scoring_v2 import (
    V2_THRESHOLD,
    V2_VERSION,
    score_finding_v2,
)


LABELS = Path("eval/holdout_findings.json")


def calculate_metrics(rows: list[dict]) -> dict:
    tp = fp = fn = tn = 0

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
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "source_file",
        help="Holdout icin kullanilan yeni Prowler OCSF JSON dosyasi",
    )

    args = parser.parse_args()

    source = Path(args.source_file)

    if not source.exists():
        raise FileNotFoundError(
            f"Holdout source bulunamadi: {source}"
        )

    if not LABELS.exists():
        raise FileNotFoundError(
            "eval/holdout_findings.json bulunamadi. "
            "Once build_holdout_set ve label_holdout calistir."
        )

    findings = json.loads(
        source.read_text(
            encoding="utf-8-sig"
        )
    )

    labels = json.loads(
        LABELS.read_text(
            encoding="utf-8"
        )
    )

    unlabeled = [
        row
        for row in labels
        if row["expected_positive"] is None
    ]

    if unlabeled:
        raise RuntimeError(
            f"{len(unlabeled)} holdout kaydi henuz label edilmedi. "
            "Evaluation durduruldu."
        )

    fails = [
        finding
        for finding in findings
        if finding.get("status_code") == "FAIL"
    ]

    if len(fails) != len(labels):
        raise RuntimeError(
            "Raw FAIL finding sayisi ile holdout label sayisi uyusmuyor."
        )

    evaluated = []

    for label in labels:
        source_index = label["source_index"]

        if source_index < 0 or source_index >= len(fails):
            raise RuntimeError(
                f"Gecersiz source_index: {source_index}"
            )

        finding = fails[source_index]

        scored = score_finding_v2(
            finding
        )

        evaluated.append(
            {
                **label,
                "v2_score": scored["v2_score"],
                "predicted_positive": (
                    scored["v2_score"] >= V2_THRESHOLD
                ),
            }
        )

    metrics = calculate_metrics(
        evaluated
    )

    positive_count = sum(
        1
        for row in evaluated
        if row["expected_positive"] is True
    )

    negative_count = sum(
        1
        for row in evaluated
        if row["expected_positive"] is False
    )

    print("=" * 70)
    print("SENTINELMIND SCORING V2 HOLDOUT VALIDATION")
    print("=" * 70)

    print(f"V2 Version : {V2_VERSION}")
    print(f"Threshold  : {V2_THRESHOLD}")
    print(f"Holdout N  : {len(evaluated)}")
    print(f"Positive   : {positive_count}")
    print(f"Negative   : {negative_count}")

    print()
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

    print()
    print(
        "Bu sonuc frozen V2 v1.0 kurallari "
        "degistirilmeden hesaplandi."
    )


if __name__ == "__main__":
    main()