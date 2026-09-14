import json
from pathlib import Path

from eval.scoring_v2 import (
    V2_THRESHOLD,
    V2_VERSION,
    score_finding_v2,
)


DATA = Path("output/prowler-71-findings.ocsf.json")
LABELS = Path("eval/labeled_findings.json")


def calculate_metrics(rows):
    tp = fp = fn = tn = 0

    for row in rows:
        expected = row["expected_positive"]
        predicted = row["v2_score"] >= V2_THRESHOLD

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
        if (tp + fp)
        else 0.0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn)
        else 0.0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )

    return tp, fp, fn, tn, precision, recall, f1


def main():
    findings = json.loads(
        DATA.read_text(encoding="utf-8")
    )

    labels = json.loads(
        LABELS.read_text(encoding="utf-8")
    )

    fails = [
        finding
        for finding in findings
        if finding.get("status_code") == "FAIL"
    ]

    if len(fails) != len(labels):
        raise RuntimeError(
            "Finding ve label sayilari uyusmuyor."
        )

    rows = []

    for finding, label in zip(fails, labels):
        scored = score_finding_v2(finding)

        rows.append(
            {
                **label,
                "baseline_score": scored["baseline_score"],
                "v2_score": scored["v2_score"],
                "v2_bonus": scored["v2_bonus"],
                "v2_reasons": scored["v2_reasons"],
            }
        )

    (
        tp,
        fp,
        fn,
        tn,
        precision,
        recall,
        f1,
    ) = calculate_metrics(rows)

    print("=" * 72)
    print("SENTINELMIND EXPERIMENTAL SCORING V2")
    print("=" * 72)

    print(f"Version: {V2_VERSION}")
    print(f"Threshold: {V2_THRESHOLD}")

    print()
    print(f"TP: {tp}")
    print(f"FP: {fp}")
    print(f"FN: {fn}")
    print(f"TN: {tn}")

    print()
    print(f"Precision: {precision:.3f}")
    print(f"Recall:    {recall:.3f}")
    print(f"F1 Score:  {f1:.3f}")

    print()
    print("Degisen bulgular:")

    for row in rows:
        old_pred = (
            row["baseline_score"] >= V2_THRESHOLD
        )

        new_pred = (
            row["v2_score"] >= V2_THRESHOLD
        )

        if old_pred != new_pred:
            print(
                f"{row['eval_id']:>2} | "
                f"{row['event_code']} | "
                f"{row['baseline_score']} -> "
                f"{row['v2_score']} | "
                f"expected={row['expected_positive']} | "
                f"{row['v2_reasons']}"
            )


if __name__ == "__main__":
    main()