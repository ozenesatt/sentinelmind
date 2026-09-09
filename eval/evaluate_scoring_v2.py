import json
from pathlib import Path

from engine.filter_engine import score_finding


DATA = Path("output/prowler-71-findings.ocsf.json")
LABELS = Path("eval/labeled_findings.json")

THRESHOLD = 60


def contextual_bonus(scored: dict) -> tuple[int, list[str]]:
    """
    Genel kategori agirliklarini bozmak yerine,
    guvenlik etkisi acik olan kontrol ailelerine
    aciklanabilir context bonuslari uygular.
    """

    code = scored["event_code"]
    bonus = 0
    reasons = []

    # Key Vault dogasi geregi secret/key servisi.
    if code.startswith("keyvault_"):
        bonus += 15
        reasons.append("keyvault-sensitive-service +15")

    # Network telemetry kaybi detection/forensics icin kritik.
    if code in {
        "network_flow_log_captured_sent",
        "network_watcher_enabled",
    }:
        bonus += 10
        reasons.append("network-telemetry +10")

    # Private endpoint eksigi trust-boundary riskidir.
    if code == "storage_ensure_private_endpoints_in_storage_accounts":
        bonus += 10
        reasons.append("private-endpoint-boundary +10")

    # Secure transfer dogrudan transport security kontroludur.
    if code == "storage_secure_transfer_required_is_enabled":
        bonus += 5
        reasons.append("secure-transport +5")

    return bonus, reasons


def score_v2(finding: dict) -> dict:
    scored = score_finding(finding)

    bonus, reasons = contextual_bonus(scored)

    v2_score = min(
        scored["score"] + bonus,
        100,
    )

    return {
        **scored,
        "baseline_score": scored["score"],
        "v2_score": v2_score,
        "v2_bonus": bonus,
        "v2_reasons": reasons,
    }


def calculate_metrics(rows):
    tp = fp = fn = tn = 0

    for row in rows:
        expected = row["expected_positive"]
        predicted = row["v2_score"] >= THRESHOLD

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
        scored = score_v2(finding)

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

    print(f"Threshold: {THRESHOLD}")
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
        old_pred = row["baseline_score"] >= THRESHOLD
        new_pred = row["v2_score"] >= THRESHOLD

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