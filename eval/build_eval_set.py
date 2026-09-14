import json
from pathlib import Path

from engine.filter_engine import score_finding


SOURCE = Path("output/prowler-71-findings.ocsf.json")
OUTPUT = Path("eval/labeled_findings.json")

THRESHOLD = 60


def main():
    findings = json.loads(
        SOURCE.read_text(encoding="utf-8")
    )

    fails = [
        finding
        for finding in findings
        if finding.get("status_code") == "FAIL"
    ]

    dataset = []

    for index, finding in enumerate(fails, start=1):
        scored = score_finding(finding)

        dataset.append(
            {
                "eval_id": index,
                "event_code": scored["event_code"],
                "message": scored["message"],
                "resource": scored["resource"],
                "severity": scored["severity"],
                "categories": scored["categories"],
                "risk_score": scored["score"],

                # Motorun tahmini.
                "predicted_positive": (
                    scored["score"] >= THRESHOLD
                ),

                # HUMAN GROUND TRUTH
                #
                # true  = gercekten yuksek oncelikli
                # false = yuksek oncelikli degil
                #
                # Ilk uretimde bos birakilir.
                "expected_positive": None,

                # Manuel labeling sirasinda gerekirse not.
                "label_reason": "",
            }
        )

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT.write_text(
        json.dumps(
            dataset,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(f"FAIL bulgu sayisi: {len(fails)}")
    print(f"Eval kaydi: {len(dataset)}")
    print(f"Threshold: {THRESHOLD}")
    print(f"Dosya: {OUTPUT}")


if __name__ == "__main__":
    main()