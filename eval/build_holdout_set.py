import argparse
import json
from pathlib import Path

from engine.filter_engine import get_resource_name


OUTPUT = Path("eval/holdout_findings.json")


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "source_file",
        help="Yeni ve bagimsiz Prowler OCSF JSON dosyasi",
    )

    args = parser.parse_args()

    source = Path(args.source_file)

    if not source.exists():
        raise FileNotFoundError(
            f"Holdout source bulunamadi: {source}"
        )

    findings = json.loads(
        source.read_text(
            encoding="utf-8-sig"
        )
    )

    fails = [
        finding
        for finding in findings
        if finding.get("status_code") == "FAIL"
    ]

    dataset = []

    for source_index, finding in enumerate(fails):
        metadata = finding.get(
            "metadata",
            {},
        )

        dataset.append(
            {
                "holdout_id": source_index + 1,
                "source_index": source_index,
                "event_code": metadata.get(
                    "event_code",
                    "?",
                ),
                "severity": finding.get(
                    "severity",
                    "Unknown",
                ),
                "resource": get_resource_name(
                    finding
                ),
                "categories": (
                    finding.get(
                        "unmapped",
                        {},
                    ).get(
                        "categories",
                        [],
                    )
                ),
                "message": finding.get(
                    "message",
                    "",
                )[:200],

                # Human ground truth.
                # Prediction burada bilerek yok.
                "expected_positive": None,
                "label_reason": "",
            }
        )

    OUTPUT.write_text(
        json.dumps(
            dataset,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print("=" * 60)
    print("SENTINELMIND HOLDOUT SET CREATED")
    print("=" * 60)
    print(f"Source: {source}")
    print(f"Toplam finding: {len(findings)}")
    print(f"FAIL finding: {len(fails)}")
    print(f"Holdout kaydi: {len(dataset)}")
    print(f"Output: {OUTPUT}")
    print()
    print(
        "Prediction alanlari holdout dosyasina "
        "bilerek eklenmedi."
    )


if __name__ == "__main__":
    main()