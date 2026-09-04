import json
from pathlib import Path


def load_incident(path: str) -> dict:
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"Incident dosyasi bulunamadi: {file_path}"
        )

    with file_path.open("r", encoding="utf-8") as f:
        incident = json.load(f)

    required_fields = [
        "incident_id",
        "event_ids",
        "risk_score",
        "severity",
    ]

    missing = [
        field
        for field in required_fields
        if field not in incident
    ]

    if missing:
        raise ValueError(
            f"Eksik incident alanlari: {missing}"
        )

    return incident