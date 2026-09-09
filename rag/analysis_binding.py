from datetime import datetime, timezone

from rag.ai_schema import AIAnalysis


def normalize_mitre_ids(values) -> list[str]:
    if not values:
        return []

    result = []

    for value in values:
        value = str(value).strip()

        if value and value not in result:
            result.append(value)

    return result


def bind_authoritative_fields(
    analysis: AIAnalysis,
    incident: dict,
) -> AIAnalysis:
    """
    LLM tarafindan uretilen analysis icindeki authoritative
    alanlari trusted incident verisiyle yeniden baglar.

    Authoritative:
    - incident_id
    - severity
    - generated_at
    - source MITRE IDs (eger mevcutsa)

    Source MITRE yoksa model/RAG enrichment korunabilir.
    """

    payload = analysis.model_dump()

    payload["incident_id"] = str(
        incident["incident_id"]
    )

    payload["severity"] = incident["severity"]

    payload["generated_at"] = (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )

    source_mitre_ids = normalize_mitre_ids(
        incident.get("source_mitre_ids")
        or incident.get("mitre_ids")
        or []
    )

    if source_mitre_ids:
        payload["mitre_techniques"] = source_mitre_ids

    return AIAnalysis.model_validate(payload)