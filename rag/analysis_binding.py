from datetime import datetime, timezone

from rag.ai_schema import AIAnalysis


def bind_authoritative_fields(
    analysis: AIAnalysis,
    incident: dict,
) -> AIAnalysis:
    """
    LLM tarafindan uretilen analysis icindeki authoritative alanlari
    trusted application verisiyle yeniden baglar.

    Authoritative alanlar:
    - incident_id
    - severity
    - generated_at
    """

    incident_id = str(incident["incident_id"])
    severity = incident["severity"]

    generated_at = (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )

    payload = analysis.model_dump()

    payload["incident_id"] = incident_id
    payload["severity"] = severity
    payload["generated_at"] = generated_at

    return AIAnalysis.model_validate(payload)