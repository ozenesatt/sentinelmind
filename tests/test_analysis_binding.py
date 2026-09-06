from rag.ai_schema import AIAnalysis
from rag.analysis_binding import bind_authoritative_fields


def test_authoritative_fields_are_bound_from_incident():
    incident = {
        "incident_id": "real-incident-001",
        "risk_score": 91,
        "severity": "critical",
    }

    # LLM'in bilerek yanlis authoritative alanlar
    # dondurdugunu simule ediyoruz.
    model_analysis = AIAnalysis.model_validate(
        {
            "schema_version": "1.0",
            "incident_id": "fake-incident-999",
            "title_tr": "Test analiz",
            "summary_tr": "Model tarafindan uretilen test analizidir.",
            "severity": "low",
            "risk_explanation": (
                "Model bu alani aciklar ancak risk skorunu belirlemez."
            ),
            "mitre_techniques": [],
            "affected_resources": [],
            "recommended_actions": [
                {
                    "action_type": "none",
                    "params": {},
                    "rationale_tr": "Manuel inceleme.",
                }
            ],
            "kvkk": {
                "notification_required": False,
                "draft_tr": None,
            },
            "generated_at": "2000-01-01T00:00:00Z",
        }
    )

    final_analysis = bind_authoritative_fields(
        model_analysis,
        incident,
    )

    assert final_analysis.incident_id == "real-incident-001"
    assert final_analysis.severity == "critical"

    assert (
        final_analysis.generated_at
        != "2000-01-01T00:00:00Z"
    )

    print("Authoritative field binding testi BASARILI")


if __name__ == "__main__":
    test_authoritative_fields_are_bound_from_incident()