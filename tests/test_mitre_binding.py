from rag.ai_schema import AIAnalysis
from rag.analysis_binding import bind_authoritative_fields


def build_analysis(mitre):
    return AIAnalysis.model_validate(
        {
            "schema_version": "1.0",
            "incident_id": "fake-id",
            "title_tr": "Test",
            "summary_tr": "Test",
            "severity": "low",
            "mitre_techniques": mitre,
            "affected_resources": [],
            "recommended_actions": [
                {
                    "action_type": "none",
                    "params": {
                        "ip": None,
                        "username": None,
                        "resource_id": None,
                        "rule_name": None,
                        "key_name": None,
                        "reason": "Manual review",
                    },
                    "rationale_tr": "Manual review",
                }
            ],
            "kvkk": {
                "notification_required": False,
                "draft_tr": None,
            },
            "generated_at": "2000-01-01T00:00:00Z",
        }
    )


def test_source_mitre_overrides_llm_enrichment():
    incident = {
        "incident_id": "f49d731e-c4c4-4778-84a6-d26a4df663bd",
        "severity": "high",
        "source_mitre_ids": [
            "T1199",
            "T1048",
            "T1499",
            "T1498",
            "T1046",
        ],
    }

    model_analysis = build_analysis(
        [
            "T1199",
            "T1048",
            "T1499",
            "T1498",
            "T1046",
            "T1021.004",
        ]
    )

    final_analysis = bind_authoritative_fields(
        model_analysis,
        incident,
    )

    assert final_analysis.mitre_techniques == [
        "T1199",
        "T1048",
        "T1499",
        "T1498",
        "T1046",
    ]

    assert "T1021.004" not in (
        final_analysis.mitre_techniques
    )


def test_llm_mitre_preserved_when_source_missing():
    incident = {
        "incident_id": "f49d731e-c4c4-4778-84a6-d26a4df663bd",
        "severity": "high",
        "source_mitre_ids": [],
    }

    model_analysis = build_analysis(
        ["T1021.004"]
    )

    final_analysis = bind_authoritative_fields(
        model_analysis,
        incident,
    )

    assert final_analysis.mitre_techniques == [
        "T1021.004"
    ]