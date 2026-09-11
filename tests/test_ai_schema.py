from pydantic import ValidationError

from rag.ai_schema import AIAnalysis


EMPTY_PARAMS = {
    "ip": None,
    "username": None,
    "resource_id": None,
    "rule_name": None,
    "key_name": None,
    "reason": None,
}


def test_valid_ai_analysis():
    params = dict(EMPTY_PARAMS)
    params["reason"] = "Manuel inceleme gerekli."

    payload = {
        "schema_version": "1.0",
        "incident_id": "demo-prowler-001",
        "title_tr": "Azure Storage public access riski",
        "summary_tr": (
            "Storage account anonim blob erisimine acik."
        ),
        "severity": "high",
        "mitre_techniques": [
            "T1619",
            "T1530",
        ],
        "affected_resources": [
            {
                "type": "storage_account",
                "id": (
                    "/subscriptions/demo/"
                    "resourceGroups/sentinelmind-rg/"
                    "providers/Microsoft.Storage/"
                    "storageAccounts/smweak"
                ),
            }
        ],
        "recommended_actions": [
            {
                "action_type": "none",
                "params": params,
                "rationale_tr": (
                    "Manuel inceleme onerilir."
                ),
            }
        ],
        "kvkk": {
            "notification_required": False,
            "draft_tr": None,
        },
        "generated_at": "2026-09-06T12:00:00Z",
    }

    analysis = AIAnalysis.model_validate(payload)

    assert analysis.schema_version == "1.0"
    assert analysis.incident_id == "demo-prowler-001"
    assert analysis.severity == "high"
    assert analysis.recommended_actions[0].action_type == "none"

    print("AI schema testi BASARILI")


def test_invalid_action_type_is_rejected():
    params = dict(EMPTY_PARAMS)
    params["reason"] = "Test"

    payload = {
        "schema_version": "1.0",
        "incident_id": "demo-invalid-001",
        "title_tr": "Test",
        "summary_tr": "Test",
        "severity": "high",
        "mitre_techniques": [],
        "affected_resources": [],
        "recommended_actions": [
            {
                "action_type": "delete_resource",
                "params": params,
                "rationale_tr": "Gecersiz action",
            }
        ],
        "kvkk": {
            "notification_required": False,
            "draft_tr": None,
        },
        "generated_at": "2026-09-06T12:00:00Z",
    }

    try:
        AIAnalysis.model_validate(payload)

    except ValidationError:
        print("Gecersiz action_type reddedildi")
        return

    raise AssertionError(
        "Gecersiz action_type kabul edildi!"
    )


if __name__ == "__main__":
    test_valid_ai_analysis()
    test_invalid_action_type_is_rejected()