from typing import Any


ALLOWED_ACTION_TYPES = {
    "block_ip",
    "disable_user",
    "isolate_vm",
    "close_nsg_rule",
    "revoke_storage_key",
    "none",
}


def build_adaptive_card(
    incident: dict[str, Any],
    action: dict[str, Any],
    analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    action_type = action.get("action_type")

    if action_type not in ALLOWED_ACTION_TYPES:
        raise ValueError(
            f"Unsupported action_type: {action_type}"
        )

    if action.get("status") != "pending":
        raise ValueError(
            "Adaptive Card can only be created "
            "for pending actions."
        )

    incident_id = str(incident.get("id", ""))
    action_id = str(action.get("id", ""))

    if not incident_id:
        raise ValueError("incident.id is required")

    if not action_id:
        raise ValueError("action.id is required")

    if str(action.get("incident_id", "")) != incident_id:
        raise ValueError(
            "Action does not belong to incident."
        )

    risk_score = incident.get("risk_score", "unknown")
    severity = str(
        incident.get("severity", "unknown")
    ).upper()

    title = "SentinelMind Security Incident"
    summary = "AI analysis is not available."

    if analysis:
        title = analysis.get("title") or title
        summary = (
            analysis.get("summary")
            or analysis.get("analysis")
            or summary
        )

    card = {
        "$schema": (
            "http://adaptivecards.io/schemas/"
            "adaptive-card.json"
        ),
        "type": "AdaptiveCard",
        "version": "1.5",
        "body": [
            {
                "type": "TextBlock",
                "text": title,
                "weight": "Bolder",
                "size": "Large",
                "wrap": True,
            },
            {
                "type": "FactSet",
                "facts": [
                    {
                        "title": "Incident ID",
                        "value": incident_id,
                    },
                    {
                        "title": "Risk Score",
                        "value": str(risk_score),
                    },
                    {
                        "title": "Severity",
                        "value": severity,
                    },
                    {
                        "title": "Action",
                        "value": action_type,
                    },
                    {
                        "title": "Status",
                        "value": "PENDING",
                    },
                ],
            },
            {
                "type": "TextBlock",
                "text": "Analysis",
                "weight": "Bolder",
                "separator": True,
            },
            {
                "type": "TextBlock",
                "text": str(summary),
                "wrap": True,
            },
            {
                "type": "TextBlock",
                "text": (
                    "Human approval is required before "
                    "remediation."
                ),
                "wrap": True,
                "isSubtle": True,
                "separator": True,
            },
        ],
        "actions": [
            {
                "type": "Action.Submit",
                "title": "Approve",
                "data": {
                    "sentinelmind_action": "approve",
                    "action_id": action_id,
                    "incident_id": incident_id,
                },
            },
            {
                "type": "Action.Submit",
                "title": "Reject",
                "data": {
                    "sentinelmind_action": "reject",
                    "action_id": action_id,
                    "incident_id": incident_id,
                },
            },
        ],
    }

    return card
