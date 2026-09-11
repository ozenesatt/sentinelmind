from unittest.mock import MagicMock, patch

import pytest

from rag.ai_schema import AIAnalysis
from rag.analysis_writer import write_ai_analysis


def build_analysis():
    return AIAnalysis.model_validate(
        {
            "schema_version": "1.0",
            "incident_id": "550e8400-e29b-41d4-a716-446655440000",
            "title_tr": "Test analysis",
            "summary_tr": "Test summary",
            "severity": "high",
            "mitre_techniques": [],
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
                        "reason": "Manual review required.",
                    },
                    "rationale_tr": "Manual review.",
                }
            ],
            "kvkk": {
                "notification_required": False,
                "draft_tr": None,
            },
            "generated_at": "2026-09-07T10:00:00Z",
        }
    )


def test_pii_masked_false_is_rejected():
    analysis = build_analysis()

    with pytest.raises(ValueError):
        write_ai_analysis(
            analysis,
            pii_masked=False,
        )


def test_write_ai_analysis_uses_db_insert():
    analysis = build_analysis()

    mock_cursor = MagicMock()

    mock_cursor.fetchone.return_value = {
        "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "incident_id": analysis.incident_id,
        "payload": analysis.model_dump(),
        "pii_masked": True,
        "created_at": "2026-09-07T10:00:00Z",
    }

    mock_cursor_context = MagicMock()
    mock_cursor_context.__enter__.return_value = mock_cursor

    mock_connection = MagicMock()
    mock_connection.cursor.return_value = mock_cursor_context

    mock_connection_context = MagicMock()
    mock_connection_context.__enter__.return_value = mock_connection

    with patch(
        "rag.analysis_writer.connect_db",
        return_value=mock_connection_context,
    ):
        result = write_ai_analysis(
            analysis,
            pii_masked=True,
        )

    assert result["pii_masked"] is True
    assert result["incident_id"] == analysis.incident_id

    assert mock_cursor.execute.called

    sql = mock_cursor.execute.call_args[0][0]

    assert "INSERT INTO ai_analyses" in sql
    assert "pii_masked" in sql

    params = mock_cursor.execute.call_args[0][1]

    assert params[1] == analysis.incident_id
    assert params[3] is True


if __name__ == "__main__":
    pytest.main([__file__, "-q"])