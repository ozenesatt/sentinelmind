from typing import Literal
from pydantic import BaseModel, Field


ActionType = Literal[
    "block_ip",
    "disable_user",
    "isolate_vm",
    "close_nsg_rule",
    "revoke_storage_key",
    "none",
]


class AffectedResource(BaseModel):
    type: str
    id: str


class RecommendedAction(BaseModel):
    action_type: ActionType
    params: dict = Field(default_factory=dict)
    rationale_tr: str


class KvkkAssessment(BaseModel):
    notification_required: bool
    draft_tr: str | None = None


class AIAnalysis(BaseModel):
    schema_version: Literal["1.0"] = "1.0"

    incident_id: str

    title_tr: str
    summary_tr: str

    severity: Literal[
        "low",
        "medium",
        "high",
        "critical",
    ]

    mitre_techniques: list[str]

    affected_resources: list[AffectedResource]

    recommended_actions: list[RecommendedAction]

    kvkk: KvkkAssessment

    generated_at: str