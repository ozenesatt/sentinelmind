from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


ActionType = Literal[
    "block_ip",
    "disable_user",
    "isolate_vm",
    "close_nsg_rule",
    "revoke_storage_key",
    "none",
]


class AffectedResource(StrictModel):
    type: str
    id: str


class ActionParams(StrictModel):
    # Azure Structured Outputs'ta tum alanlar required olmalidir.
    # Kullanilmayan alanlar null/None doner.
    ip: str | None
    username: str | None
    resource_id: str | None
    rule_name: str | None
    key_name: str | None
    reason: str | None


class RecommendedAction(StrictModel):
    action_type: ActionType
    params: ActionParams
    rationale_tr: str

    @model_validator(mode="after")
    def validate_required_param(self):
        params = self.params

        if self.action_type == "block_ip" and not params.ip:
            raise ValueError(
                "block_ip action icin params.ip gerekli"
            )

        if (
            self.action_type == "disable_user"
            and not params.username
        ):
            raise ValueError(
                "disable_user action icin params.username gerekli"
            )

        if (
            self.action_type == "isolate_vm"
            and not params.resource_id
        ):
            raise ValueError(
                "isolate_vm action icin params.resource_id gerekli"
            )

        if self.action_type == "close_nsg_rule":
            if not params.resource_id or not params.rule_name:
                raise ValueError(
                    "close_nsg_rule icin resource_id "
                    "ve rule_name gerekli"
                )

        if self.action_type == "revoke_storage_key":
            if not params.resource_id or not params.key_name:
                raise ValueError(
                    "revoke_storage_key icin resource_id "
                    "ve key_name gerekli"
                )

        if self.action_type == "none" and not params.reason:
            raise ValueError(
                "none action icin params.reason gerekli"
            )

        return self


class KvkkAssessment(StrictModel):
    notification_required: bool
    draft_tr: str | None


class AIAnalysis(StrictModel):
    schema_version: Literal["1.0"]

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