import os
import uuid
from typing import Any, Literal
from uuid import UUID

import psycopg2
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from psycopg2.extras import Json, RealDictCursor
from pydantic import BaseModel, Field

load_dotenv()

app = FastAPI(
    title="SentinelMind AI API",
    version="0.1.0",
)


def connect_db():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "sentinelmind"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD"),
    )


class ActionCreate(BaseModel):
    incident_id: UUID
    action_type: Literal[
        "block_ip",
        "disable_user",
        "isolate_vm",
        "close_nsg_rule",
        "revoke_storage_key",
        "none",
    ]
    params: dict[str, Any] = Field(default_factory=dict)


class ApproveRequest(BaseModel):
    approved_by: str


class RejectRequest(BaseModel):
    rejected_by: str


class TeamsActionRequest(BaseModel):
    sentinelmind_action: Literal["approve", "reject"]
    action_id: UUID
    incident_id: UUID
    actor: str = Field(min_length=1, max_length=200)


@app.get("/health")
def health():
    try:
        with connect_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1;")
                cur.fetchone()

        return {
            "status": "ok",
            "database": "ok",
        }

    except psycopg2.Error:
        raise HTTPException(
            status_code=503,
            detail="database unavailable",
        )


@app.get("/incidents")
def list_incidents():
    try:
        with connect_db() as conn:
            with conn.cursor(
                cursor_factory=RealDictCursor
            ) as cur:
                cur.execute(
                    """
                    SELECT
                        id,
                        created_at,
                        event_ids,
                        risk_score,
                        severity,
                        status
                    FROM incidents
                    ORDER BY created_at DESC;
                    """
                )
                rows = cur.fetchall()

        return [dict(row) for row in rows]

    except psycopg2.Error:
        raise HTTPException(
            status_code=503,
            detail="database unavailable",
        )


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: UUID):
    try:
        with connect_db() as conn:
            with conn.cursor(
                cursor_factory=RealDictCursor
            ) as cur:
                cur.execute(
                    """
                    SELECT
                        id,
                        created_at,
                        event_ids,
                        risk_score,
                        severity,
                        status
                    FROM incidents
                    WHERE id = %s;
                    """,
                    (str(incident_id),),
                )
                row = cur.fetchone()

        if row is None:
            raise HTTPException(
                status_code=404,
                detail="incident not found",
            )

        return dict(row)

    except HTTPException:
        raise

    except psycopg2.Error:
        raise HTTPException(
            status_code=503,
            detail="database unavailable",
        )


@app.get("/actions")
def list_actions():
    try:
        with connect_db() as conn:
            with conn.cursor(
                cursor_factory=RealDictCursor
            ) as cur:
                cur.execute(
                    """
                    SELECT
                        id,
                        incident_id,
                        action_type,
                        params,
                        status,
                        approved_by,
                        executed_at,
                        result
                    FROM actions
                    ORDER BY id DESC;
                    """
                )
                rows = cur.fetchall()

        return [dict(row) for row in rows]

    except psycopg2.Error:
        raise HTTPException(
            status_code=503,
            detail="database unavailable",
        )


@app.get("/actions/{action_id}")
def get_action(action_id: UUID):
    try:
        with connect_db() as conn:
            with conn.cursor(
                cursor_factory=RealDictCursor
            ) as cur:
                cur.execute(
                    """
                    SELECT
                        id,
                        incident_id,
                        action_type,
                        params,
                        status,
                        approved_by,
                        executed_at,
                        result
                    FROM actions
                    WHERE id = %s;
                    """,
                    (str(action_id),),
                )
                row = cur.fetchone()

        if row is None:
            raise HTTPException(
                status_code=404,
                detail="action not found",
            )

        return dict(row)

    except HTTPException:
        raise

    except psycopg2.Error:
        raise HTTPException(
            status_code=503,
            detail="database unavailable",
        )


@app.post("/actions", status_code=201)
def create_action(body: ActionCreate):
    action_id = uuid.uuid4()

    try:
        with connect_db() as conn:
            with conn.cursor(
                cursor_factory=RealDictCursor
            ) as cur:
                cur.execute(
                    """
                    INSERT INTO actions (
                        id,
                        incident_id,
                        action_type,
                        params,
                        status
                    )
                    VALUES (%s, %s, %s, %s, 'pending')
                    RETURNING
                        id,
                        incident_id,
                        action_type,
                        params,
                        status,
                        approved_by,
                        executed_at,
                        result;
                    """,
                    (
                        str(action_id),
                        str(body.incident_id),
                        body.action_type,
                        Json(body.params),
                    ),
                )
                row = cur.fetchone()

        return dict(row)

    except psycopg2.errors.ForeignKeyViolation:
        raise HTTPException(
            status_code=404,
            detail="incident not found",
        )

    except psycopg2.Error:
        raise HTTPException(
            status_code=503,
            detail="database unavailable",
        )


@app.post("/actions/{action_id}/approve")
def approve_action(
    action_id: UUID,
    body: ApproveRequest,
):
    try:
        with connect_db() as conn:
            with conn.cursor(
                cursor_factory=RealDictCursor
            ) as cur:
                cur.execute(
                    """
                    UPDATE actions
                    SET
                        status = 'approved',
                        approved_by = %s
                    WHERE id = %s
                      AND status = 'pending'
                    RETURNING
                        id,
                        incident_id,
                        action_type,
                        params,
                        status,
                        approved_by,
                        executed_at,
                        result;
                    """,
                    (
                        body.approved_by,
                        str(action_id),
                    ),
                )
                row = cur.fetchone()

                if row is None:
                    cur.execute(
                        "SELECT status FROM actions WHERE id = %s;",
                        (str(action_id),),
                    )
                    existing = cur.fetchone()

                    if existing is None:
                        raise HTTPException(
                            status_code=404,
                            detail="action not found",
                        )

                    raise HTTPException(
                        status_code=409,
                        detail="action is not pending",
                    )

        return dict(row)

    except HTTPException:
        raise

    except psycopg2.Error:
        raise HTTPException(
            status_code=503,
            detail="database unavailable",
        )


@app.post("/actions/{action_id}/reject")
def reject_action(
    action_id: UUID,
    body: RejectRequest,
):
    try:
        with connect_db() as conn:
            with conn.cursor(
                cursor_factory=RealDictCursor
            ) as cur:
                cur.execute(
                    """
                    UPDATE actions
                    SET
                        status = 'rejected',
                        result = jsonb_build_object(
                            'rejected_by',
                            %s::text
                        )
                    WHERE id = %s
                      AND status = 'pending'
                    RETURNING
                        id,
                        incident_id,
                        action_type,
                        params,
                        status,
                        approved_by,
                        executed_at,
                        result;
                    """,
                    (
                        body.rejected_by,
                        str(action_id),
                    ),
                )
                row = cur.fetchone()

                if row is None:
                    cur.execute(
                        "SELECT status FROM actions WHERE id = %s;",
                        (str(action_id),),
                    )
                    existing = cur.fetchone()

                    if existing is None:
                        raise HTTPException(
                            status_code=404,
                            detail="action not found",
                        )

                    raise HTTPException(
                        status_code=409,
                        detail="action is not pending",
                    )

        return dict(row)

    except HTTPException:
        raise

    except psycopg2.Error:
        raise HTTPException(
            status_code=503,
            detail="database unavailable",
        )

@app.post("/teams/actions")
def handle_teams_action(body: TeamsActionRequest):
    action = get_action(body.action_id)

    if str(action["incident_id"]) != str(body.incident_id):
        raise HTTPException(
            status_code=409,
            detail="action does not belong to incident",
        )

    if body.sentinelmind_action == "approve":
        return approve_action(
            body.action_id,
            ApproveRequest(
                approved_by=body.actor,
            ),
        )

    return reject_action(
        body.action_id,
        RejectRequest(
            rejected_by=body.actor,
        ),
    )
