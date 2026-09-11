from uuid import UUID

import psycopg2
from fastapi import FastAPI, Header, HTTPException

from api.main import (
    ApproveRequest,
    RejectRequest,
    TeamsActionRequest,
    approve_action,
    connect_db,
    get_action,
    reject_action,
    verify_teams_callback_token,
)


app = FastAPI(
    title="SentinelMind Teams Callback Gateway",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


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
            "service": "teams-callback-gateway",
        }

    except psycopg2.Error:
        raise HTTPException(
            status_code=503,
            detail="database unavailable",
        )


@app.post("/teams/actions")
def handle_teams_action(
    body: TeamsActionRequest,
    x_sentinelmind_token: str | None = Header(default=None),
):
    verify_teams_callback_token(
        x_sentinelmind_token
    )

    action = get_action(
        UUID(str(body.action_id))
    )

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
