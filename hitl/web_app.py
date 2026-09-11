import html
import json
from uuid import UUID

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse

from api.main import (
    ApproveRequest,
    RejectRequest,
    approve_action,
    get_incident,
    list_actions,
    reject_action,
)


app = FastAPI(
    title="SentinelMind HITL Web UI",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


def safe(value) -> str:
    if value is None:
        return "-"
    return html.escape(str(value))


@app.get("/", response_class=HTMLResponse)
def dashboard():
    actions = list_actions()
    pending_actions = [
        action
        for action in actions
        if action.get("status") == "pending"
    ]

    cards = []

    for action in pending_actions:
        try:
            incident = get_incident(
                UUID(str(action["incident_id"]))
            )
        except HTTPException:
            incident = {}

        params = json.dumps(
            action.get("params") or {},
            ensure_ascii=False,
            indent=2,
            default=str,
        )

        cards.append(
            f"""
            <section class="card">
                <div class="top">
                    <div>
                        <div class="label">INCIDENT</div>
                        <div class="mono">{safe(action.get("incident_id"))}</div>
                    </div>
                    <span class="status">PENDING</span>
                </div>

                <div class="grid">
                    <div>
                        <div class="label">Risk Score</div>
                        <div class="value">{safe(incident.get("risk_score"))}</div>
                    </div>

                    <div>
                        <div class="label">Severity</div>
                        <div class="value">{safe(incident.get("severity")).upper()}</div>
                    </div>

                    <div>
                        <div class="label">Action</div>
                        <div class="value">{safe(action.get("action_type"))}</div>
                    </div>
                </div>

                <div class="label">Action ID</div>
                <div class="mono small">{safe(action.get("id"))}</div>

                <div class="label space">Parameters</div>
                <pre>{safe(params)}</pre>

                <div class="buttons">
                    <form method="post"
                          action="/actions/{safe(action.get("id"))}/approve">
                        <button class="approve" type="submit">
                            APPROVE
                        </button>
                    </form>

                    <form method="post"
                          action="/actions/{safe(action.get("id"))}/reject">
                        <button class="reject" type="submit">
                            REJECT
                        </button>
                    </form>
                </div>
            </section>
            """
        )

    if not cards:
        cards.append(
            """
            <section class="empty">
                <h2>No pending actions</h2>
                <p>SentinelMind currently has no actions waiting for human approval.</p>
            </section>
            """
        )

    page = f"""
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>SentinelMind HITL</title>
        <style>
            * {{
                box-sizing: border-box;
            }}

            body {{
                margin: 0;
                font-family: Segoe UI, Arial, sans-serif;
                background: #07111f;
                color: #eaf2ff;
            }}

            header {{
                padding: 28px 7%;
                border-bottom: 1px solid #1c3554;
                background: #0a1628;
            }}

            header h1 {{
                margin: 0;
                font-size: 26px;
            }}

            header p {{
                margin: 7px 0 0;
                color: #8fa9c7;
            }}

            main {{
                width: min(1050px, 90%);
                margin: 36px auto;
            }}

            .card {{
                background: #0d1b2e;
                border: 1px solid #203b5c;
                border-radius: 14px;
                padding: 24px;
                margin-bottom: 22px;
            }}

            .top {{
                display: flex;
                justify-content: space-between;
                gap: 20px;
                margin-bottom: 25px;
            }}

            .grid {{
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 18px;
                padding: 20px 0;
                margin-bottom: 18px;
                border-top: 1px solid #203b5c;
                border-bottom: 1px solid #203b5c;
            }}

            .label {{
                color: #7894b5;
                font-size: 12px;
                letter-spacing: 1px;
                text-transform: uppercase;
                margin-bottom: 6px;
            }}

            .value {{
                font-size: 20px;
                font-weight: 600;
            }}

            .mono {{
                font-family: Consolas, monospace;
                color: #b9d5f5;
            }}

            .small {{
                font-size: 13px;
            }}

            .space {{
                margin-top: 20px;
            }}

            .status {{
                height: fit-content;
                padding: 7px 12px;
                background: #3c3110;
                border: 1px solid #8a7018;
                border-radius: 20px;
                color: #ffd761;
                font-size: 12px;
                font-weight: 700;
            }}

            pre {{
                overflow-x: auto;
                padding: 14px;
                border-radius: 8px;
                background: #07111f;
                border: 1px solid #1c3554;
                color: #cfe1f7;
            }}

            .buttons {{
                display: flex;
                gap: 12px;
                margin-top: 24px;
            }}

            button {{
                border: 0;
                border-radius: 8px;
                padding: 11px 24px;
                font-weight: 700;
                cursor: pointer;
            }}

            .approve {{
                background: #2b7a4b;
                color: white;
            }}

            .reject {{
                background: #963b45;
                color: white;
            }}

            .empty {{
                text-align: center;
                padding: 60px 20px;
                background: #0d1b2e;
                border: 1px solid #203b5c;
                border-radius: 14px;
            }}

            .empty p {{
                color: #8fa9c7;
            }}

            @media (max-width: 700px) {{
                .grid {{
                    grid-template-columns: 1fr;
                }}
            }}
        </style>
    </head>

    <body>
        <header>
            <h1>SentinelMind AI</h1>
            <p>Human-in-the-Loop Security Approval</p>
        </header>

        <main>
            {''.join(cards)}
        </main>
    </body>
    </html>
    """

    return HTMLResponse(page)


@app.post("/actions/{action_id}/approve")
def web_approve(action_id: UUID):
    approve_action(
        action_id,
        ApproveRequest(
            approved_by="sentinelmind-web-ui"
        ),
    )

    return RedirectResponse(
        url="/",
        status_code=303,
    )


@app.post("/actions/{action_id}/reject")
def web_reject(action_id: UUID):
    reject_action(
        action_id,
        RejectRequest(
            rejected_by="sentinelmind-web-ui"
        ),
    )

    return RedirectResponse(
        url="/",
        status_code=303,
    )
