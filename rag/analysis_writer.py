import os
import uuid
from uuid import UUID

import psycopg2
from psycopg2.extras import Json, RealDictCursor

from rag.ai_schema import AIAnalysis


def connect_db():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "sentinelmind"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD"),
    )


def validate_incident_id(incident_id: str) -> UUID:
    """
    ai_analyses.incident_id UUID FK oldugu icin
    gercek incident UUID beklenir.
    """

    try:
        return UUID(str(incident_id))
    except ValueError as exc:
        raise ValueError(
            "ai_analyses yazimi icin incident_id "
            "gecerli bir UUID olmali."
        ) from exc


def write_ai_analysis(
    analysis: AIAnalysis,
    pii_masked: bool,
) -> dict:
    """
    Dogrulanmis AI analysis sonucunu ai_analyses tablosuna yazar.

    Guvenlik siniri:
    LLM'e PII gonderildiyse bu fonksiyon kullanilmamalidir.
    SentinelMind AI pipeline'inda DB yazimi icin pii_masked=True
    zorunludur.
    """

    if pii_masked is not True:
        raise ValueError(
            "ai_analyses yazimi icin pii_masked=True zorunludur."
        )

    incident_id = validate_incident_id(
        analysis.incident_id
    )

    analysis_id = uuid.uuid4()

    payload = analysis.model_dump()

    with connect_db() as conn:
        with conn.cursor(
            cursor_factory=RealDictCursor
        ) as cur:
            cur.execute(
                """
                INSERT INTO ai_analyses (
                    id,
                    incident_id,
                    payload,
                    pii_masked
                )
                VALUES (%s, %s, %s, %s)
                RETURNING
                    id,
                    incident_id,
                    payload,
                    pii_masked,
                    created_at;
                """,
                (
                    str(analysis_id),
                    str(incident_id),
                    Json(payload),
                    True,
                ),
            )

            row = cur.fetchone()

    return dict(row)


def read_ai_analysis(
    analysis_id: UUID | str,
) -> dict | None:
    """
    Yazilan kaydi tekrar okuyarak DB dogrulamasi icin kullanilir.
    """

    analysis_id = UUID(str(analysis_id))

    with connect_db() as conn:
        with conn.cursor(
            cursor_factory=RealDictCursor
        ) as cur:
            cur.execute(
                """
                SELECT
                    id,
                    incident_id,
                    payload,
                    pii_masked,
                    created_at
                FROM ai_analyses
                WHERE id = %s;
                """,
                (str(analysis_id),),
            )

            row = cur.fetchone()

    if row is None:
        return None

    return dict(row)