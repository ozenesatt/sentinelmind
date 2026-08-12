-- SentinelMind AI — paylaşılan veri şeması v1.0
-- Sahiplik: events + actions = Esat | incidents + ai_analyses = Sıla
-- Değişiklik için karşı tarafın onayı gerekir (bkz. docs/contracts.md)

-- ============================================================
-- events: Wazuh (SIEM) + Prowler (CSPM) ham girdisi
-- YAZAN: Esat (collector)  |  OKUYAN: Sıla (filtreleme/korelasyon)
-- ============================================================
CREATE TABLE events (
  id               BIGSERIAL PRIMARY KEY,
  source           TEXT NOT NULL CHECK (source IN ('wazuh','prowler')),
  external_id      TEXT UNIQUE NOT NULL,      -- idempotency: aynı olay iki kez girmesin
  occurred_at      TIMESTAMPTZ NOT NULL,
  agent_id         TEXT,
  agent_name       TEXT,
  rule_id          TEXT,
  rule_level       INT,
  rule_description TEXT,
  mitre_ids        TEXT[],                    -- örn. {'T1110.001'}
  src_ip           INET,
  dst_ip           INET,
  username         TEXT,
  resource_id      TEXT,                      -- Azure resource ID (Prowler)
  check_status     TEXT,                      -- PASS / FAIL (Prowler)
  raw              JSONB NOT NULL,            -- ham log, maskelenmemiş
  ingested_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_events_occurred ON events (occurred_at DESC);
CREATE INDEX idx_events_src_ip   ON events (src_ip);
CREATE INDEX idx_events_source   ON events (source, rule_level);

-- ============================================================
-- incidents: korelasyon motoru çıktısı
-- YAZAN: Sıla  |  OKUYAN: Esat (actions katmanı)
-- ============================================================
CREATE TABLE incidents (
  id          UUID PRIMARY KEY,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  event_ids   BIGINT[] NOT NULL,             -- ilişkilendirilen events.id listesi
  risk_score  INT NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  severity    TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  status      TEXT NOT NULL DEFAULT 'new'
);

-- ============================================================
-- ai_analyses: LLM çıktısı (Türkçe özet, öneriler, KVKK taslağı)
-- YAZAN: Sıla  |  OKUYAN: Esat (Teams Adaptive Card)
-- payload yapısı için bkz. docs/contracts.md
-- ============================================================
CREATE TABLE ai_analyses (
  id          UUID PRIMARY KEY,
  incident_id UUID NOT NULL REFERENCES incidents(id),
  payload     JSONB NOT NULL,
  pii_masked  BOOLEAN NOT NULL,              -- LLM öncesi maskeleme uygulandı mı
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- actions: insan onaylı müdahaleler
-- YAZAN: Esat
-- ============================================================
CREATE TABLE actions (
  id          UUID PRIMARY KEY,
  incident_id UUID NOT NULL REFERENCES incidents(id),
  action_type TEXT NOT NULL CHECK (action_type IN
    ('block_ip','disable_user','isolate_vm','close_nsg_rule','revoke_storage_key','none')),
  params      JSONB NOT NULL,
  status      TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','approved','rejected','executed','failed')),
  approved_by TEXT,
  executed_at TIMESTAMPTZ,
  result      JSONB
);

CREATE INDEX idx_actions_incident ON actions (incident_id);