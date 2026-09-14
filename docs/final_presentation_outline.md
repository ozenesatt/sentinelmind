# SentinelMind AI — Final Presentation Outline

## Sunum Ana Mesajı

SentinelMind, cloud security bulgularını yalnızca listeleyen bir sistem değildir.

Platform:

- güvenlik bulgularını toplar
- deterministic olarak önceliklendirir
- ilişkili olayları incident haline getirir
- RAG destekli AI analizi üretir
- kritik alanları trusted application logic ile doğrular
- insan onayı olmadan remediation çalıştırmaz
- yapılan işlemleri audit olarak kaydeder

Ana güvenlik prensibi:

**AI analyzes and recommends.  
Trusted systems validate.  
Humans approve.  
Deterministic executors remediate.**

---

# Slide 1 — Problem

## Başlık

**Cloud Security Alerts Are Easy to Generate, Hard to Prioritize**

## Anlatılacaklar

Cloud ve endpoint güvenlik sistemleri çok sayıda finding ve event üretir.

Sorun yalnızca tespit değildir.

Asıl sorular:

- Hangisi gerçekten önemli?
- Hangilerine önce müdahale edilmeli?
- Birden fazla event aynı incident'ın parçası mı?
- Güvenlik analistine olay nasıl açıklanmalı?
- AI önerisine güvenilebilir mi?
- Remediation güvenli şekilde nasıl yapılmalı?

## Mesaj

SentinelMind bu zinciri tek platform içinde birleştirmeyi hedefler.

---

# Slide 2 — SentinelMind Architecture

## Başlık

**From Detection to Human-Approved Remediation**

## Mimari Akış

Prowler / Wazuh
→ Events
→ Deterministic Risk Scoring
→ Correlation
→ Incidents
→ PII Masking
→ RAG
→ Azure OpenAI
→ Structured AI Analysis
→ Trusted Validation
→ Pending Action
→ Human Approval
→ Remediation
→ Audit

## Temel Bileşenler

Detection:

- Prowler
- Wazuh
- Sigma
- correlation

AI:

- CIS
- MITRE ATT&CK
- KVKK
- Azure OpenAI
- structured outputs

Platform:

- PostgreSQL
- FastAPI
- HITL Web Panel
- Azure remediation executor

---

# Slide 3 — Detection & Risk Prioritization

## Başlık

**Deterministic Before Generative AI**

## Ana Noktalar

Risk score LLM tarafından hesaplanmaz.

Deterministic scoring engine kullanılır.

Baseline:

- 55 FAIL finding
- 16 manually labeled positive
- 39 negative
- threshold: 60

Baseline result:

- TP: 9
- FP: 0
- FN: 7
- TN: 39
- Precision: 1.000
- Recall: 0.562
- F1: 0.720

## Deneysel V2

Tuning-set:

- Precision: 1.000
- Recall: 1.000
- F1: 1.000

Ancak:

**Bu bağımsız holdout sonucu değildir.**

Independent validation yeni unseen Prowler data gerektirir.

---

# Slide 4 — AI Analysis with Trust Boundaries

## Başlık

**AI Is Not the Source of Truth**

## RAG Kaynakları

- CIS Azure Foundations
- MITRE ATT&CK Enterprise
- KVKK context

## AI Output

- title_tr
- summary_tr
- severity
- mitre_techniques
- affected_resources
- recommended_actions
- kvkk

## Authoritative Alanlar

LLM tarafından değiştirilemez:

- incident_id
- severity
- generated_at
- source MITRE IDs

## Güvenlik

- PII masking
- strict schema
- closed action enum
- fail-closed placeholder resolution
- structured output validation
- prompt injection guards

---

# Slide 5 — Real Incident #31

## Başlık

**Real Azure Security Finding**

## Finding

Azure NSG:

`sentinelmind-soc-nsg`

Rule:

`DEMO-Insecure-SSH-Any`

Configuration:

- Allow
- Inbound
- TCP
- Source: *
- Destination Port: 22

## Incident

Risk Score:

`70`

Severity:

`high`

## Authoritative MITRE

- T1199
- T1048
- T1499
- T1498
- T1046

Modelin daha önce eklediği source dışı technique final output'a alınmamıştır.

---

# Slide 6 — Trusted AI Action Bridge

## Başlık

**AI Recommendation ≠ Direct Execution**

## Gerçek Öneri

`close_nsg_rule`

## Bridge Kontrolleri

AI recommendation:

→ authoritative Prowler event ile karşılaştırılır

Doğrulanan:

- Azure resource ID
- resource group
- NSG name
- rule name
- protocol
- source
- port

Sonuç:

`pending action`

AI doğrudan Azure'a işlem göndermez.

---

# Slide 7 — Human-in-the-Loop Remediation

## Başlık

**Human Approval Before Cloud Changes**

## Akış

Pending Action
→ HITL Web Panel
→ Approve / Reject

Approve sonrası:

`status = approved`

ancak:

`executed_at = NULL`

Bu noktada Azure henüz değiştirilmez.

Executor önce:

`dry-run`

ile hedefi doğrular.

Sonrasında açık execution komutu ile remediation yapılır.

---

# Slide 8 — Real Azure Remediation

## Başlık

**End-to-End Verified**

## Gerçek Sonuç

`DEMO-Insecure-SSH-Any`

Azure NSG rule gerçek ortamdan silindi.

Doğrulama:

Azure CLI → `NotFound`

PostgreSQL:

- status = executed
- executed_at = populated
- outcome = rule_deleted

Sonrasında demo environment Bicep ile reset edildi.

---

# Slide 9 — Detection Engineering

## Başlık

**Beyond Cloud Findings**

## Ek Detection Çalışmaları

Sigma:

- Windows 4625 failed logon
- RDP failed logon
- RDP successful logon telemetry

Correlation:

- same username
- same source IP
- ≥5 failed logons
- 5-minute window

Wazuh adapter:

- nested Wazuh event normalization
- brute-force validator

Real Wazuh validation:

optional / pending real exported dataset

---

# Slide 10 — Security Controls

## Başlık

**Designed to Fail Closed**

## Kontroller

- deterministic risk scoring
- PII masking before LLM
- strict structured output
- authoritative field binding
- source MITRE preservation
- closed action enum
- trusted action validation
- human approval
- dry-run remediation
- PostgreSQL audit trail

## Mesaj

SentinelMind LLM'e güvenlik kontrolünün tamamını devretmez.

---

# Slide 11 — Current Status

## Başlık

**Functional MVP Validated**

## Tamamlananlar

- Prowler ingestion
- Wazuh integration
- PostgreSQL
- deterministic risk scoring
- correlation
- incident generation
- RAG
- Azure OpenAI
- AI analysis persistence
- FastAPI read-back
- Trusted AI Action Bridge
- HITL Web Panel
- real Azure remediation
- audit
- Detection/Eval workflow

## Final Kapanış

- PR #15 merge
- final merged-main regression
- documentation integration
- CI / packaging
- presentation

---

# Slide 12 — What Makes SentinelMind Different?

## Başlık

**AI-Assisted Security, Not AI-Controlled Security**

## Farklılaştırıcı Noktalar

1. CSPM + SIEM/XDR yaklaşımı

2. Deterministic risk scoring

3. Measurable detection metrics

4. RAG with CIS / MITRE / KVKK context

5. Turkish security analysis

6. Authoritative source preservation

7. Human-in-the-loop remediation

8. Real Azure E2E validation

## Final Mesaj

SentinelMind'in amacı:

**AI kullanarak güvenlik analistinin karar verme sürecini hızlandırmak,
ancak güvenlik kontrolünü AI'a devretmemektir.**

---

# Optional Demo Backup

Canlı demo başarısız olursa aşağıdaki kanıtlar hazır tutulmalıdır:

- Prowler finding screenshot
- Incident #31 DB result
- AI analysis JSON
- FastAPI read-back
- HITL Web Panel screenshot
- approved action DB result
- dry-run output
- Azure rule before/after
- executed audit record
- reset deployment result

Canlı demo hiçbir zaman tek kanıt yöntemi olmamalıdır.