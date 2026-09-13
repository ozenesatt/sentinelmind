# SentinelMind Final Demo Flow

## Amaç

Bu demo, SentinelMind'in gerçek bir Azure cloud security bulgusunu nasıl
tespit ettiğini, önceliklendirdiğini, AI ile analiz ettiğini ve insan onayı
sonrasında güvenli remediation uyguladığını uçtan uca göstermeyi amaçlar.

Ana demo senaryosu gerçek Prowler incident #31 üzerinden yürütülür.

---

## 1. Başlangıç Durumu

Azure ortamında aşağıdaki NSG kuralı bulunur:

- NSG: `sentinelmind-soc-nsg`
- Rule: `DEMO-Insecure-SSH-Any`
- Access: `Allow`
- Direction: `Inbound`
- Protocol: `Tcp`
- Source: `*`
- Destination Port: `22`
- Priority: `100`

Bu kural internet üzerinden SSH erişimine izin veren demo güvenlik
zafiyetini temsil eder.

---

## 2. Prowler Detection

Prowler Azure ortamını tarar.

Gerçek finding event #31 olarak SentinelMind veri katmanına alınır.

Finding:

`Internet-accessible SSH / TCP 22 NSG rule`

SentinelMind event kaydı authoritative source olarak korunur.

---

## 3. Deterministic Risk Scoring

Detection engine finding üzerinde deterministic risk skoru hesaplar.

Incident #31 için:

- Risk Score: `70`
- Severity: `high`

Risk score AI tarafından belirlenmez.

Risk hesabı SentinelMind deterministic scoring engine tarafından yapılır.

---

## 4. Incident Creation

Yüksek riskli event SentinelMind Incident Producer tarafından incident
adayına dönüştürülür.

Gerçek incident:

`f49d731e-c4c4-4778-84a6-d26a4df663bd`

Incident:

- source event: `31`
- risk score: `70`
- severity: `high`
- resource: `sentinelmind-soc-nsg`

---

## 5. PII Masking

Incident AI katmanına gönderilmeden önce gerekli PII masking uygulanır.

Ham event verisi audit amacıyla korunur.

AI çağrısına giden içerik maskelenmiş formdadır.

DB kaydında:

`pii_masked = true`

olarak doğrulanır.

---

## 6. RAG Context Retrieval

SentinelMind RAG katmanı güvenlik bulgusunu ilgili güvenlik kaynaklarıyla
zenginleştirir.

Kullanılan bilgi kaynakları:

- CIS Azure Foundations
- MITRE ATT&CK Enterprise
- KVKK context

CIS dokümanı lisans kısıtları nedeniyle repository içinde dağıtılmaz.

---

## 7. Azure OpenAI Analysis

Maskelenmiş incident ve RAG context Azure OpenAI GPT-4o deployment'ına
gönderilir.

Model structured output üretir.

Ana output alanları:

- title_tr
- summary_tr
- severity
- mitre_techniques
- affected_resources
- recommended_actions
- kvkk

---

## 8. Authoritative Binding

LLM output doğrudan final output olarak kabul edilmez.

Trusted application layer aşağıdaki alanları yeniden bind eder:

- incident_id
- severity
- generated_at
- source MITRE IDs

Incident #31 source MITRE listesi:

- T1199
- T1048
- T1499
- T1498
- T1046

Model daha önce ek bir MITRE technique önermiştir.

Authoritative binding sonrası final AI output yalnızca source event içindeki
MITRE listesiyle korunmuştur.

---

## 9. AI Analysis Persistence

Final structured AI analysis PostgreSQL `ai_analyses` tablosuna yazılır.

Gerçek incident #31 analysis kaydı:

- incident ile eşleşir
- `pii_masked=true`
- structured payload içerir

Analysis FastAPI üzerinden geri okunabilir.

Endpointler:

- `GET /ai-analyses`
- `GET /incidents/{incident_id}/analysis`

---

## 10. Recommended Action

AI analysis gerçek senaryoda:

`close_nsg_rule`

action'ını önerir.

AI önerisi doğrudan Azure'a gönderilmez.

---

## 11. Trusted AI Action Bridge

Trusted AI Action Bridge öneriyi authoritative Prowler event ile doğrular.

Doğrulanan değerler:

- resource ID
- resource group
- NSG name
- rule name
- direction
- protocol
- source
- destination port

Incident #31 için normalize edilen remediation hedefi:

- resource group: `sentinelmind-rg`
- NSG: `sentinelmind-soc-nsg`
- rule: `DEMO-Insecure-SSH-Any`

Bridge yalnızca doğrulama başarılıysa action kaydı oluşturur.

Action ilk olarak:

`pending`

durumunda kaydedilir.

---

## 12. Human-in-the-Loop

Pending action SentinelMind Web Panel üzerinde gösterilir.

Kullanıcı:

- Approve
- Reject

kararı verebilir.

Gerçek demo senaryosunda action Approve edilmiştir.

DB sonucu:

- status: `approved`
- approved_by: `sentinelmind-web-ui`
- executed_at: `NULL`

Bu aşamada Azure üzerinde henüz değişiklik yapılmamıştır.

---

## 13. Dry-Run

Remediation executor önce dry-run modunda çalıştırılır.

Dry-run gerçek NSG rule'u bulur ve doğrular:

- Allow
- Inbound
- Tcp
- Source `*`
- Port `22`
- Priority `100`

Dry-run hiçbir Azure kaynağını değiştirmez.

---

## 14. Real Remediation

İnsan onayı sonrası remediation executor gerçek execution modunda çalışır.

Azure NSG rule:

`DEMO-Insecure-SSH-Any`

silinir.

Azure CLI verification sonrası rule artık bulunamaz.

---

## 15. Audit Result

PostgreSQL action kaydı güncellenir.

Final state:

- status: `executed`
- executed_at: populated
- result.outcome: `rule_deleted`

Bu sayede remediation işleminin audit trail'i korunur.

---

## 16. Demo Environment Reset

Demo ortamının yeniden kullanılabilir kalması için silinen NSG rule
Bicep ile yeniden oluşturulur.

Reset deployment:

`Succeeded`

Rule tekrar:

- Allow
- Inbound
- Tcp
- Source `*`
- Port `22`
- Priority `100`

durumuna döner.

---

# Final Security Story

SentinelMind demo sırasında şu güvenlik zincirini gösterir:

Prowler
→ Event
→ Deterministic Risk Scoring
→ Incident
→ PII Masking
→ RAG
→ Azure OpenAI
→ Structured AI Analysis
→ Authoritative Binding
→ PostgreSQL
→ Trusted AI Action Bridge
→ Pending Action
→ Human Approval
→ Dry-Run
→ Azure Remediation
→ Audit

---

# Ana Mesaj

SentinelMind mimarisinde:

**AI analyzes and recommends.**

**Trusted application logic validates.**

**Humans approve.**

**Deterministic executors remediate.**

AI doğrudan Azure üzerinde işlem yapmaz.

---

# Demo'da Gösterilecek Ana Ekranlar

1. Azure NSG insecure rule
2. Prowler finding
3. Incident + risk score
4. AI structured analysis
5. Authoritative MITRE listesi
6. FastAPI analysis read-back
7. Pending action
8. HITL Web Panel
9. Approved action
10. Dry-run output
11. Azure rule deletion
12. PostgreSQL executed audit record
13. Bicep reset sonucu

---

# Opsiyonel İkinci Senaryo

Wazuh Windows Event ID 4625 brute-force correlation ikinci demo senaryosu
olarak kullanılabilir.

Ancak ana final demo Prowler → Azure remediation zinciridir.

Wazuh senaryosu ana demo başarısını riske atmamak için opsiyonel tutulur.