# SentinelMind Final Evidence Checklist

Bu doküman final demo, video ve teslim sırasında kullanılacak teknik kanıtların kontrol listesidir.

Amaç:
- hangi iddianın hangi kanıtla desteklendiğini netleştirmek
- canlı demo başarısız olsa bile yedek kanıt bulundurmak
- sunumda yalnızca gerçekten doğrulanmış sonuçları göstermek

---

## 1. Prowler Finding — Incident #31

Gösterilecek kanıt:

- Prowler finding / event #31
- Resource: `sentinelmind-soc-nsg`
- Finding: internet üzerinden SSH / TCP 22 erişimi
- Source event authoritative record

Beklenen anlatım:

> Prowler, Azure NSG üzerinde internetten SSH erişimine izin veren gerçek bir cloud security finding üretti.

Durum:

- [ ] Screenshot hazır
- [ ] Event çıktısı hazır

---

## 2. Deterministic Risk Score

Gösterilecek değerler:

- Incident ID: `f49d731e-c4c4-4778-84a6-d26a4df663bd`
- Event ID: `31`
- Risk Score: `70`
- Severity: `high`

Beklenen anlatım:

> Risk score LLM tarafından üretilmez. SentinelMind deterministic scoring engine tarafından hesaplanır.

Durum:

- [ ] DB / incident çıktısı hazır
- [ ] Screenshot hazır

---

## 3. Authoritative MITRE

Source MITRE listesi:

- T1199
- T1048
- T1499
- T1498
- T1046

Gösterilecek kanıt:

- source incident MITRE listesi
- final AI analysis MITRE listesi

Beklenen anlatım:

> Source MITRE ID'leri mevcutsa LLM bu alanı değiştiremez. Final output authoritative source mapping'i korur.

Önemli:

Model daha önce source dışında `T1021.004` önermişti.
Authoritative binding sonrası final output'a alınmadı.

Durum:

- [ ] Source MITRE kanıtı hazır
- [ ] Final AI MITRE kanıtı hazır

---

## 4. PII Masking

Gösterilecek kanıt:

- AI analysis DB kaydı
- `pii_masked = true`

Beklenen anlatım:

> Ham event audit amacıyla korunabilir ancak AI çağrısından önce PII masking uygulanır.

Durum:

- [ ] DB çıktısı hazır
- [ ] Screenshot hazır

---

## 5. Azure OpenAI Structured Analysis

Gösterilecek alanlar:

- title_tr
- summary_tr
- severity
- mitre_techniques
- affected_resources
- recommended_actions
- kvkk

Teknik detay:

- incident_id
- schema_version
- generated_at

Beklenen anlatım:

> LLM serbest-form çıktı yerine strict structured schema ile çalışır.

Durum:

- [ ] JSON output hazır
- [ ] Screenshot hazır

---

## 6. ai_analyses PostgreSQL Record

Gösterilecek kanıt:

- incident #31 ile eşleşen gerçek `ai_analyses` kaydı
- `pii_masked=true`
- structured payload

Beklenen anlatım:

> AI analysis yalnızca model cevabı olarak kalmaz; audit edilebilir şekilde PostgreSQL'e yazılır.

Durum:

- [ ] SQL read-back hazır
- [ ] Screenshot hazır

---

## 7. FastAPI Read-Back

Endpointler:

- `GET /ai-analyses`
- `GET /incidents/{incident_id}/analysis`

Gösterilecek kanıt:

- incident #31 analysis response

Beklenen anlatım:

> AI analysis API üzerinden tekrar okunabilir ve platform katmanında kullanılabilir.

Durum:

- [ ] API response hazır
- [ ] Screenshot hazır

---

## 8. Trusted AI Action Bridge

Gerçek öneri:

`close_nsg_rule`

Authoritative değerler:

- Resource Group: `sentinelmind-rg`
- NSG: `sentinelmind-soc-nsg`
- Rule: `DEMO-Insecure-SSH-Any`
- Direction: `Inbound`
- Protocol: `Tcp`
- Source: `*`
- Destination Port: `22`

Beklenen anlatım:

> AI recommendation doğrudan Azure executor'a gönderilmez. Trusted application layer öneriyi authoritative Prowler event ile çapraz doğrular.

Durum:

- [ ] Bridge output hazır
- [ ] Screenshot hazır

---

## 9. Pending Action

Gösterilecek kanıt:

- action record
- status: `pending`

Beklenen anlatım:

> AI önerisi ilk olarak yalnızca pending action oluşturur.

Durum:

- [ ] DB çıktısı hazır
- [ ] Screenshot hazır

---

## 10. Human-in-the-Loop Approval

Gösterilecek kanıt:

- SentinelMind Web Panel
- Approve / Reject ekranı

Approve sonrası DB:

- status: `approved`
- approved_by: `sentinelmind-web-ui`
- executed_at: `NULL`

Beklenen anlatım:

> İnsan onayı remediation'ı otomatik olarak çalıştırmaz. Approval ile execution ayrıdır.

Durum:

- [ ] Web Panel screenshot hazır
- [ ] Approved DB state hazır

---

## 11. Dry-Run

Dry-run doğrulaması:

- Rule exists
- Allow
- Inbound
- Tcp
- Source `*`
- Port `22`
- Priority `100`

Beklenen anlatım:

> Gerçek cloud değişikliğinden önce executor dry-run ile hedefi doğrular ve hiçbir değişiklik yapmaz.

Durum:

- [ ] Dry-run terminal çıktısı hazır
- [ ] Screenshot hazır

---

## 12. Real Azure Remediation

Silinen rule:

`DEMO-Insecure-SSH-Any`

Gösterilecek kanıt:

- execute çıktısı
- Azure CLI verification
- `NotFound`

Beklenen anlatım:

> İnsan onayı ve trusted validation sonrasında Azure NSG rule gerçek ortamdan kaldırıldı.

Durum:

- [ ] Execute çıktısı hazır
- [ ] NotFound verification hazır

---

## 13. PostgreSQL Audit Result

Final action state:

- status: `executed`
- executed_at: populated
- result.outcome: `rule_deleted`

Beklenen anlatım:

> Yapılan remediation işlemi PostgreSQL audit trail içinde saklanır.

Durum:

- [ ] Final DB record hazır
- [ ] Screenshot hazır

---

## 14. Demo Reset

Gösterilecek kanıt:

- `reset-demo-nsg.bicep`
- deployment state: `Succeeded`

Reset sonrası:

- Allow
- Inbound
- Tcp
- Source `*`
- Port `22`
- Priority `100`

Beklenen anlatım:

> Demo ortamı remediation sonrasında Bicep ile tekrar başlangıç durumuna alınabilir.

Durum:

- [ ] Reset deployment screenshot hazır
- [ ] Rule restored verification hazır

---

# Detection & Evaluation Evidence

## 15. Baseline Metrics

Dataset:

- 55 FAIL finding
- Positive: 16
- Negative: 39

Threshold:

`60`

Result:

- TP: 9
- FP: 0
- FN: 7
- TN: 39
- Precision: 1.000
- Recall: 0.562
- F1: 0.720

Beklenen anlatım:

> Baseline yaklaşım yüksek precision üretirken recall tarafında bazı önemli finding'leri kaçırdı.

Durum:

- [ ] Metrics output hazır
- [ ] Table / screenshot hazır

---

## 16. Threshold Analysis

Öne çıkan sonuçlar:

- Threshold 40 → Recall 1.000, Precision 0.516
- Threshold 45 → Recall 1.000, Precision 0.593
- Threshold 50 → Recall 0.938, Precision 0.600
- Threshold 55 → Recall 0.625, Precision 0.833
- Threshold 60 → Recall 0.562, Precision 1.000

Beklenen anlatım:

> Threshold seçimi precision-recall trade-off oluşturur.

Durum:

- [ ] Threshold table hazır
- [ ] Screenshot / chart hazır

---

## 17. Experimental Scoring V2 — Tuning Result

Frozen version:

`1.0`

Threshold:

`60`

Tuning-set result:

- TP: 16
- FP: 0
- FN: 0
- TN: 39
- Precision: 1.000
- Recall: 1.000
- F1: 1.000

Önemli:

Bu bağımsız validation değildir.

Beklenen anlatım:

> V2 tuning-set sonucu exploratory olarak tutulur; genel performans kanıtı olarak kullanılmaz.

Durum:

- [ ] Tuning output hazır
- [ ] Limitation metni hazır

---

## 18. Independent Controlled Holdout

Azure Resource Group:

`sentinelmind-holdout-rg`

Tuning FAIL unique check sayısı:

`42`

Holdout FAIL checks:

- network_http_internet_access_restricted
- network_rdp_internet_access_restricted
- network_udp_internet_access_restricted
- network_subnet_nsg_associated

Overlap:

`[]`

Prowler scan:

- FAIL: 4
- PASS: 1

Human labels:

- Positive: 4
- Negative: 0

Frozen V2 result:

- TP: 4
- FP: 0
- FN: 0
- TN: 0
- Precision: 1.000
- Recall: 1.000
- F1: 1.000

Correct interpretation:

> Frozen Scoring V2 v1.0 correctly prioritized 4/4 unseen positive findings in a controlled independent Azure holdout run.

Important limitation:

> The holdout is positive-only and therefore does not independently measure false-positive behavior on unseen negative findings.

Durum:

- [ ] Prowler scan screenshot hazır
- [ ] OVERLAP `[]` kanıtı hazır
- [ ] Holdout evaluation output hazır
- [ ] Limitation açıkça gösteriliyor

---

# Detection Engineering Evidence

## 19. Sigma Rules

Hazırlanan senaryolar:

- Windows Event ID 4625 failed logon
- RDP failed logon
- RDP successful logon telemetry

Durum:

- [ ] Sigma rule dosyaları hazır
- [ ] Unit test kanıtı hazır

---

## 20. Failed Logon Correlation

Davranış:

- same username
- same source IP
- minimum 5 failed logons
- 5-minute window

Durum:

- [ ] Correlation test output hazır

---

## 21. Wazuh Adapter

Tamamlanan:

- Wazuh nested event normalization
- Event ID 4625 adapter
- brute-force validator

Sınırlama:

Gerçek Wazuh export validator üzerinden henüz production validation olarak tamamlanmamışsa finalde optional olarak belirtilmelidir.

Durum:

- [ ] Adapter test kanıtı hazır
- [ ] Real Wazuh status doğru ifade edilmiş

---

# Quality & Delivery Evidence

## 22. Local Final Regression

Final merged-main regression:

`55 passed`

Durum:

- [ ] Terminal screenshot hazır

---

## 23. GitHub Actions CI

Workflow:

`SentinelMind CI`

Doğrulanan:

- Detection/Eval merge success
- Final docs merge success
- Holdout infrastructure merge success
- Holdout results PR checks success

Durum:

- [ ] GitHub Actions screenshot hazır

---

## 24. Pull Request Evidence

Önemli PR'lar:

- PR #9 — RAG + AI
- PR #10 — AI Analysis API
- PR #13 — HITL Web Panel
- PR #14 — Trusted AI Action Bridge
- PR #15 — Detection & Evaluation
- PR #16 — Final Detection & AI Docs
- PR #19 — Holdout Infrastructure
- PR #22 — Holdout Validation Results

Durum:

- [ ] Merge / approval ekranları hazır

---

# Final Video Minimum Evidence Set

Video çok uzun olmayacaksa minimum şu kanıtlar gösterilmelidir:

1. SentinelMind architecture
2. Prowler incident #31
3. Risk Score 70
4. Structured AI analysis
5. Authoritative MITRE
6. Pending action
7. HITL Web Panel
8. Dry-run
9. Real NSG remediation
10. Audit result
11. Detection baseline metrics
12. Independent holdout 4/4 result
13. CI + 55 passed

---

# Final Claim Rules

Final sunum/video sırasında:

Söylenebilir:

- Real Azure E2E completed
- Real AI analysis persisted and read back
- Human-approved NSG remediation executed
- 55 local tests passed
- GitHub CI passing
- Controlled independent holdout detected 4/4 unseen positive findings

Söylenmemeli:

- "All remediation actions are production validated"
- "SentinelMind has 100% general detection accuracy"
- "Holdout proves zero false positives"
- "Wazuh second E2E is complete" unless real validation is separately completed
- "AI autonomously remediates Azure"

Ana mesaj:

**AI analyzes and recommends. Trusted systems validate. Humans approve. Deterministic executors remediate.**