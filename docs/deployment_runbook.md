# SentinelMind Deployment and Operations Runbook

## Amaç

Bu doküman SentinelMind geliştirme ve demo ortamının Platform & Cloud bileşenlerini tekrar ayağa kaldırmak ve doğrulamak için operasyonel referanstır.

Bu belge production deployment guide değildir.

## 1. Gereksinimler

Temel geliştirme ortamı:

- Python 3.12
- PostgreSQL
- Azure CLI
- Git
- GitHub CLI
- Azure subscription
- Azure OpenAI deployment
- Prowler
- Wazuh laboratuvar ortamı - opsiyonel ikinci veri kaynağı

Python bağımlılıkları:

    python -m pip install -r requirements.txt

## 2. Repository

Ana branch:

    git checkout main
    git pull --ff-only

Çalışma ağacını kontrol etmek için:

    git status --short

## 3. PostgreSQL

SentinelMind aşağıdaki ana tabloları kullanır:

- events
- incidents
- ai_analyses
- actions

Schema:

- docs/schema.sql

Windows geliştirme ortamında PostgreSQL durum kontrolü:

    C:\PostgreSQL\pgsql\bin\pg_ctl.exe -D C:\PostgreSQL\data status

Başlatma:

    C:\PostgreSQL\pgsql\bin\pg_ctl.exe -D C:\PostgreSQL\data -l C:\PostgreSQL\log.txt start

Durdurma:

    C:\PostgreSQL\pgsql\bin\pg_ctl.exe -D C:\PostgreSQL\data stop -m fast

## 4. Python Environment ve Testler

Bağımlılıkları kurmak için:

    .\.venv\Scripts\python.exe -m pip install -r requirements.txt

Lokal full regression:

    .\.venv\Scripts\python.exe -m pytest -q

CI eşdeğeri deterministik regression:

    .\.venv\Scripts\python.exe -m pytest -q -m "not integration"

Lokal doğrulanmış sonuç:

- 32 passed

GitHub Actions CI sonucu:

- 31 passed
- 1 integration test deselected

## 5. Prowler Ingest

Collector:

- collector/prowler_ingest.py

Prowler çıktıları normalize edilerek PostgreSQL events tablosuna aktarılır.

Collector idempotent davranacak şekilde geliştirilmiştir.

Ana demo senaryosunda kullanılan bulgu internetten TCP/22 erişimine açık Azure NSG rule bulgusudur.

## 6. Wazuh Ingest

Collector:

- collector/wazuh_ingest.py

Wazuh ikinci güvenlik veri kaynağı olarak kullanılmaktadır.

Windows endpoint üzerinde gerçek authentication failure eventleri üretilmiş ve PostgreSQL ingest doğrulanmıştır.

Wazuh ana Azure remediation E2E demosunun zorunlu bağımlılığı değildir.

## 7. Incident Producer

Dosya:

- engine/incident_producer.py

Incident üretiminden önce Prowler eventlerinin PostgreSQL içinde mevcut olduğu doğrulanmalıdır.

Risk ve correlation davranışı deterministiktir.

AI modeli risk skoru üretmez.

## 8. API

Dosya:

- api/main.py

Development API örneği:

    .\.venv\Scripts\python.exe -m uvicorn api.main:app --host 127.0.0.1 --port 8001

Önemli AI analysis endpointleri:

- GET /ai-analyses
- GET /incidents/{incident_id}/analysis

Gerçek AI analysis kaydı bu endpointler üzerinden okunarak doğrulanmıştır.
## 9. HITL Web

Dosya:

- hitl/web_app.py

Development ortamında:

    .\.venv\Scripts\python.exe -m uvicorn hitl.web_app:app --host 127.0.0.1 --port 8004

Arayüz pending action kayıtlarını gösterir.

Kullanıcı:

- Approve
- Reject

kararı verebilir.

Approve işlemi remediation'ı otomatik çalıştırmaz.

Development arayüzünde production authentication ve CSRF koruması bulunmadığı için public internete doğrudan açılmamalıdır.

## 10. Trusted AI Action Bridge

Dosya:

- engine/ai_action_bridge.py

Bridge AI önerisini doğrudan Azure executor'a aktarmaz.

Önce:

- incident eşleşmesi
- analysis eşleşmesi
- pii_masked=True
- authoritative Prowler event
- resource_id eşleşmesi
- rule_name eşleşmesi
- Azure NSG resource yapısı
- inbound Allow
- TCP veya wildcard protocol
- destination port 22
- public source

kontrollerini gerçekleştirir.

Başarılı doğrulama sonrasında yalnızca pending action oluşturabilir.

Aynı analysis için duplicate action oluşturmaz.

## 11. Human Approval

Action önce pending olarak oluşturulur.

HITL Web üzerinden Approve sonrasında beklenen durum:

- status=approved
- approved_by=sentinelmind-web-ui
- executed_at=NULL

Bu aşamada Azure değişikliği henüz gerçekleşmez.

## 12. Azure Remediation Executor

Dosya:

- actions/remediate.py

Ana desteklenen gerçek remediation yolu:

- close_nsg_rule

Önce dry-run çalıştırılmalıdır:

    .\.venv\Scripts\python.exe -m actions.remediate --action-id <ACTION_ID>

Gerçek execute yalnızca insan onayı sonrasında:

    .\.venv\Scripts\python.exe -m actions.remediate --action-id <ACTION_ID> --execute

ACTION_ID yerine PostgreSQL'deki gerçek action UUID kullanılmalıdır.

Pending action execute edilmemelidir.

## 13. Azure Validation

Azure oturum kontrolü:

    az account show

Ana demo rule kontrolü:

    az network nsg rule show --resource-group sentinelmind-rg --nsg-name sentinelmind-soc-nsg --name DEMO-Insecure-SSH-Any

Gerçek remediation sonrasında aynı sorgunun NotFound sonucu vermesi beklenir.

## 14. Demo Environment Reset

Dosya:

- infra/reset-demo-nsg.bicep

Önce validate:

    az deployment group validate --resource-group sentinelmind-rg --template-file .\infra\reset-demo-nsg.bicep

Sonra reset deployment:

    az deployment group create --resource-group sentinelmind-rg --template-file .\infra\reset-demo-nsg.bicep

Reset sonrasında demo NSG rule tekrar kontrol edilmelidir.

## 15. Audit Verification

Gerçek remediation sonrasında action kaydı silinmez.

Beklenen durum:

- status=executed
- executed_at dolu
- result alanında operation ve outcome bilgisi mevcut

Bu audit trail remediation'ın sonradan incelenebilmesini sağlar.

## 16. GitHub Actions CI

Workflow:

- .github/workflows/ci.yml

Pipeline:

- Python 3.12 ortamını hazırlar
- requirements.txt bağımlılıklarını kurar
- kritik modülleri compile eder
- deterministik pytest suite çalıştırır

RAG pipeline testi lokal ChromaDB indexine ihtiyaç duyduğu için integration testi olarak ayrılmıştır.

## 17. Güvenli Demo Sırası

Önerilen demo sırası:

1. PostgreSQL durumunu kontrol et.
2. Azure CLI login durumunu kontrol et.
3. Demo NSG rule mevcut mu kontrol et.
4. Prowler eventini doğrula.
5. Incident kaydını doğrula.
6. AI analysis kaydını doğrula.
7. Trusted AI Action Bridge dry-run çalıştır.
8. Pending action oluştur.
9. HITL Web üzerinden Approve ver.
10. Remediation dry-run çalıştır.
11. Azure security rule pre-check yap.
12. Remediation execute çalıştır.
13. Azure rule silindiğini doğrula.
14. PostgreSQL audit kaydını doğrula.
15. Bicep reset çalıştır.
16. Azure rule tekrar geldiğini doğrula.

## 18. Teams Durumu

Repository içinde:

- teams/adaptive_card.py
- teams/callback_api.py

dosyaları bulunmaktadır.

Teams backend ve callback entegrasyon katmanı geliştirilmiştir.

Gerçek tenant-side Microsoft Teams workflow provisioning Microsoft 365 organizational tenant erişimine bağlı olduğu için final MVP'nin zorunlu bileşeni değildir.

Ana HITL akışı bağımsız web interface üzerinden çalışmaktadır.

## 19. Güvenlik Notları

- AI doğrudan Azure değişikliği yapmaz.
- Human approval zorunludur.
- Dry-run varsayılan davranıştır.
- Raw event verisi DB içinde korunur.
- PII masking AI çağrısından önce yapılır.
- Trusted bridge AI önerisini authoritative event ile doğrular.
- Secrets repository içine commit edilmemelidir.
- Development HITL interface public internete açılmamalıdır.
- Production deployment ek authentication, authorization, secrets management ve hardening gerektirir.

## Sonuç

SentinelMind Platform & Cloud ana doğrulanmış workflow:

Prowler -> PostgreSQL -> Incident -> AI Analysis -> Trusted AI Action Bridge -> Human Approval -> Azure Remediation -> Audit -> Bicep Reset

şeklindedir.

Bu akış gerçek Azure demo ortamında doğrulanmıştır.