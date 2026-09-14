# SentinelMind Platform & Cloud Final Status

## Genel Durum

SentinelMind Platform & Cloud katmanı, projenin ana MVP akışını gerçek Azure ve PostgreSQL ortamı üzerinde çalıştıracak seviyeye getirilmiştir.

Ana doğrulanmış akış:

Prowler -> PostgreSQL events -> Incident Producer -> AI Analysis -> Trusted AI Action Bridge -> Pending Action -> Human-in-the-Loop Approval -> Azure Remediation -> PostgreSQL Audit

Platform katmanının amacı AI modeline doğrudan bulut kaynağı değiştirme yetkisi vermek değil; detection, analysis, approval ve remediation aşamalarını kontrollü ve denetlenebilir bir pipeline içinde birbirine bağlamaktır.

---

## 1. Azure Altyapısı

Azure demo altyapısı Infrastructure as Code yaklaşımıyla Bicep kullanılarak oluşturulmuştur.

İlgili dosyalar:

- `infra/main.bicep`
- `infra/modules/compute.bicep`
- `infra/cloud-init.yaml`
- `infra/reset-demo-nsg.bicep`

Demo ortamında kullanılan temel kaynaklardan biri:

- Resource Group: `sentinelmind-rg`
- NSG: `sentinelmind-soc-nsg`
- Demo rule: `DEMO-Insecure-SSH-Any`

Demo güvenlik kuralı bilinçli olarak TCP/22 erişimini internetten açık bırakacak şekilde oluşturulmuştur. Bu kural gerçek remediation senaryosunda Prowler tarafından tespit edilmekte ve SentinelMind remediation pipeline'ı ile kaldırılabilmektedir.

`reset-demo-nsg.bicep` dosyası demo sonrasında güvenlik kuralını tekrar oluşturmak için kullanılmaktadır.

Bu sayede aynı senaryo tekrar üretilebilir şekilde gösterilebilmektedir.

---

## 2. Prowler Entegrasyonu

Prowler CSPM bulguları normalize edilerek PostgreSQL `events` tablosuna alınmaktadır.

İlgili dosya:

- `collector/prowler_ingest.py`

İngest katmanı idempotent çalışacak şekilde tasarlanmıştır.

Gerçek demo verisinde Prowler tarafından bulunan internetten SSH erişimi açık NSG bulgusu ana E2E senaryosunda kullanılmıştır.

Ana event:

- Source: `prowler`
- Rule ID: `network_ssh_internet_access_restricted`
- Check status: `FAIL`
- Resource: `sentinelmind-soc-nsg`
- Security rule: `DEMO-Insecure-SSH-Any`
- Direction: `Inbound`
- Access: `Allow`
- Protocol: `Tcp`
- Source: `*`
- Destination port: `22`

Prowler event içindeki raw veri korunmaktadır.

---

## 3. Wazuh Entegrasyonu

Wazuh tarafı ayrı bir SIEM/XDR veri kaynağı olarak entegre edilmiştir.

İlgili dosya:

- `collector/wazuh_ingest.py`

Wazuh Manager / Indexer / Dashboard laboratuvar ortamında çalıştırılmış ve Windows endpoint üzerinden gerçek authentication failure eventleri üretilmiştir.

Wazuh eventlerinin PostgreSQL'e aktarımı idempotent şekilde doğrulanmıştır.

Wazuh, ana Azure remediation demosunun zorunlu bir bağımlılığı değildir. İkinci detection senaryosu ve SIEM entegrasyonu olarak kullanılmaktadır.

---

## 4. PostgreSQL Veri Katmanı

SentinelMind'in ortak veri katmanı PostgreSQL'dir.

Ana tablolar:

- `events`
- `incidents`
- `ai_analyses`
- `actions`

Schema:

- `docs/schema.sql`

Contract:

- `docs/contracts.md`

Sorumluluk ayrımı:

- Platform & Cloud: `events`, `actions`
- Detection & AI: `incidents`, `ai_analyses`

Raw event verisi DB içinde korunur. PII masking işlemi raw event üzerinde değil, AI'a gönderimden hemen önce gerçekleştirilir.

---

## 5. Deterministic Filtering ve Incident Producer

Platform ile Detection katmanları arasındaki incident üretim pipeline'ı repository içinde bulunmaktadır.

İlgili dosyalar:

- `engine/filter_engine.py`
- `engine/incident_producer.py`

Risk değerlendirmesi deterministik kurallarla yapılmaktadır.

AI modeli risk skorunu üretmez.

Incident Producer Prowler eventlerini resource_id bazlı gruplayarak incident adaylarına dönüştürmektedir. Resource bilgisi bulunmayan eventler bağımsız olarak ele alınmaktadır.

MVP davranışında incident threshold ve severity davranışı mevcut contract kapsamında korunmaktadır.

---

## 6. FastAPI Katmanı

SentinelMind'in API katmanı:

- `api/main.py`

API üzerinden incident, action ve AI analysis verilerine erişim sağlanmaktadır.

AI analysis read endpointleri:

- `GET /ai-analyses`
- `GET /incidents/{incident_id}/analysis`

Gerçek Azure OpenAI analizi PostgreSQL'e yazıldıktan sonra bu endpointler üzerinden tekrar okunarak doğrulanmıştır.

---

## 7. Trusted AI Action Bridge

İlgili dosya:

- `engine/ai_action_bridge.py`

Bu katman SentinelMind'in en kritik güvenlik sınırlarından biridir.

AI tarafından üretilen remediation önerisi doğrudan executor'a gönderilmez.

Bridge aşağıdaki kontrolleri gerçekleştirir:

1. AI analysis kaydının incident ile eşleşmesini doğrular.
2. `pii_masked=True` şartını kontrol eder.
3. Desteklenen action tipini kontrol eder.
4. AI tarafından verilen `resource_id` bilgisini authoritative Prowler event ile karşılaştırır.
5. AI tarafından verilen `rule_name` bilgisini authoritative event ile karşılaştırır.
6. Azure NSG resource ID bilgisini parse eder.
7. Güvenlik kuralının gerçekten:
   - Allow
   - Inbound
   - TCP veya wildcard protocol
   - destination port 22
   - public source
   koşullarını karşıladığını doğrular.
8. Action kaydını yalnızca `pending` durumda oluşturur.

Bridge aynı AI analysis için tekrar çalıştırıldığında duplicate action üretmez.

---

## 8. Human-in-the-Loop Web Interface

İlgili dosya:

- `hitl/web_app.py`

SentinelMind remediation akışında insan onayı zorunludur.

Web arayüzü pending action kayıtlarını gösterir ve kullanıcıya:

- Approve
- Reject

seçenekleri sunar.

Approve işlemi remediation'ı otomatik çalıştırmaz.

Onay sonrası action:

- `status=approved`
- `approved_by=sentinelmind-web-ui`
- `executed_at=NULL`

durumunda kalır.

Bu davranış AI önerisi ile gerçek bulut değişikliği arasında insan kontrolünün korunmasını sağlar.

---

## 9. Azure Remediation Executor

İlgili dosya:

- `actions/remediate.py`

Executor yalnızca approved action kayıtlarını işler.

Ana desteklenen gerçek remediation yolu:

- `close_nsg_rule`

Varsayılan davranış dry-run'dır.

Dry-run sırasında:

- Azure kaynağı kontrol edilir.
- Security rule doğrulanır.
- Hiçbir Azure değişikliği yapılmaz.

Gerçek değişiklik yalnızca açık şekilde `--execute` kullanıldığında yapılır.

---

## 10. Gerçek Azure Remediation Kanıtı

Ana E2E senaryosunda:

1. Prowler internetten açık SSH rule bulgusunu tespit etti.
2. Incident oluşturuldu.
3. Azure OpenAI analiz üretti.
4. AI `close_nsg_rule` önerdi.
5. Trusted AI Action Bridge authoritative event ile öneriyi doğruladı.
6. Pending action oluşturuldu.
7. HITL Web üzerinden insan Approve verdi.
8. Remediation executor önce dry-run çalıştırıldı.
9. Daha sonra gerçek execute gerçekleştirildi.
10. Azure NSG security rule silindi.
11. Azure CLI ile rule tekrar sorgulandığında NotFound sonucu alındı.
12. PostgreSQL action kaydı `executed` olarak güncellendi.
13. Audit result içine remediation sonucu yazıldı.
14. Bicep reset ile demo rule tekrar oluşturuldu.

Bu akış ana SentinelMind MVP'sinin gerçek cloud remediation kanıtıdır.

---

## 11. Audit Trail

Remediation sonrasında action kaydı silinmez.

DB audit kaydı korunur.

Örnek result alanı aşağıdaki bilgileri içerir:

- operation
- resource_group
- nsg_name
- rule_name
- outcome

Bu sayede remediation işlemi sonradan incelenebilir.

---

## 12. Teams Entegrasyonu

Teams entegrasyonu için aşağıdaki backend bileşenleri repository içinde bulunmaktadır:

- `teams/adaptive_card.py`
- `teams/callback_api.py`

Adaptive Card ve callback altyapısı geliştirilmiştir.

Ancak gerçek Microsoft Teams tenant-side workflow provisioning işlemi Microsoft 365 organizational tenant erişimine bağlıdır.

Bu nedenle Teams entegrasyonu final MVP'nin zorunlu bileşeni değildir.

Final MVP Human-in-the-Loop akışı bağımsız web interface üzerinden çalışmaktadır.

Teams entegrasyonu opsiyonel Microsoft 365 entegrasyonu olarak konumlandırılmıştır.

---

## 13. CI ve Automated Testing

GitHub Actions CI pipeline:

- `.github/workflows/ci.yml`

CI aşağıdaki kontrolleri gerçekleştirir:

- Python 3.12 ortamı
- dependency installation
- kritik modül compile kontrolleri
- deterministik pytest regression suite

Lokal full regression:

- 32 tests passed

CI regression:

- 31 tests passed
- 1 integration test deselected

RAG pipeline testi lokal ChromaDB indexine ihtiyaç duyduğu için integration test olarak ayrılmıştır.

Bu sayede GitHub CI dış credential veya lokal index gerektirmeden deterministik çalışmaktadır.

---

## 14. Platform & Cloud MVP Durumu

Tamamlanan ana bileşenler:

- Azure Bicep infrastructure
- Prowler ingest
- Wazuh ingest
- PostgreSQL data layer
- Incident integration
- FastAPI
- AI Analysis Read API
- Trusted AI Action Bridge
- HITL Web approval
- Azure remediation dry-run
- Gerçek Azure NSG remediation
- PostgreSQL remediation audit
- Demo environment reset
- Automated bridge security tests
- GitHub Actions CI

Opsiyonel / final geliştirme alanları:

- Microsoft Teams tenant-side real workflow
- Ek remediation action executor'ları
- Wazuh tabanlı ikinci AI E2E
- Production authentication / authorization
- Production secrets management
- Production deployment hardening

---

## Final Değerlendirme

Platform & Cloud katmanı ana SentinelMind MVP senaryosu için tamamlanmış ve gerçek Azure üzerinde uçtan uca doğrulanmıştır.

Sistem otomatik remediation yapan kontrolsüz bir AI ajanı değildir.

Güvenlik modeli:

Detection -> Deterministic Risk -> AI Decision Support -> Trusted Validation -> Human Approval -> Controlled Remediation -> Audit

şeklindedir.

Bu yapı AI çıktısını karar destek katmanı olarak kullanırken, authoritative güvenlik verisini, insan onayını ve denetlenebilir remediation sürecini korumaktadır.