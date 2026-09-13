# SentinelMind AI Safety & Trust Boundaries

## 1. Temel Prensip

SentinelMind mimarisinde Large Language Model güvenlik kararlarının tek
otoritesi değildir.

AI katmanı:

- analiz üretir
- açıklama üretir
- öneri üretir

Ancak kritik güvenlik kararları trusted application layer tarafından
doğrulanır.

Ana prensip:

**AI recommends, trusted systems validate, humans approve.**

---

## 2. Authoritative Fields

Aşağıdaki alanlar LLM tarafından serbestçe belirlenmez:

- incident_id
- severity
- generated_at
- source MITRE IDs mevcutsa mitre_techniques

Bu alanlar trusted incident ve source event verisinden final output üzerine
yeniden bind edilir.

---

## 3. MITRE Safety

Source event içinde güvenilir MITRE Technique ID'leri varsa modelin ürettiği
MITRE listesi kullanılmaz.

Final output yalnızca authoritative source mapping'i korur.

Source MITRE bulunmuyorsa RAG / LLM enrichment yapılabilir.

Bu durumda üretilen mapping authoritative ground truth değil,
AI-assisted enrichment olarak değerlendirilir.

---

## 4. PII Masking

Ham event verisi audit ve forensic amaçlarla `events.raw` içinde korunabilir.

Ancak AI çağrısından hemen önce PII masking uygulanır.

Maskelenebilen örnek değerler:

- IP address
- username
- e-mail
- TCKN benzeri identifier değerleri

AI analysis DB kaydında:

`pii_masked = true`

bilgisi tutulur.

---

## 5. Placeholder Resolution

LLM tarafından kullanılan maskeli değerler trusted application layer içinde
gerçek değerlere çözülür.

Sadece önceden oluşturulmuş ve mapping içinde bulunan placeholder'lar kabul
edilir.

Bilinmeyen placeholder örneği:

`[IP_999]`

fail-closed davranışı üretir.

Bu değer remediation katmanına geçirilmez.

---

## 6. Closed Action Types

AI yalnızca önceden tanımlanmış action type değerlerini üretebilir:

- block_ip
- disable_user
- isolate_vm
- close_nsg_rule
- revoke_storage_key
- none

Bu liste dışında bir action schema validation sırasında reddedilir.

---

## 7. Trusted AI Action Bridge

AI recommendation doğrudan Azure remediation executor'a gönderilmez.

Örnek `close_nsg_rule` akışı:

AI recommendation
→ Trusted AI Action Bridge
→ authoritative Prowler event validation
→ normalized Azure parameters
→ pending action
→ human approval
→ remediation executor
→ Azure
→ PostgreSQL audit

Bridge aşağıdaki değerleri source event ile çapraz kontrol eder:

- resource ID
- NSG name
- rule name
- access direction
- protocol
- source
- destination port

---

## 8. Human-in-the-Loop

Action ilk olarak:

`pending`

durumunda oluşturulur.

İnsan kullanıcı:

- Approve
- Reject

kararı verir.

Approve kararı remediation'ı doğrudan LLM tarafından başlatmaz.

Executor yalnızca onaylanmış action üzerinde çalışır.

Bu yapı destructive AI autonomy riskini azaltır.

---

## 9. Dry-Run

Gerçek remediation öncesinde dry-run desteği kullanılır.

Dry-run:

- hedef kaynağın varlığını doğrular
- uygulanacak işlemi gösterir
- gerçek Azure değişikliği yapmaz

Gerçek execution ayrı ve açık bir adım olarak çalıştırılır.

---

## 10. Prompt Injection

Incident ve event içerikleri güvenilmeyen input olarak değerlendirilir.

Prompt içinde modelden:

- source security data içindeki talimatları izlememesi
- closed schema dışına çıkmaması
- deterministic risk skorunu değiştirmemesi
- remediation işlemini kendi başına yürütmemesi

istenir.

Prompt guard testleri ve gerçek Azure adversarial model testi uygulanmıştır.

---

## 11. Structured Output

AI response serbest-form text yerine Pydantic tabanlı strict structured
schema ile doğrulanır.

Schema:

- unknown fields reddeder
- action type değerlerini sınırlar
- gerekli action parametrelerini doğrular
- invalid model output'un application layer'a geçmesini engeller

---

## 12. Auditability

Aşağıdaki aşamalar PostgreSQL üzerinde takip edilebilir:

- incident
- AI analysis
- recommended action
- human approval
- execution
- execution result

Bu sayede AI önerisi ile gerçek remediation işlemi arasında denetlenebilir
bir kayıt zinciri oluşur.

---

## 13. Gerçek E2E Güvenlik Doğrulaması

Gerçek incident #31 üzerinde:

- source MITRE mapping korunmuştur
- LLM'in eklediği source dışı MITRE technique final output'a alınmamıştır
- AI analysis DB'ye yazılmıştır
- recommendation authoritative Prowler event ile doğrulanmıştır
- action pending oluşturulmuştur
- insan tarafından approve edilmiştir
- remediation önce dry-run ile doğrulanmıştır
- Azure NSG rule gerçek execution ile silinmiştir
- sonuç PostgreSQL audit kaydına yazılmıştır

Bu senaryo SentinelMind'in AI güvenlik kontrol zincirinin uçtan uca
çalıştığını doğrulamaktadır.

---

## 14. Mevcut Sınırlar

Contract birden fazla action type tanımlar.

Ancak gerçek Azure remediation executor ile uçtan uca doğrulanmış action:

`close_nsg_rule`

Diğer action type değerleri schema seviyesinde desteklenmekle birlikte
production remediation olarak doğrulanmış gibi sunulmamalıdır.

Teams entegrasyonu Microsoft 365 erişim koşulları nedeniyle optional
integration olarak tutulmaktadır.

Ana MVP Human-in-the-Loop yolu SentinelMind Web Panel üzerinden çalışır.