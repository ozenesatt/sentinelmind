# SentinelMind Detection & Evaluation Metrics

## 1. Amaç

Bu doküman SentinelMind Detection & AI katmanında kullanılan
deterministik risk skorlama yaklaşımının değerlendirme sonuçlarını özetler.

Değerlendirme; manuel olarak incelenmiş Prowler FAIL bulguları üzerinde,
yüksek öncelikli güvenlik bulgularının doğru biçimde ayrıştırılmasını ölçer.

---

## 2. Evaluation Dataset

İlk evaluation seti gerçek Prowler OCSF çıktısından oluşturulmuştur.

Toplam FAIL bulgusu:

- 55 kayıt

Manuel etiket dağılımı:

- Positive / High Priority: 16
- Negative / Not High Priority: 39

Etiketleme sırasında model prediction veya risk score kullanıcıya
gösterilmemiştir.

Bu veri seti "manually reviewed labeled evaluation set" olarak tanımlanır.

---

## 3. Baseline Detection

Baseline sistem deterministic `score_finding()` motorunu kullanır.

Incident candidate threshold:

`risk_score >= 60`

Sonuçlar:

| Metric | Value |
|---|---:|
| TP | 9 |
| FP | 0 |
| FN | 7 |
| TN | 39 |
| Precision | 1.000 |
| Recall | 0.562 |
| F1 Score | 0.720 |

### Yorum

Baseline yaklaşım false-positive üretmemiştir.

Bunun karşılığında bazı güvenlik açısından önemli bulgular threshold altında
kaldığı için recall sınırlı kalmıştır.

Bu sonuç SentinelMind'in ilk yaklaşımının yüksek precision odaklı olduğunu
göstermektedir.

---

## 4. Threshold Analysis

Farklı threshold değerleri aynı labeled dataset üzerinde değerlendirilmiştir.

| Threshold | TP | FP | FN | TN | Precision | Recall | F1 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 40 | 16 | 15 | 0 | 24 | 0.516 | 1.000 | 0.681 |
| 45 | 16 | 11 | 0 | 28 | 0.593 | 1.000 | 0.744 |
| 50 | 15 | 10 | 1 | 29 | 0.600 | 0.938 | 0.732 |
| 55 | 10 | 2 | 6 | 37 | 0.833 | 0.625 | 0.714 |
| 60 | 9 | 0 | 7 | 39 | 1.000 | 0.562 | 0.720 |

Threshold 60 ana baseline olarak korunmuştur.

---

## 5. Experimental Scoring V2

False-negative analizinden sonra deneysel Scoring V2 geliştirilmiştir.

V2 version:

`1.0`

Threshold:

`60`

Ek contextual bonus kategorileri:

- Key Vault security findings
- Network telemetry findings
- Storage private endpoint findings
- Secure transport findings

Tuning dataset sonucu:

| Metric | Value |
|---|---:|
| TP | 16 |
| FP | 0 |
| FN | 0 |
| TN | 39 |
| Precision | 1.000 |
| Recall | 1.000 |
| F1 Score | 1.000 |

## Önemli Sınırlama

Bu sonuç bağımsız holdout sonucu değildir.

Scoring V2 kuralları aynı evaluation datasetindeki false-negative analizinden
sonra geliştirildiği için bu değerler yalnızca:

**exploratory / tuning-set result**

olarak değerlendirilmelidir.

Bu nedenle SentinelMind final raporunda bu değerler bağımsız performans
kanıtı olarak sunulmaz.

---

## 6. Holdout Validation

Scoring V2 v1.0 holdout verisi görülmeden önce Git üzerinde freeze edilmiştir.

Ayrı bir Azure Resource Group kullanılmıştır:

`sentinelmind-holdout-rg`

Holdout scan yalnızca tuning setinde bulunmayan dört yeni network check üzerinde çalıştırılmıştır:

- `network_http_internet_access_restricted`
- `network_rdp_internet_access_restricted`
- `network_udp_internet_access_restricted`
- `network_subnet_nsg_associated`

Eski tuning FAIL check'leriyle otomatik overlap kontrolü:

`OVERLAP: []`

Prowler scan sonucu:

- FAIL: 4
- PASS: 1

Evaluation yalnızca FAIL finding'lerin önceliklendirilmesini ölçtüğü için holdout değerlendirmesine 4 FAIL finding dahil edilmiştir.

Human labeling sırasında V2 risk score ve prediction gösterilmemiştir.

Frozen V2 v1.0 sonucu:

| Metric | Value |
|---|---:|
| Holdout N | 4 |
| Positive | 4 |
| Negative | 0 |
| TP | 4 |
| FP | 0 |
| FN | 0 |
| TN | 0 |
| Precision | 1.000 |
| Recall | 1.000 |
| F1 Score | 1.000 |

Frozen V2, tuning sırasında görülmeyen dört high-priority finding'in 4/4'ünü yakalamıştır.

### Holdout Sınırlaması

Bu kontrollü holdout yalnızca positive örneklerden oluşmaktadır.

Bu nedenle sonuç, unseen positive finding'ler üzerindeki false-negative davranışı hakkında kanıt sağlar ancak unseen negative finding'ler olmadığı için false-positive davranışını bağımsız olarak ölçmez.

Sonuç şu şekilde yorumlanmalıdır:

**Controlled independent holdout validation — positive-only, N=4**

Bu sonuç genel sistem performansının %100 olduğu şeklinde yorumlanmamalıdır.
## 7. Sigma & Correlation Validation

Detection katmanında aşağıdaki senaryolar ayrıca test edilmiştir:

- Windows Event ID 4625 failed logon
- RDP failed logon
- RDP successful logon telemetry
- repeated failed logon correlation
- Wazuh failed logon normalization

Brute-force candidate davranışı:

- aynı kullanıcı
- aynı source IP
- en az 5 adet Event ID 4625
- 5 dakika zaman penceresi

Gerçek Wazuh event validation aracı hazırlanmıştır.

Gerçek Wazuh export ile validation henüz tamamlanmamıştır ve bu nedenle
synthetic test sonucu gerçek production validation olarak sunulmaz.

---

## 8. Sonuç

SentinelMind Detection katmanı:

- deterministic risk scoring kullanır
- ölçülebilir evaluation sağlar
- false-positive / false-negative sonuçlarını takip eder
- threshold trade-off analizine izin verir
- tuning ve holdout sonuçlarını birbirinden ayırır
- Sigma tabanlı detection senaryolarını test eder

Final değerlendirmede en güvenilir production baseline sonucu:

- Precision: 1.000
- Recall: 0.562
- F1: 0.720

Scoring V2 sonuçları ise independent holdout tamamlanana kadar experimental
olarak tutulur.