# SentinelMind Detection Evaluation

Bu klasör, SentinelMind deterministic detection/risk scoring motorunun
ölçülebilir değerlendirmesi için kullanılır.

## Dataset

Evaluation set, gerçek Prowler OCSF çıktısındaki FAIL bulgularından oluşturuldu.

- Toplam gerçek Prowler bulgusu: 71
- FAIL bulgusu: 55
- Manuel olarak incelenen eval kaydı: 55
- Positive label: 16
- Negative label: 39

Gerçek etiketli dataset `labeled_findings.json` içinde tutulur.
Bu dosya resource/subscription bilgileri içerebildiği için Git'e eklenmez.

## Baseline

Production baseline scorer:

- Threshold: 60
- TP: 9
- FP: 0
- FN: 7
- TN: 39
- Precision: 1.000
- Recall: 0.562
- F1: 0.720

Baseline sonucu, mevcut deterministic scoring motorunun manuel olarak
review edilmiş dataset üzerindeki performansıdır.

## Threshold Analysis

40, 45, 50, 55 ve 60 threshold değerleri karşılaştırıldı.

En yüksek F1 değeri threshold 45'te görülmesine rağmen false positive
sayısı yükseldiği için yalnızca threshold düşürmek production değişikliği
olarak kabul edilmedi.

Baseline threshold 60 korunarak hata analizi yapıldı.

## Experimental Scoring V2

False negative analizi sonucunda context-aware bonus kuralları deneysel
olarak test edildi:

- Key Vault sensitive service
- Network telemetry
- Private endpoint / trust boundary
- Secure transport

Aynı tuning dataset üzerinde V2 sonucu:

- TP: 16
- FP: 0
- FN: 0
- TN: 39
- Precision: 1.000
- Recall: 1.000
- F1: 1.000

Bu sonuç production performansı veya bağımsız doğrulama sonucu değildir.

V2 kuralları aynı dataset üzerindeki hata analizi kullanılarak geliştirildiği
için sonuç yalnızca exploratory/tuning sonucu olarak değerlendirilmelidir.

Production'a alınmadan önce yeni ve bağımsız bir holdout dataset üzerinde
doğrulanmalıdır.

## Scripts

- `build_eval_set.py`: Prowler FAIL bulgularından eval template üretir.
- `label_findings.py`: manuel labeling aracı.
- `evaluate_detection.py`: baseline precision/recall/F1 hesaplar.
- `evaluate_thresholds.py`: threshold karşılaştırması yapar.
- `evaluate_scoring_v2.py`: deneysel context-aware V2 scorer'ı değerlendirir.