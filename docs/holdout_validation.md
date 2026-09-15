# SentinelMind Scoring V2 — Independent Holdout Validation

## Overview

SentinelMind Experimental Scoring V2 v1.0 was frozen before the holdout
environment and holdout findings were evaluated.

The purpose of this validation was to test the frozen scoring behavior on
Azure security checks that were not present among the original tuning FAIL
checks.

---

## Frozen Configuration

- Scoring Version: `1.0`
- Threshold: `60`
- Scoring rules were not modified after observing holdout labels or results.

---

## Isolation

A dedicated Azure Resource Group was used:

`sentinelmind-holdout-rg`

The holdout environment was separated from the main SentinelMind demo
environment.

The infrastructure contained:

- isolated VNet
- NSG
- exposed test subnet
- subnet without NSG association

No VM was required.

---

## New Holdout Checks

The original tuning dataset contained 42 unique FAIL check types.

The following holdout FAIL checks were selected specifically because they
were not present in those tuning FAIL checks:

- `network_http_internet_access_restricted`
- `network_rdp_internet_access_restricted`
- `network_udp_internet_access_restricted`
- `network_subnet_nsg_associated`

Automated overlap verification result:

`OVERLAP: []`

---

## Prowler Scan

Prowler version:

`5.37.1`

The scan was scoped only to:

`sentinelmind-holdout-rg`

Executed checks:

- network_http_internet_access_restricted
- network_rdp_internet_access_restricted
- network_udp_internet_access_restricted
- network_subnet_nsg_associated

Scan result:

- FAIL: 4
- PASS: 1

The subnet NSG check produced one PASS and one FAIL because one subnet had an
NSG associated while the second subnet intentionally did not.

---

## Human Labeling

The evaluation workflow included only FAIL findings because the SentinelMind
detection evaluation measures prioritization of security findings.

Holdout FAIL findings:

`4`

Label distribution:

- High Priority / Positive: 4
- Not High Priority / Negative: 0

During labeling:

- V2 risk score was hidden.
- V2 prediction was hidden.
- Labels were assigned before evaluation was executed.

---

## Frozen V2 Result

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
| F1 | 1.000 |

Frozen Scoring V2 v1.0 identified all four unseen high-priority findings.

No false negative was observed in this controlled holdout run.

---

## Important Limitation

This holdout contains only positive examples.

Therefore this experiment provides evidence that the frozen V2 detected
the four unseen high-priority network findings, but it does not independently
measure false-positive behavior on unseen negative findings.

For that reason the result must not be interpreted as:

"SentinelMind has 100% general detection performance."

The correct interpretation is:

> Frozen Scoring V2 v1.0 correctly prioritized 4/4 unseen positive findings
> in a controlled independent Azure holdout run.

A larger mixed-class holdout containing both positive and negative examples
would be required for stronger generalization claims.

---

## Validation Classification

This experiment is classified as:

**Controlled independent holdout validation — positive-only, N=4**

It is separate from the original tuning-set result.