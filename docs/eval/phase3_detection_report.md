# Phase 3 Threat Detection Rules Engine Evaluation Report

> **Methodology Notice:** The development evaluation dataset (`dev_generated_extra.jsonl`) is agent-generated. High stance and categorization accuracy reflect synthetic generation and serve strictly as a regression smoke test. Any category with fewer than 5 positive samples is marked as *not reliably measured*.

## 1. Summary
- **Dataset:** `dev (generated)` (108 samples)
- **Benign / Cautionary Set Size:** 25 samples
- **False-Positive Rate on Benign Messages:** 8.00% (2/25)
- **Dev-Copy Lint Violations:** 0 violations (clean)
- **Stance Accuracy:** 64.81%
- **Overall Micro F1:** 0.8864
- **Overall Macro F1:** 0.8782
- **Holdout Evaluation:** holdout: not provided

## 2. Dev-Copy Lint Audit
Scans all taxonomy rules for any phrase or regex literal of 4+ words that occurs verbatim in dev samples.

✅ **Zero verbatim 4+ word rule phrases detected in dev samples.** All rules are generalized.

## 3. Dev (Generated) Per-Category Breakdown & Confusion Matrix
| Category | Positives | Precision | Recall | F1 Score | TP | FP | FN | TN | Reliability |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `banking_fraud` | 11 | 0.8462 | 1.0000 | 0.9167 | 11 | 2 | 0 | 95 | Reliable (>=5) |
| `cybercrime_discussion` | 8 | 1.0000 | 0.8750 | 0.9333 | 7 | 0 | 1 | 100 | Reliable (>=5) |
| `fake_job_scams` | 8 | 1.0000 | 0.7500 | 0.8571 | 6 | 0 | 2 | 100 | Reliable (>=5) |
| `identity_fraud` | 8 | 1.0000 | 0.8750 | 0.9333 | 7 | 0 | 1 | 100 | Reliable (>=5) |
| `investment_scams` | 8 | 1.0000 | 1.0000 | 1.0000 | 8 | 0 | 0 | 100 | Reliable (>=5) |
| `malware_indicators` | 8 | 0.8750 | 0.8750 | 0.8750 | 7 | 1 | 1 | 99 | Reliable (>=5) |
| `online_threats` | 8 | 1.0000 | 0.5000 | 0.6667 | 4 | 0 | 4 | 100 | Reliable (>=5) |
| `otp_theft` | 8 | 0.8333 | 0.6250 | 0.7143 | 5 | 1 | 3 | 99 | Reliable (>=5) |
| `phishing` | 9 | 1.0000 | 0.7778 | 0.8750 | 7 | 0 | 2 | 99 | Reliable (>=5) |
| `suspicious_urls` | 8 | 1.0000 | 1.0000 | 1.0000 | 8 | 0 | 0 | 100 | Reliable (>=5) |
| `upi_fraud` | 8 | 0.8000 | 1.0000 | 0.8889 | 8 | 2 | 0 | 98 | Reliable (>=5) |

## 4. Dev (Generated) Per-Language Confusion Matrix
| Language | Total Samples | Exact Set Matches | Accuracy | TP | FP | FN |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| English | 35 | 30 | 85.7% | 30 | 3 | 3 |
| Hindi | 20 | 17 | 85.0% | 13 | 1 | 2 |
| Hinglish | 28 | 25 | 89.3% | 22 | 1 | 2 |
| Marathi | 25 | 18 | 72.0% | 13 | 1 | 7 |

## 5. Architectural Invariants Verified
- **Sensitive Excerpt Masking:** Full redaction for passwords, PINs, CVV, OTP, phone numbers, Telegram handles; e-mail domain retention (`[EMAIL_REDACTED]@domain`), UPI handle retention (`***@handle`); cards, Aadhaar, PAN, and bank accounts retain at most last 4 digits; excerpts bounded <= 120 chars.
- **ReDoS Hard Cap & Time Budget:** Hard 4096 character input limit enforced; 50ms per-rule regex timeout with degraded fallback and counter logging; 200ms overall per-message budget.
- **Official Domain Allowlist:** Externalized in `rules/allowlists/official_domains.yaml` with label-boundary matching (`.bank.in`, `.fin.in`, `.gov.in`, `.nic.in` and official banks); suppresses brand lookalike alerts only.
- **Idempotency:** Unique constraint `(tenant_id, message_id, category, taxonomy_version)` enforced.
- **Consent Gating:** Re-checked at runtime in worker task; non-consented messages immediately skipped.
- **Deletion Cascade:** Purges detections, rule hits, and URL indicators on `/delete_me`.
- **Offline URL Heuristics:** Zero network or socket resolution during indicator extraction.
- **Rule Review Gate:** Unreviewed rules excluded in `TTI_ENV=production`.
