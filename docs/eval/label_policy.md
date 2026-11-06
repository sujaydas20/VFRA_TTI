# Threat and Scam Dataset Labeling Policy

## 1. Core Principle
* **Categories** describe *what the text is about* (the threat vector, lure, fraudulent mechanism, or illicit discussion).
* **Stance** describes *what the speaker is doing* (warning others, reporting an incident, discussing educationally, actively facilitating fraud, or unclear).

## 2. Invariants
1. **Lures Retain Categories in Warnings:** If a message cautions or warns against a specific scam mechanism (e.g., an alert warning users not to click courier SMS with malicious APKs), the message keeps the underlying threat categories (`phishing`, `malware_indicators`) while having `expected_stance: "warning"`.
2. **Victim Reports Retain Categories:** If a victim reports losing money to an impersonator demanding remote access, the message retains the fraudulent categories with `expected_stance: "reporting"`.
3. **No Simultaneous Rule and Label Tuning:** A ground truth label and an active rule are never tuned simultaneously for the same test case. Label amendments must be documented in the changelog with clear rationale.
4. **Stance Labels:** The stance label must strictly be one of:
   * `warning`: Cautions, alerts, or advisories against sharing credentials or falling for scams.
   * `reporting`: Victim complaints, loss notifications, or law enforcement incident reports.
   * `discussing`: Educational questions, news sharing, or cyber helpline references.
   * `potentially_facilitating`: Direct solicitations, lures, urgent calls to action, or extortion.
   * `unclear`: Conflicting cues or degraded execution requiring human triage.
   * `none`: Reserved exclusively for clean messages with zero threat detections.

## 3. Dataset Changelog
* **`dev_sample_13`**: Updated `expected_categories` from `["phishing"]` to `["phishing", "malware_indicators"]`.
  * *Reason:* Under the unified labeling policy, the alert text explicitly describes courier phishing SMS accompanied by malicious APK download links. The message legitimately references both phishing and malware delivery mechanisms with `expected_stance: "warning"`.

