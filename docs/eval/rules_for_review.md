# Threat Detection Taxonomy: Regional Rules for Review

This document exports the **ACTUAL** Hindi, Marathi, and Hinglish keywords, phrases, proximity windows, and regex patterns configured in `backend/rules/taxonomy/` for human review.

## Summary Counts

- **Total Rules:** 22
- **Reviewed Rules:** 0
- **Unreviewed Rules:** 22

### Rules per Language
| Language | Rule Count |
|---|---|
| `en` | 22 |
| `hi` | 22 |
| `hinglish` | 22 |
| `mr` | 22 |

### Rules per Category
| Category | Rule Count |
|---|---|
| `banking_fraud` | 3 |
| `cybercrime_discussion` | 1 |
| `fake_job_scams` | 2 |
| `identity_fraud` | 1 |
| `investment_scams` | 2 |
| `malware_indicators` | 2 |
| `online_threats` | 2 |
| `otp_theft` | 2 |
| `phishing` | 2 |
| `suspicious_urls` | 1 |
| `upi_fraud` | 4 |

---

## Detailed Rule Pattern Specification

### `bank_kyc_suspension`
- **Category:** `banking_fraud`
- **Rule Type:** `phrase`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `HIGH`
- **Weight:** `2.0`

**Actual Pattern Definitions:**
```yaml
phrases:
- KYC expire
- account band
- account blocked
- केवायसी अपडेट
- खाते ब्लॉक
- खाता ब्लॉक
- rewards points
proximity:
- - kyc
  - expire
  - 4
- - account
  - block
  - 4
- - खाता
  - ब्लॉक
  - 5
- - केवायसी
  - अपडेट
  - 4
```

### `utility_electricity_disconnect`
- **Category:** `banking_fraud`
- **Rule Type:** `phrase`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `HIGH`
- **Weight:** `2.0`

**Actual Pattern Definitions:**
```yaml
phrases:
- electricity bill
- power disconnect
- बिजली बिल
- बिजली काट
- वीज बिल
- वीज खंडित
proximity:
- - electricity
  - disconnected
  - 5
- - power
  - disconnected
  - 5
- - बिजली
  - काट
  - 6
- - वीज
  - खंडित
  - 6
```

### `loan_courier_impersonation`
- **Category:** `banking_fraud`
- **Rule Type:** `phrase`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `HIGH`
- **Weight:** `1.5`

**Actual Pattern Definitions:**
```yaml
phrases:
- pre-approved loan
- customs officer
- parcel seized
- drugs in parcel
- बिजली अधिकारी
- कूरियर अधिकारी
proximity:
- - fedex
  - parcel
  - 6
- - customs
  - parcel
  - 6
- - drugs
  - parcel
  - 6
```

### `cybercrime_helpline_discussion`
- **Category:** `cybercrime_discussion`
- **Rule Type:** `phrase`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `INFO`
- **Weight:** `1.0`

**Actual Pattern Definitions:**
```yaml
phrases:
- cybersecurity
- cyber cell
- cyber crime
- सायबर सेल
- 1930 हेल्पलाइन
- cybercrime portal
proximity:
- - '1930'
  - report
  - 5
- - '1930'
  - शिकायत
  - 5
- - '1930'
  - तक्रार
  - 5
- - cybercrime
  - report
  - 5
```

### `task_scam_video_reviews`
- **Category:** `fake_job_scams`
- **Rule Type:** `phrase`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `HIGH`
- **Weight:** `2.0`

**Actual Pattern Definitions:**
```yaml
phrases:
- work from home
- part time job
- daily income
- task earning
- पार्ट टाइम जॉब
- होटल रेटिंग
- टास्क पूर्ण
- यूट्यूब लाईक
proximity:
- - work from home
  - income
  - 6
- - part time
  - job
  - 4
- - youtube
  - subscribe
  - 5
- - youtube
  - like
  - 5
- - video
  - like
  - 4
- - rating
  - earn
  - 5
```

### `task_scam_telegram_recruitment`
- **Category:** `fake_job_scams`
- **Rule Type:** `phrase`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `MEDIUM`
- **Weight:** `1.2`

**Actual Pattern Definitions:**
```yaml
phrases:
- Telegram contact
- Telegram job
- टेलीग्राम संपर्क
proximity:
- - telegram
  - contact
  - 4
- - telegram
  - join
  - 4
- - telegram
  - salary
  - 5
```

### `police_fir_digital_arrest`
- **Category:** `identity_fraud`
- **Rule Type:** `phrase`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `CRITICAL`
- **Weight:** `2.5`

**Actual Pattern Definitions:**
```yaml
phrases:
- digital arrest
- police FIR
- money laundering
- arrest warrant
- arrest warrant niklega
- डिजिटल अरेस्ट
- मनी लॉन्ड्रिंग
- अटक वॉरंट
proximity:
- - arrest
  - settlement
  - 6
- - police
  - warrant
  - 5
- - fir
  - settle
  - 5
- - डिजिटल
  - अरेस्ट
  - 4
- - मनी लॉन्ड्रिंग
  - केस
  - 5
```

### `crypto_arbitrage_guarantee`
- **Category:** `investment_scams`
- **Rule Type:** `phrase`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `HIGH`
- **Weight:** `2.0`

**Actual Pattern Definitions:**
```yaml
phrases:
- guaranteed returns
- crypto arbitrage
- VIP signals
- trading group
- 10x returns
proximity:
- - guaranteed
  - returns
  - 4
- - crypto
  - signals
  - 5
- - trading
  - vip
  - 4
- - usdt
  - earning
  - 5
```

### `lottery_kbc_fee_scam`
- **Category:** `investment_scams`
- **Rule Type:** `phrase`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `HIGH`
- **Weight:** `2.0`

**Actual Pattern Definitions:**
```yaml
phrases:
- KBC lottery
- केबीसी लॉटरी
- लॉटरी लगी
- पैसे डबल
- खात्रीशीर नफा
proximity:
- - kbc
  - lottery
  - 4
- - lottery
  - won
  - 4
- - पैसे
  - डबल
  - 4
- - शेअर
  - नफा
  - 5
```

### `apk_file_solicitation`
- **Category:** `malware_indicators`
- **Rule Type:** `phrase`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `HIGH`
- **Weight:** `2.0`

**Actual Pattern Definitions:**
```yaml
phrases:
- download apk
- install apk
- apk file
- एपीके डाउनलोड
- एपीके इंस्टॉल
- Trojan rat
proximity:
- - download
  - apk
  - 5
- - install
  - apk
  - 5
- - fake
  - apk
  - 5
- - suspicious
  - apk
  - 5
```

### `remote_access_scam_tools`
- **Category:** `malware_indicators`
- **Rule Type:** `phrase`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `HIGH`
- **Weight:** `2.0`

**Actual Pattern Definitions:**
```yaml
proximity:
- - anydesk
  - kyc
  - 8
- - anydesk
  - bank
  - 8
- - anydesk
  - otp
  - 8
- - teamviewer
  - support
  - 8
- - teamviewer
  - bank
  - 8
- - quicksupport
  - officer
  - 8
- - screen share
  - otp
  - 8
- - स्क्रीन शेयर
  - बैंक
  - 8
- - रिमोट ऐप
  - अधिकारी
  - 8
```

### `sextortion_webcam_blackmail`
- **Category:** `online_threats`
- **Rule Type:** `phrase`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `CRITICAL`
- **Weight:** `3.0`

**Actual Pattern Definitions:**
```yaml
phrases:
- webcam leak
- private video
- private photos
- तस्वीरें वायरल
- व्हिडिओ व्हायरल
proximity:
- - webcam
  - leak
  - 5
- - private
  - leak
  - 5
- - video
  - viral
  - 5
- - तस्वीरें
  - वायरल
  - 5
```

### `physical_violence_threat`
- **Category:** `online_threats`
- **Rule Type:** `phrase`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `CRITICAL`
- **Weight:** `3.0`

**Actual Pattern Definitions:**
```yaml
phrases:
- kill you
- जान से मार
- जीवे मारण्याची धमकी
- घर आकर मारूँगा
proximity:
- - kill
  - family
  - 5
- - जान
  - मार
  - 4
```

### `otp_solicitation_phrase`
- **Category:** `otp_theft`
- **Rule Type:** `phrase`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `CRITICAL`
- **Weight:** `2.5`

**Actual Pattern Definitions:**
```yaml
phrases:
- share OTP
- enter OTP
- send OTP
- ओटीपी बताओ
- ओटीपी सांगा
proximity:
- - otp
  - enter
  - 4
- - otp
  - share
  - 4
- - otp
  - pin
  - 4
- - otp
  - batao
  - 4
- - otp
  - bhejo
  - 4
```

### `otp_harvesting_regex`
- **Category:** `otp_theft`
- **Rule Type:** `regex`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `CRITICAL`
- **Weight:** `2.0`

**Actual Pattern Definitions:**
```yaml
regex: (?i)\b(?:enter|share|send|forward|batao|bhejo|सांगा|बताओ)\b.{1,20}\b(?:otp|verification\s*code)\b
```

### `phishing_kyc_rewards_link`
- **Category:** `phishing`
- **Rule Type:** `phrase`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `HIGH`
- **Weight:** `2.0`

**Actual Pattern Definitions:**
```yaml
phrases:
- click link
- update link
- Redeem now at
- यहाँ क्लिक करें
- लिंकवर क्लिक करा
- courier delivery
proximity:
- - courier
  - sms
  - 6
- - courier
  - link
  - 6
- - courier
  - apk
  - 6
- - delivery
  - sms
  - 5
- - delivery
  - link
  - 5
- - link
  - click
  - 4
- - link
  - update
  - 4
- - लिंक
  - क्लिक
  - 4
- - पैन
  - क्लिक
  - 5
```

### `phishing_pm_kisan_lure`
- **Category:** `phishing`
- **Rule Type:** `phrase`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `HIGH`
- **Weight:** `1.5`

**Actual Pattern Definitions:**
```yaml
phrases:
- PM Kisan
- पीएम किसान
- Kisan Yojana
- योजना हप्ता
proximity:
- - kisan
  - yojana
  - 4
- - kisan
  - installment
  - 4
- - किसान
  - योजना
  - 4
```

### `defanged_phishing_link`
- **Category:** `suspicious_urls`
- **Rule Type:** `phrase`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `HIGH`
- **Weight:** `2.0`

**Actual Pattern Definitions:**
```yaml
phrases:
- hxxp://
- hxxps://
- '[.]xyz'
- '[.]top'
- '[.]tk'
```

### `upi_fraud_pin_demand`
- **Category:** `upi_fraud`
- **Rule Type:** `phrase`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `HIGH`
- **Weight:** `2.0`

**Actual Pattern Definitions:**
```yaml
phrases:
- UPI PIN
- यूपीआई पिन
- UPI pin daalo
proximity:
- - upi
  - pin
  - 4
- - upi
  - transfer
  - 4
- - पिन
  - टाका
  - 4
- - पिन
  - डालो
  - 4
```

### `upi_fraud_qr_collect`
- **Category:** `upi_fraud`
- **Rule Type:** `phrase`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `HIGH`
- **Weight:** `1.5`

**Actual Pattern Definitions:**
```yaml
phrases:
- QR code scan
- क्यूआर कोड
proximity:
- - qr
  - scan
  - 4
- - qr
  - bheja
  - 4
```

### `upi_fraud_receive_pin_myth`
- **Category:** `upi_fraud`
- **Rule Type:** `phrase`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `HIGH`
- **Weight:** `1.8`

**Actual Pattern Definitions:**
```yaml
phrases:
- receive money PIN
- पैसे घेण्यासाठी पिन
- पैसे लेने के लिए पिन
proximity:
- - receive
  - pin
  - 5
- - पैसे
  - पिन
  - 4
- - paise
  - pin
  - 4
```

### `upi_fraud_vpa_entity`
- **Category:** `upi_fraud`
- **Rule Type:** `entity`
- **Languages:** en, hi, mr, hinglish
- **is_reviewed:** `False`
- **Severity:** `MEDIUM`
- **Weight:** `1.0`

**Actual Pattern Definitions:**
```yaml
entity_type: upi
```

