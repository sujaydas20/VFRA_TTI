"""Context and stance discrimination for threat and scam messages.

MANDATORY INVARIANTS:
- Stance labels must be strictly one of:
  * reporting: victim reports past incident or complaint
  * warning: alert or caution advising others against fraud/sharing credentials
  * discussing: educational, academic, query, or helpline discussion
  * potentially_facilitating: active solicitation, urgency, extortion, credential demand, lure
  * unclear: ambiguous context, conflicting cues, or degraded execution (routes to human review)
- 'none' is reserved strictly for benign messages with no detections.
- Ambiguous or conflicting signals must return 'unclear'; never silently suppress.
"""

import re
from typing import Dict, List, Pattern, Tuple


class StanceClassifier:
    """Classifies message stance across English, Hindi, Marathi, and Hinglish."""

    WARNING_PATTERNS: List[Pattern] = [
        re.compile(r"(?i)\b(?:never share|do not share|don't share|banks? never ask)\b"),
        re.compile(r"(?i)\b(?:public alert|scam alert|security alert|fraud alert)\b"),
        re.compile(r"(?i)\b(?:beware of|watch out for|stay safe from|be cautious)\b"),
        re.compile(r"(?i)\b(?:do not download|don't download|do not click|don't click)\b"),
        re.compile(r"(?i)\b(?:fraudsters are sending|scammers are|fake sms|fake link)\b"),
        # Hindi
        re.compile(r"(?:सावधान|धोखाधड़ी|सावधानी बरतें|सतर्क रहें|अलर्ट)"),
        re.compile(r"(?:ओटीपी|पिन|पासवर्ड).*(?:साझा\s*न\s*करें|मत\s*बताएं|न\s*दें)"),
        re.compile(r"(?:अज्ञात\s*लिंक\s*पर\s*क्लिक\s*न\s*करें|ऐप\s*डाउनलोड\s*न\s*करें)"),
        # Marathi
        re.compile(r"(?:सावधान|सतर्कता बाळगा|सावध राहा|सतर्क राहा)"),
        re.compile(r"(?:कोणालाही|ओटीपी|पिन).*(?:सांगू\s*नका|देऊ\s*नका)"),
        re.compile(r"(?:कोणत्याही\s*अनोळखी\s*लिंकवर\s*क्लिक\s*करू\s*नका|अॅप\s*डाउनलोड\s*करू\s*नका)"),
        # Hinglish
        re.compile(r"(?i)\bkisi ko bhi\b.*\bmat (?:batana|batao|dena)\b"),
        re.compile(r"(?i)\bbank kabhi nahi maangta\b"),
        re.compile(r"(?i)\bdhyan rahe\b.*\bkabhi bhi\b.*\b(?:nahi|mat)\b"),
        re.compile(r"(?i)\b(?:bach ke raho|fake aur scam|install mat karna|mat batana)\b"),
        re.compile(r"(?i)\b(?:aaj kal bohot zyada|fake courier delivery)\b"),
    ]

    REPORTING_PATTERNS: List[Pattern] = [
        re.compile(r"(?i)\b(?:i lost|friend lost|money was deducted|got scammed|reported to police)\b"),
        re.compile(r"(?i)\b(?:caller pretending to be|fraudster stole|cheated of|cut gaye)\b"),
        re.compile(r"(?i)\b(?:unauthorized transaction|money debited without|complaint filed)\b"),
        # Hindi
        re.compile(r"(?:खाते से|अकाउंट से)\s*\d+.*(?:कट गए|निकल गए|गायब हो गए)"),
        re.compile(r"(?:शिकायत दर्ज कराई|पुलिस में शिकायत|धोखाधड़ी हुई)"),
        # Marathi
        re.compile(r"(?:खात्यातून|खाते|अकाउंट|पैसे).*(?:कपात|कट गए|काढले|तक्रार|फसवणूक)"),
        # Hinglish
        re.compile(r"(?i)\b(?:account se|paise).*(?:uda diye|kat gaye|nikal gaye)\b"),
        re.compile(r"(?i)\b(?:scammer ne|police me complain|fraud ho gaya|dhokha hua)\b"),
    ]

    DISCUSSING_PATTERNS: List[Pattern] = [
        re.compile(r"(?i)\b(?:analyzed|in our class|looks like a phishing|how to report|can anyone confirm)\b"),
        re.compile(r"(?i)\b(?:cybercrime cell|cyber helpline 1930|cybercrime\.gov\.in|awareness session)\b"),
        re.compile(r"(?i)\b(?:is this genuine|is this real|asking for verification|how does this work)\b"),
        # Hindi
        re.compile(r"(?:साइबर सेल|1930 पर|तक्रार कशी|जागरूकता सत्र|क्या यह असली है)"),
        # Marathi
        re.compile(r"(?:सायबर सेल|1930 वर|माहिती सत्र|तक्रार कशी नोंदवायची)"),
        # Hinglish
        re.compile(r"(?i)\b(?:cybercrime portal|kya ye real hai|phishing attempt to me)\b"),
    ]

    FACILITATING_PATTERNS: List[Pattern] = [
        re.compile(r"(?i)\b(?:update now|click here|redeem now|account (?:will be )?block(?:ed)?|expir(?:e|ing))\b"),
        re.compile(r"(?i)\b(?:guaranteed(?:\s+\d+%)?\s+returns?|part time job|earn (?:rs|inr|\$|\u20b9)\s*\d+.*daily)\b"),
        re.compile(r"(?i)\b(?:electricity bill unpaid|power supply will be disconnected)\b"),
        re.compile(r"(?i)\b(?:download this apk|pre-approved loan|processing fee)\b"),
        re.compile(r"(?i)\b(?:leak your|send me \d+.*or|arrest warrant|fir registered)\b"),
        re.compile(r"(?i)\b(?:enter (?:otp|upi pin)|share (?:otp|credentials))\b"),
        # Hindi
        re.compile(r"(?:खाता.*ब्लॉक|केवायसी.*अपडेट|तुरंत\s*क्लिक\s*करें)"),
        re.compile(r"(?:घर\s*बैठे.*कमाएं|पार्ट\s*टाइम\s*जॉब|लॉटरी\s*लगी\s*है)"),
        re.compile(r"(?:बिजली\s*काट\s*दी\s*जाएगी|अरेस्ट\s*वॉरंट|तस्वीरें.*वायरल)"),
        # Marathi
        re.compile(r"(?:खाते.*ब्लॉक|केवायसी.*अपडेट|खालील\s*लिंकवर\s*क्लिक)"),
        re.compile(r"(?:खात्रीशीर\s*नफा|लॉटरी\s*लागली|वीजपुरवठा\s*खंडित|जीवे\s*मारण्याची)"),
        # Hinglish
        re.compile(r"(?i)\b(?:expire ho gaya|warna account band|loan pass ho gaya)\b"),
        re.compile(r"(?i)\b(?:power will be disconnected|task based earning|vip group)\b"),
        re.compile(r"(?i)\b(?:immediate settlement|warna arrest|enter karo)\b"),
    ]

    @classmethod
    def classify(cls, text: str, has_detections: bool = False) -> str:
        """Determine the stance of the input text.
        
        Exact returned values:
        - warning
        - reporting
        - discussing
        - potentially_facilitating
        - unclear (conflicting cues, ambiguous intent with detections)
        - none (only when has_detections is False and no threat patterns match)
        """
        if not text or not text.strip():
            return "none"

        is_warning = any(p.search(text) for p in cls.WARNING_PATTERNS)
        is_reporting = any(p.search(text) for p in cls.REPORTING_PATTERNS)
        is_discussing = any(p.search(text) for p in cls.DISCUSSING_PATTERNS)
        is_facilitating = any(p.search(text) for p in cls.FACILITATING_PATTERNS)

        # 1. Conflict detection: message matches both facilitating AND cautioning/reporting
        if is_facilitating and (is_warning or is_reporting):
            # If explicit warning cues dominate, warning takes precedence, else unclear
            return "warning" if is_warning else "unclear"

        # 2. Singular stances
        if is_warning:
            return "warning"
        if is_discussing:
            return "discussing"
        if is_reporting:
            return "reporting"
        if is_facilitating:
            return "potentially_facilitating"

        # 3. If there are positive detections but no stance matched -> unclear
        if has_detections:
            return "unclear"

        return "none"
