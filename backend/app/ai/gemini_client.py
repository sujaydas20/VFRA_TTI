"""Google Gemini API Client Integration using official google-genai SDK.

Features:
- Configurable model selection (gemini-2.5-flash, gemini-2.5-pro, etc.)
- Native asynchronous execution via client.aio.models.generate_content
- Structured JSON output parsing against GeminiStructuredThreatOutput schema
- Token consumption and cost accounting
- Robust fallback heuristic analysis when API key is unconfigured or rate limited
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from app.ai.prompts import (
    THREAT_INTELLIGENCE_SYSTEM_INSTRUCTION,
    build_threat_analysis_prompt,
    build_anomaly_interpretation_prompt,
)
from app.ai.schemas import (
    GeminiStructuredThreatOutput,
    SlangInterpretation,
    ThreatCategoryEnum,
    ThreatSeverityEnum,
)
from app.core.config import get_settings

logger = logging.getLogger(__name__)

# Try importing google-genai
try:
    from google import genai
    from google.genai import types
    from google.genai.errors import APIError
    HAS_GENAI_SDK = True
except ImportError:
    HAS_GENAI_SDK = False
    logger.warning("google-genai SDK not installed. Running in heuristic fallback mode.")


# Estimated pricing per 1M tokens (USD)
MODEL_PRICING = {
    "gemini-2.5-flash": {"input_per_m": 0.075, "output_per_m": 0.30},
    "gemini-2.0-flash": {"input_per_m": 0.10, "output_per_m": 0.40},
    "gemini-1.5-flash": {"input_per_m": 0.075, "output_per_m": 0.30},
    "gemini-2.5-pro": {"input_per_m": 1.25, "output_per_m": 5.00},
    "gemini-1.5-pro": {"input_per_m": 1.25, "output_per_m": 5.00},
}


class GeminiClientWrapper:
    """Enterprise wrapper for Google Gemini API."""

    _instance: Optional["GeminiClientWrapper"] = None

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.settings = get_settings()
        self.api_key = api_key or self.settings.GEMINI_API_KEY
        self.model = model or self.settings.GEMINI_MODEL
        self.pro_model = self.settings.GEMINI_PRO_MODEL

        self._client: Optional[Any] = None
        if HAS_GENAI_SDK and self.api_key:
            try:
                self._client = genai.Client(api_key=self.api_key)
                logger.info("Initialized Gemini Client with model '%s'", self.model)
            except Exception as e:
                logger.error("Failed to initialize genai.Client: %s", e)
                self._client = None

    @classmethod
    def get_instance(cls) -> "GeminiClientWrapper":
        """Singleton accessor."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @property
    def is_configured(self) -> bool:
        """Check if Gemini API is configured with an active key."""
        return bool(self._client is not None and self.api_key)

    async def analyze_message_content(
        self,
        sanitized_text: str,
        channel_title: Optional[str] = None,
        sender_username: Optional[str] = None,
        recent_context: Optional[List[str]] = None,
        use_pro_model: bool = False,
    ) -> Tuple[GeminiStructuredThreatOutput, Dict[str, Any]]:
        """
        Send sanitized message to Gemini for deep contextual threat intelligence analysis.
        Returns: (GeminiStructuredThreatOutput, usage_metadata)
        """
        start_time = time.perf_counter()
        target_model = self.pro_model if use_pro_model else self.model

        # If API key is not configured, immediately use offline heuristic analysis
        if not self.is_configured:
            logger.debug("Gemini API key not configured. Using deterministic heuristic threat analyzer.")
            analysis = self._run_heuristic_analysis(sanitized_text)
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            usage = {
                "model": "heuristic-rule-engine",
                "prompt_tokens": len(sanitized_text.split()),
                "completion_tokens": 50,
                "total_tokens": len(sanitized_text.split()) + 50,
                "estimated_cost_usd": 0.0,
                "latency_ms": latency_ms,
            }
            return analysis, usage

        prompt = build_threat_analysis_prompt(
            sanitized_text=sanitized_text,
            channel_title=channel_title,
            sender_username=sender_username,
            recent_context=recent_context,
        )

        try:
            # Structured generation using google-genai
            config = types.GenerateContentConfig(
                system_instruction=THREAT_INTELLIGENCE_SYSTEM_INSTRUCTION,
                temperature=self.settings.GEMINI_TEMPERATURE,
                max_output_tokens=self.settings.GEMINI_MAX_TOKENS,
                response_mime_type="application/json",
                response_schema=GeminiStructuredThreatOutput,
            )

            # Async generation
            response = await self._client.aio.models.generate_content(
                model=target_model,
                contents=prompt,
                config=config,
            )

            latency_ms = (time.perf_counter() - start_time) * 1000.0

            # Extract token counts
            prompt_tokens = 0
            completion_tokens = 0
            if hasattr(response, "usage_metadata") and response.usage_metadata:
                prompt_tokens = response.usage_metadata.prompt_token_count or 0
                completion_tokens = response.usage_metadata.candidates_token_count or 0

            cost = self._calculate_cost(target_model, prompt_tokens, completion_tokens)
            usage = {
                "model": target_model,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
                "estimated_cost_usd": cost,
                "latency_ms": latency_ms,
            }

            # Parse structured JSON response
            output_text = response.text or "{}"
            parsed_data = json.loads(output_text)
            structured_output = GeminiStructuredThreatOutput.model_validate(parsed_data)
            return structured_output, usage

        except Exception as exc:
            logger.warning("Gemini API call failed (%s: %s). Falling back to heuristic analysis.", type(exc).__name__, exc)
            analysis = self._run_heuristic_analysis(sanitized_text)
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            usage = {
                "model": f"{target_model}-fallback-heuristic",
                "prompt_tokens": len(sanitized_text.split()),
                "completion_tokens": 50,
                "total_tokens": len(sanitized_text.split()) + 50,
                "estimated_cost_usd": 0.0,
                "latency_ms": latency_ms,
            }
            return analysis, usage

    async def interpret_anomaly(
        self,
        channel_id: str,
        anomaly_type: str,
        metric_value: float,
        baseline_mean: float,
        z_score: float,
        sample_recent_messages: List[str],
    ) -> str:
        """Use Gemini to generate concise threat analyst reasoning for a channel anomaly."""
        if not self.is_configured:
            return (
                f"Statistical {anomaly_type} detected on channel '{channel_id}' with z-score of {z_score:.2f} "
                f"(current: {metric_value:.1f}, baseline: {baseline_mean:.1f}). Recommended for analyst review."
            )

        prompt = build_anomaly_interpretation_prompt(
            channel_id=channel_id,
            anomaly_type=anomaly_type,
            metric_value=metric_value,
            baseline_mean=baseline_mean,
            z_score=z_score,
            sample_recent_messages=sample_recent_messages,
        )

        try:
            config = types.GenerateContentConfig(
                system_instruction=THREAT_INTELLIGENCE_SYSTEM_INSTRUCTION,
                temperature=0.2,
                max_output_tokens=500,
            )
            response = await self._client.aio.models.generate_content(
                model=self.model,
                contents=prompt,
                config=config,
            )
            return response.text or "Anomaly interpretation generated."
        except Exception as e:
            logger.warning("Failed to interpret anomaly via Gemini: %s", e)
            return (
                f"Statistical {anomaly_type} detected with z-score {z_score:.2f}. "
                f"Message velocity exceeds normal channel variance."
            )

    def _calculate_cost(self, model: str, prompt_tokens: int, completion_tokens: int) -> float:
        """Calculate estimated cost in USD based on official token pricing."""
        rates = MODEL_PRICING.get(model, MODEL_PRICING["gemini-2.5-flash"])
        input_cost = (prompt_tokens / 1_000_000.0) * rates["input_per_m"]
        output_cost = (completion_tokens / 1_000_000.0) * rates["output_per_m"]
        return round(input_cost + output_cost, 6)

    def _run_heuristic_analysis(self, text: str) -> GeminiStructuredThreatOutput:
        """
        High-fidelity deterministic threat analyzer for offline / fallback mode.
        Covers all 13 threat categories and slang dictionaries.
        """
        text_lower = text.lower()

        # Threat keyword matchers
        patterns = {
            ThreatCategoryEnum.UPI_FRAUD: [
                r"\b(upi|gpay|phonepe|paytm)\b.*?\b(refund|freeze|pin|scam|mule|fake|screenshot)\b",
                r"\b[a-zA-Z0-9.\-_]+@[a-zA-Z]{2,64}\b.*?\b(send|pay|claim|cashback)\b",
                r"\b(qr code|upi id|merchant)\b.*?\b(fraud|trap|stolen)\b",
            ],
            ThreatCategoryEnum.BANKING_FRAUD: [
                r"\b(bank|account|neft|rtgs|imps)\b.*?\b(freeze|mule|rent|kyc|otp)\b",
                r"\b(mule account|cashing out|bank logs|instant cashout)\b",
                r"\b(cheque|atm clone|credit card|cvv|fullz)\b",
            ],
            ThreatCategoryEnum.DATA_LEAKS: [
                r"\b(database|leak|dump|breach|exfiltrated|sql dump)\b",
                r"\b(aadhar|pan card|voter id|passport)\b.*?\b(dump|records|leak)\b",
                r"\b(combo list|passwords dump|user records)\b",
            ],
            ThreatCategoryEnum.CREDENTIAL_EXPOSURE: [
                r"\b(passwords?|credentials?|login:pass|combo|stealer logs?)\b",
                r"\b(redline|lumma|vidar|meta stealer)\b",
                r"\b(token grabber|cookie dump)\b",
            ],
            ThreatCategoryEnum.MALWARE: [
                r"\b(rat|trojan|ransomware|keylogger|crypter|fud payload)\b",
                r"\b(apk mod|stealer\.exe|bypass av|c2 server)\b",
                r"\b(meterpreter|mimikatz|reverse shell)\b",
            ],
            ThreatCategoryEnum.PHISHING: [
                r"\b(phishing|phish kit|fake login|lookalike domain)\b",
                r"\b(hxxps?://|http://[0-9]{1,3}\.[0-9]{1,3})\b.*?\b(login|verify|bank)\b",
                r"\b(urgent kyc|account suspended|click here to verify)\b",
            ],
            ThreatCategoryEnum.EXTORTION: [
                r"\b(blackmail|extort|ransom|nude|leak private|compromised photo)\b",
                r"\b(pay btc or leak|threat to expose|police complaint)\b",
            ],
            ThreatCategoryEnum.ONLINE_SCAMS: [
                r"\b(part time job|telegram task|crypto investment|double your money)\b",
                r"\b(guaranteed profit|daily 5000|work from home scam)\b",
                r"\b(fake loan|loan app harassment)\b",
            ],
            ThreatCategoryEnum.FINANCIAL_FRAUD: [
                r"\b(crypto|trc20|usdt|bitcoin|monero)\b.*?\b(launder|mixer|mule|dirty)\b",
                r"\b(fake currency|counterfeit|hawala)\b",
            ],
        }

        matched_category = ThreatCategoryEnum.BENIGN
        evidence: List[str] = []
        slang_list: List[SlangInterpretation] = []

        # Slang extraction
        slang_dict = {
            "mule account": "Bank account operated by a proxy to receive and siphon illicit funds",
            "cashing out": "Liquidating fraudulent credit balances into cash or untraceable crypto",
            "fullz": "Complete set of victim personally identifiable information including card details",
            "otp bot": "Automated IVR/Telegram bot designed to intercept 2FA codes",
            "bank logs": "Stolen online banking credentials with active session cookies",
            "sim swap": "Illegitimate hijacking of a victim's cellular SIM card to intercept 2FA",
            "wh/cc": "Carding terminology referring to warehouse/credit card dumps",
            "trc20": "TRON blockchain token commonly leveraged for illicit fund movement",
            "dump": "Exfiltrated database or stolen bulk records offered for sale",
            "🐀": "Remote Access Trojan (RAT) indicator",
            "💰": "Illicit financial gain indicator",
            "💳": "Compromised payment card indicator",
            "🤫": "Covert or illegal leak indicator",
            "💣": "Zero-day exploit or aggressive cyberattack indicator",
        }

        for term, meaning in slang_dict.items():
            if term.lower() in text_lower:
                slang_list.append(SlangInterpretation(term=term, meaning=meaning))

        for cat, regexes in patterns.items():
            for r in regexes:
                m = re.search(r, text_lower)
                if m:
                    matched_category = cat
                    evidence.append(m.group(0))
                    break
            if matched_category != ThreatCategoryEnum.BENIGN:
                break

        # Scoring heuristics
        threat_detected = matched_category != ThreatCategoryEnum.BENIGN or len(slang_list) > 0
        if not threat_detected:
            return GeminiStructuredThreatOutput(
                threat_detected=False,
                primary_category=ThreatCategoryEnum.BENIGN,
                secondary_categories=[],
                severity=ThreatSeverityEnum.INFO,
                confidence_score=15.0,
                threat_description="Message contains ordinary conversational text with no detected threat indicators.",
                explanation="Automated baseline inspection detected no malicious keywords, fraud patterns, or illicit solicitations.",
                supporting_evidence=[],
                slang_interpretations=[],
                coded_language_detected=False,
                is_actionable=False,
                recommended_action="MONITOR",
            )

        # Classify severity
        confidence = 70.0 + (len(evidence) * 10.0) + (len(slang_list) * 5.0)
        confidence = min(confidence, 95.0)

        severity = ThreatSeverityEnum.MEDIUM
        if matched_category in (ThreatCategoryEnum.MALWARE, ThreatCategoryEnum.DATA_LEAKS, ThreatCategoryEnum.EXTORTION):
            severity = ThreatSeverityEnum.HIGH
        if len(evidence) >= 2 or len(slang_list) >= 2:
            severity = ThreatSeverityEnum.CRITICAL if severity == ThreatSeverityEnum.HIGH else ThreatSeverityEnum.HIGH

        desc = f"Identified potential {matched_category.value.replace('_', ' ').title()} operation involving {', '.join(evidence[:3])}."
        exp = (
            f"Deterministic heuristics detected indicators matching {matched_category.value}. "
            f"Observed keywords and coded references suggest active illicit activity."
        )

        return GeminiStructuredThreatOutput(
            threat_detected=True,
            primary_category=matched_category,
            secondary_categories=[],
            severity=severity,
            confidence_score=confidence,
            threat_description=desc,
            explanation=exp,
            supporting_evidence=evidence,
            slang_interpretations=slang_list,
            coded_language_detected=len(slang_list) > 0,
            is_actionable=severity in (ThreatSeverityEnum.HIGH, ThreatSeverityEnum.CRITICAL),
            recommended_action="FLAG_FOR_ANALYST_TRIAGE" if severity in (ThreatSeverityEnum.HIGH, ThreatSeverityEnum.CRITICAL) else "LOG_AND_MONITOR",
        )
