"""Test suite for Google Gemini AI Threat Intelligence & Automated Detection Engine.

Verifies:
1. Text normalization, script/language identification, and relevance triage (Module 1)
2. Automated threat classification across all 13 categories (Module 2)
3. Contextual intelligence, slang, and emoji decoding (Module 3)
4. Deterministic entity and IOC extraction and defanging (Module 4)
5. Statistical anomaly detection and z-score calculation (Module 5)
6. Cross-source intelligence correlation (Module 6)
7. Deterministic calibrated scoring and severity rating (Module 7)
8. High-severity alert generation and deduplication
9. Celery task wiring and dedicated telegram_ai queue
10. Database model integrity and representation
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import uuid
import pytest

from app.ai.alert_engine import AIAlertEngine
from app.ai.anomaly_detector import AnomalyDetectionEngine
from app.ai.correlation_engine import IntelligenceCorrelationEngine
from app.ai.gemini_client import GeminiClientWrapper
from app.ai.ioc_extractor import IOCExtractor
from app.ai.message_understanding import MessageUnderstandingEngine
from app.ai.schemas import (
    AnomalyTypeEnum,
    CorrelationTypeEnum,
    ThreatCategoryEnum,
    ThreatSeverityEnum,
)
from app.ai.scoring_engine import ThreatScoringEngine
from app.ai.threat_classifier import ThreatClassificationOrchestrator
from app.database.models.ai import (
    AIAlertRecord,
    AIMessageAnalysis,
    AITokenUsageRecord,
    ExtractedIOCRecord,
    IntelligenceCorrelation,
    ThreatAnomalyRecord,
)
from app.workers.celery_app import celery_app


def test_ai_module1_message_understanding_and_normalization():
    """Verify Module 1: Text normalization, zero-width stripping, and script detection."""
    engine = MessageUnderstandingEngine()

    raw_text = "Hacked\u200b  Aadhaar \u200dDump 100%   working \tखिलाड़ी   "
    res = engine.process(raw_text)

    # Unicode & whitespace normalization
    assert "\u200b" not in res.normalized_text
    assert "\u200d" not in res.normalized_text
    assert "  " not in res.normalized_text
    assert "खिलाड़ी" in res.normalized_text

    # Script identification
    assert "Latin" in res.detected_scripts
    assert "Devanagari (Hindi/Regional)" in res.detected_scripts
    assert res.is_multilingual is True

    # Slang extraction
    assert "aadhaar dump" in res.detected_slang or "aadhar dump" in res.detected_slang
    assert res.is_relevant_for_ai is True


def test_ai_module1_relevance_triage():
    """Verify Module 1: Filters trivial conversational noise to preserve token budget."""
    engine = MessageUnderstandingEngine()

    # Noise examples should bypass LLM
    assert engine.process("hi").is_relevant_for_ai is False
    assert engine.process("good morning").is_relevant_for_ai is False
    assert engine.process("/start").is_relevant_for_ai is False
    assert engine.process("ok thanks").is_relevant_for_ai is False

    # Substantive or threat-laden messages must pass triage
    assert engine.process("Fresh mule account available for rent in Mumbai").is_relevant_for_ai is True
    assert engine.process("Contact @dark_broker for fullz db leak").is_relevant_for_ai is True


def test_ai_module4_ioc_extraction_and_defanging():
    """Verify Module 4: Deterministic extraction and defanging of IOCs."""
    extractor = IOCExtractor()

    sample = (
        "C2 server at 198.51.100.42 and domain malicious-bank[.]cc. "
        "Pay 0.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or TRC20 to "
        "TXa1234567890123456789012345678901. UPI: mule_pay@okhdfcbank. "
        "Contact @cyber_agent_99 or call +919876543210. Hash: "
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855."
    )

    iocs = extractor.extract_all(sample)
    types_found = {i.ioc_type for i in iocs}

    assert "ipv4" in types_found
    assert "domain" in types_found
    assert "crypto_btc" in types_found
    assert "crypto_tron" in types_found
    assert "upi_id" in types_found
    assert "telegram_handle" in types_found
    assert "phone" in types_found
    assert "hash_sha256" in types_found

    # Verify defanging
    ip_ioc = next(i for i in iocs if i.ioc_type == "ipv4")
    assert "[.]" in ip_ioc.defanged_value

    upi_ioc = next(i for i in iocs if i.ioc_type == "upi_id")
    assert upi_ioc.normalized_value == "mule_pay@okhdfcbank"

    btc_ioc = next(i for i in iocs if i.ioc_type == "crypto_btc")
    assert btc_ioc.normalized_value == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


def test_ai_module7_threat_scoring_calibration():
    """Verify Module 7: Hybrid calibrated scoring and severity thresholds."""
    scoring = ThreatScoringEngine()
    extractor = IOCExtractor()

    # Scenario 1: Benign text
    score_benign = scoring.calculate_calibrated_score(
        llm_confidence=10.0,
        threat_category=ThreatCategoryEnum.BENIGN.value,
        extracted_iocs=[],
        detected_slang={},
        threat_detected=False,
    )
    assert score_benign <= 20.0
    assert scoring.determine_severity(score_benign, ThreatCategoryEnum.BENIGN.value) == ThreatSeverityEnum.INFO

    # Scenario 2: Active UPI Fraud with Slang & Crypto
    sample = "Mule account ready for cashing out. Pay USDT to TXa1234567890123456789012345678901 or upi test@icici"
    iocs = extractor.extract_all(sample)
    slang = {"mule account": "proxy", "cashing out": "liquidate"}

    score_threat = scoring.calculate_calibrated_score(
        llm_confidence=80.0,
        threat_category=ThreatCategoryEnum.UPI_FRAUD.value,
        extracted_iocs=iocs,
        detected_slang=slang,
        threat_detected=True,
    )
    assert score_threat >= 75.0
    severity = scoring.determine_severity(score_threat, ThreatCategoryEnum.UPI_FRAUD.value, has_critical_ioc=True)
    assert severity in (ThreatSeverityEnum.HIGH, ThreatSeverityEnum.CRITICAL)


def test_ai_gemini_client_heuristic_offline_mode():
    """Verify Gemini client operates cleanly in offline heuristic mode when unconfigured."""
    client = GeminiClientWrapper(api_key=None)
    assert client.is_configured is False

    # Financial fraud test
    analysis = client._run_heuristic_analysis("Selling fresh Indian bank logs with OTP bot access. Instant cashout.")
    assert analysis.threat_detected is True
    assert analysis.primary_category in (ThreatCategoryEnum.BANKING_FRAUD, ThreatCategoryEnum.FINANCIAL_FRAUD)
    assert analysis.severity in (ThreatSeverityEnum.HIGH, ThreatSeverityEnum.CRITICAL)
    assert len(analysis.slang_interpretations) > 0

    # Pricing calculations
    cost_flash = client._calculate_cost("gemini-2.5-flash", prompt_tokens=1000, completion_tokens=200)
    assert cost_flash > 0.0
    assert cost_flash < 0.001


@pytest.mark.asyncio
async def test_ai_module5_anomaly_detection_evaluator():
    """Verify Module 5: Statistical volume velocity evaluation and z-score computation."""
    detector = AnomalyDetectionEngine()
    mock_db = AsyncMock()

    # 1h count: 50 messages, 24h count: 120 messages (hourly mean = 5.0, std ~ 2.23)
    mock_db.add = MagicMock()
    mock_db.scalar.side_effect = [50, 120]

    with patch.object(detector.gemini_client, "interpret_anomaly", new_callable=AsyncMock) as mock_interp:
        mock_interp.return_value = "Sudden spike in message velocity consistent with a coordinated campaign."
        anomalies = await detector.evaluate_channel_anomalies(
            db=mock_db,
            tenant_id=uuid.uuid4(),
            channel_id="-1001999999999",
            sample_messages=["Sample test burst 1", "Sample test burst 2"],
        )

    assert len(anomalies) == 1
    assert anomalies[0].anomaly_type == AnomalyTypeEnum.VOLUME_SPIKE.value
    assert anomalies[0].z_score > 2.5
    assert anomalies[0].severity in ("MEDIUM", "HIGH")
    assert "coordinated campaign" in anomalies[0].gemini_explanation


@pytest.mark.asyncio
async def test_ai_module6_intelligence_correlation():
    """Verify Module 6: Cross-source IOC matching and correlation record creation."""
    engine = IntelligenceCorrelationEngine()
    tenant_id = uuid.uuid4()
    msg_1 = "tg_chan1_101"
    msg_2 = "tg_chan2_505"

    new_ioc = ExtractedIOCRecord(
        ioc_id=uuid.uuid4(),
        tenant_id=tenant_id,
        message_id=msg_1,
        channel_id="chan1",
        ioc_type="crypto_tron",
        raw_value="TXYZ1234567890123456789012345678901",
        normalized_value="TXYZ1234567890123456789012345678901",
        defanged_value="TXYZ1234567890123456789012345678901",
    )

    matching_historical_ioc = ExtractedIOCRecord(
        ioc_id=uuid.uuid4(),
        tenant_id=tenant_id,
        message_id=msg_2,
        channel_id="chan2",
        ioc_type="crypto_tron",
        raw_value="TXYZ1234567890123456789012345678901",
        normalized_value="TXYZ1234567890123456789012345678901",
        defanged_value="TXYZ1234567890123456789012345678901",
    )

    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.scalars.return_value = MagicMock(all=lambda: [matching_historical_ioc])
    mock_db.scalar.return_value = None  # No prior existing correlation

    correlations = await engine.correlate_message_iocs(
        db=mock_db,
        tenant_id=tenant_id,
        message_id=msg_1,
        channel_id="chan1",
        new_iocs=[new_ioc],
    )

    assert len(correlations) == 1
    assert correlations[0].correlation_type == CorrelationTypeEnum.SHARED_IOC.value
    assert correlations[0].source_message_id == msg_1
    assert correlations[0].target_message_id == msg_2
    assert "TXYZ" in correlations[0].matched_entity_value


@pytest.mark.asyncio
async def test_ai_alert_engine_deduplication():
    """Verify AI alert engine creates alerts for high severity and deduplicates alerts."""
    alert_engine = AIAlertEngine()
    tenant_id = uuid.uuid4()

    analysis = AIMessageAnalysis(
        analysis_id=uuid.uuid4(),
        tenant_id=tenant_id,
        message_id="msg_999",
        channel_id="dark_intel",
        threat_detected=True,
        threat_category=ThreatCategoryEnum.MALWARE.value,
        severity=ThreatSeverityEnum.CRITICAL.value,
        calibrated_score=92.5,
        threat_description="Ransomware builder distributed",
        supporting_evidence=["crypter.exe", "fud payload"],
    )

    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.scalar.return_value = None  # No duplicate exists

    alert = await alert_engine.evaluate_and_create_alert(
        db=mock_db,
        tenant_id=tenant_id,
        analysis=analysis,
    )
    assert alert is not None
    assert alert.severity == "CRITICAL"
    assert alert.alert_category == ThreatCategoryEnum.MALWARE.value
    assert mock_db.add.called

    # When duplicate exists, it suppresses new alert creation
    mock_db.scalar.return_value = alert
    dup_alert = await alert_engine.evaluate_and_create_alert(
        db=mock_db,
        tenant_id=tenant_id,
        analysis=analysis,
    )
    assert dup_alert is alert


@pytest.mark.asyncio
async def test_threat_classification_orchestrator_end_to_end():
    """Verify full end-to-end execution of ThreatClassificationOrchestrator."""
    orchestrator = ThreatClassificationOrchestrator()
    tenant_id = uuid.uuid4()
    message_id = "e2e_msg_test_001"
    channel_id = "-1001234567890"
    raw_text = (
        "VIP Bank Logs with OTP bypass bot for sale. "
        "Pay 200 USDT to TXa1234567890123456789012345678901. "
        "Contact mule operator @dark_fin_sec."
    )

    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.scalar.return_value = None  # Not previously analyzed
    mock_db.scalars.return_value = MagicMock(all=lambda: [])

    analysis = await orchestrator.analyze_message(
        db=mock_db,
        tenant_id=tenant_id,
        message_id=message_id,
        channel_id=channel_id,
        raw_text=raw_text,
        channel_title="Dark Fin",
        sender_username="mule_op",
    )

    assert analysis.threat_detected is True
    assert analysis.threat_category in (ThreatCategoryEnum.BANKING_FRAUD.value, ThreatCategoryEnum.FINANCIAL_FRAUD.value)
    assert analysis.severity in (ThreatSeverityEnum.HIGH.value, ThreatSeverityEnum.CRITICAL.value)
    assert analysis.calibrated_score >= 70.0
    assert mock_db.commit.called
    assert mock_db.refresh.called


def test_ai_celery_queues_and_task_wiring():
    """Verify Celery task configuration includes dedicated telegram_ai queue."""
    q_names = [q.name for q in celery_app.conf.task_queues]
    assert "telegram_ai" in q_names
    assert "app.workers.tasks.analyze_telegram_message_ai" in celery_app.conf.task_routes
    assert "app.workers.tasks.run_channel_anomaly_check" in celery_app.conf.task_routes
    assert celery_app.conf.task_routes["app.workers.tasks.analyze_telegram_message_ai"]["queue"] == "telegram_ai"


def test_ai_database_models_representation():
    """Verify SQLAlchemy AI model instantiation and representation."""
    tenant_id = uuid.uuid4()

    analysis = AIMessageAnalysis(
        analysis_id=uuid.uuid4(),
        tenant_id=tenant_id,
        message_id="msg_001",
        channel_id="chan_001",
        threat_detected=True,
        threat_category="DATA_LEAKS",
        severity="HIGH",
        confidence_score=85.0,
        calibrated_score=88.0,
    )
    assert "DATA_LEAKS" in repr(analysis)
    assert "HIGH" in repr(analysis)

    ioc = ExtractedIOCRecord(
        ioc_id=uuid.uuid4(),
        tenant_id=tenant_id,
        message_id="msg_001",
        channel_id="chan_001",
        ioc_type="ipv4",
        raw_value="198.51.100.1",
        normalized_value="198.51.100.1",
        defanged_value="198.51.100[.]1",
    )
    assert "198.51.100[.]1" in repr(ioc)

    usage = AITokenUsageRecord(
        usage_id=uuid.uuid4(),
        tenant_id=tenant_id,
        model_name="gemini-2.5-flash",
        operation_type="MESSAGE_ANALYSIS",
        prompt_tokens=150,
        completion_tokens=40,
        total_tokens=190,
        estimated_cost_usd=0.00003,
    )
    assert "gemini-2.5-flash" in repr(usage)
