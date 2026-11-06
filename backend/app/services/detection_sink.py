"""Detection sink implementations for emitting threat detections."""

import logging
from typing import Any, Dict
from app.services.protocols import DetectionSink

logger = logging.getLogger("tti.detection.sink")


class LoggingDetectionSink(DetectionSink):
    """Reference logging detection sink that records threat detection events structured in logs."""

    def __init__(self) -> None:
        self.emitted_count = 0

    async def emit(self, detection: Any) -> None:
        """Emit threat detection event to structured logs."""
        self.emitted_count += 1
        
        # Extract attributes whether detection is an object or dictionary
        if isinstance(detection, dict):
            category = detection.get("category")
            severity = detection.get("severity")
            stance = detection.get("stance")
            rule_confidence = detection.get("rule_confidence")
            message_id = detection.get("message_id")
            tenant_id = str(detection.get("tenant_id"))
        else:
            category = getattr(detection, "category", "unknown")
            severity = getattr(detection, "severity", "UNKNOWN")
            stance = getattr(detection, "stance", "unknown")
            rule_confidence = getattr(detection, "rule_confidence", 0.0)
            message_id = getattr(detection, "message_id", "unknown")
            tenant_id = str(getattr(detection, "tenant_id", "unknown"))

        logger.info(
            "Threat detection emitted: tenant=%s category=%s severity=%s stance=%s confidence=%.2f message_id=%s",
            tenant_id,
            category,
            severity,
            stance,
            rule_confidence,
            message_id,
            extra={
                "detection_tenant_id": tenant_id,
                "detection_category": category,
                "detection_severity": severity,
                "detection_stance": stance,
                "detection_confidence": rule_confidence,
                "detection_message_id": message_id,
            },
        )
