"""Untrusted ingestion processing pipeline."""

import hashlib
import json
from uuid import UUID
from app.core.errors import TenantAccessError
from app.ingestion.sanitizer import InputSanitizer
from app.ingestion.schemas import NormalizedIntelligenceItem, RawIngestEnvelope


class IngestionPipeline:
    """Processes untrusted raw intelligence payloads into normalized, safe records."""

    @classmethod
    def process_envelope(cls, envelope: RawIngestEnvelope) -> NormalizedIntelligenceItem:
        """
        Process an incoming raw payload envelope through validation, hashing, and sanitization.
        """
        # 1. Enforce tenant isolation validation
        try:
            _ = UUID(envelope.tenant_id)
        except ValueError:
            raise TenantAccessError(f"Invalid tenant UUID format: {envelope.tenant_id}")

        # 2. Compute immutable cryptographic SHA-256 hash of original raw payload
        raw_bytes = json.dumps(envelope.raw_payload, sort_keys=True).encode("utf-8")
        content_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        # 3. Extract text content based on source type
        raw_text = ""
        external_id = "unknown"
        title = "Untitled Thread"
        author = None

        if envelope.source_type == "telegram":
            raw_text = str(envelope.raw_payload.get("raw_text", ""))
            external_id = str(envelope.raw_payload.get("message_id", "0"))
            author = envelope.raw_payload.get("sender_username")
            title = envelope.raw_payload.get("channel_title", f"Telegram Channel {envelope.source_reference}")
        elif envelope.source_type == "darkweb":
            raw_text = str(envelope.raw_payload.get("raw_html") or envelope.raw_payload.get("extracted_text", ""))
            external_id = str(envelope.raw_payload.get("page_id", "dw_page"))
            title = str(envelope.raw_payload.get("site_title", f"DarkWeb Target {envelope.source_reference}"))
        else:
            raw_text = str(envelope.raw_payload)

        # 4. Execute input sanitization
        sanitized_text, applied_actions = InputSanitizer.sanitize_text(raw_text)

        # 5. Sanitize title and author fields as well
        sanitized_title, _ = InputSanitizer.sanitize_text(title)
        sanitized_author, _ = InputSanitizer.sanitize_text(author) if author else (None, [])

        return NormalizedIntelligenceItem(
            tenant_id=envelope.tenant_id,
            source_type=envelope.source_type,
            external_id=external_id,
            title=sanitized_title or "Sanitized Untitled Thread",
            sanitized_text=sanitized_text,
            content_sha256=content_sha256,
            author_identifier=sanitized_author,
            captured_at_utc=envelope.captured_at_utc,
            sanitization_applied=applied_actions,
            metadata={
                "source_reference": envelope.source_reference,
                "raw_byte_size": len(raw_bytes),
            },
        )
