"""Structured logging configuration for TTI."""

import logging
import sys
from app.core.config import get_settings


def setup_logging() -> logging.Logger:
    """Configure system-wide logging with uniform formatting."""
    settings = get_settings()
    log_level = getattr(logging, settings.TTI_LOG_LEVEL.upper(), logging.INFO)

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] [%(name)s] [tenant:%(tenant_id)s] %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )

    # Provide fallback for %(tenant_id)s if omitted in log calls
    old_factory = logging.getLogRecordFactory()

    def record_factory(*args, **kwargs):
        record = old_factory(*args, **kwargs)
        if not hasattr(record, "tenant_id"):
            record.tenant_id = "system"
        return record

    logging.setLogRecordFactory(record_factory)

    logger = logging.getLogger("tti")
    logger.setLevel(log_level)
    return logger
