"""Queue adapters package."""

from app.adapters.queue.celery_dispatcher import CeleryTaskDispatcher
from app.adapters.queue.inline_dispatcher import InlineTaskDispatcher

__all__ = ["CeleryTaskDispatcher", "InlineTaskDispatcher"]
