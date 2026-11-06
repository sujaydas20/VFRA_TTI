"""Data transfer schemas for dark-web marketplace and forum content."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DarkWebThreadItem(BaseModel):
    """Post or comment inside a dark-web forum topic."""
    post_id: str
    author_alias: str
    post_timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_content: str
    quoted_post_id: Optional[str] = None


class DarkWebPagePayload(BaseModel):
    """Raw page structure scraped from an onion forum or leak site."""
    page_id: str
    onion_url: str
    site_title: Optional[str] = None
    category: str = "forum"  # forum, marketplace, paste, ransomware_leak
    captured_at_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_html: str = ""
    extracted_text: str = ""
    thread_items: List[DarkWebThreadItem] = Field(default_factory=list)
    proxy_routed_via: Optional[str] = None
    extra_metadata: Dict[str, Any] = Field(default_factory=dict)
