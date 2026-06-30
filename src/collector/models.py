"""
Data models for the collector.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class ConfigEntry:
    """Represents a single parsed and classified proxy config."""

    protocol: str
    uri: str
    secure: bool
    reasons: List[str] = field(default_factory=list)
    original: str = ""

    def to_dict(self) -> dict:
        return {
            "protocol": self.protocol,
            "uri": self.uri,
            "secure": self.secure,
            "reasons": self.reasons,
            "original": self.original,
        }
