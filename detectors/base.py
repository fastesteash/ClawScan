"""Base class for all detectors."""

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.parser import Skill


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    detector: str
    severity: Severity
    title: str
    description: str
    evidence: str = ""
    owasp_asi: str = ""
    mitre_atlas: str = ""
    line: int = 0


class BaseDetector:
    name: str = "base"

    def run(self, skill: "Skill") -> list[Finding]:
        raise NotImplementedError
