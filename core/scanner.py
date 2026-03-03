"""
Orchestrates all detectors against one or more skill directories.
"""

from pathlib import Path
from dataclasses import dataclass, field

from core.parser import Skill, SkillParseError
from detectors.base import Finding, Severity
from detectors.prompt_injection import PromptInjectionDetector
from detectors.credential_theft import CredentialTheftDetector
from detectors.exfiltration import ExfiltrationDetector
from detectors.obfuscation import ObfuscationDetector
from detectors.permissions import PermissionsDetector
from detectors.typosquatting import TyposquattingDetector

SEVERITY_SCORE = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

ALL_DETECTORS = [
    PromptInjectionDetector(),
    CredentialTheftDetector(),
    ExfiltrationDetector(),
    ObfuscationDetector(),
    PermissionsDetector(),
    TyposquattingDetector(),
]


@dataclass
class SkillResult:
    skill: Skill
    findings: list[Finding] = field(default_factory=list)
    parse_error: str = ""

    @property
    def risk_score(self) -> int:
        return sum(SEVERITY_SCORE.get(f.severity, 0) for f in self.findings)

    @property
    def risk_label(self) -> str:
        score = self.risk_score
        if score == 0:
            return "CLEAN"
        if score <= 4:
            return "LOW"
        if score <= 10:
            return "MEDIUM"
        if score <= 20:
            return "HIGH"
        return "CRITICAL"

    @property
    def highest_severity(self) -> Severity | None:
        if not self.findings:
            return None
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for s in order:
            if any(f.severity == s for f in self.findings):
                return s
        return None


@dataclass
class ScanSummary:
    results: list[SkillResult] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def flagged(self) -> int:
        return sum(1 for r in self.results if r.findings)

    @property
    def clean(self) -> int:
        return self.total - self.flagged

    @property
    def critical_count(self) -> int:
        return sum(1 for r in self.results if r.highest_severity == Severity.CRITICAL)


def scan_skill(skill_path: Path) -> SkillResult:
    try:
        skill = Skill(skill_path)
    except SkillParseError as e:
        result = SkillResult(skill=None, parse_error=str(e))  # type: ignore[arg-type]
        return result

    findings: list[Finding] = []
    for detector in ALL_DETECTORS:
        try:
            findings.extend(detector.run(skill))
        except Exception as e:
            # Detector failures should not crash the whole scan
            findings.append(Finding(
                detector=detector.name,
                severity=Severity.INFO,
                title=f"Detector error: {detector.name}",
                description=str(e),
            ))

    return SkillResult(skill=skill, findings=findings)


def scan_directory(target: Path, recursive: bool = False) -> ScanSummary:
    """
    Scan a directory for OpenClaw skills.
    - If recursive=False, treats `target` itself as a single skill.
    - If recursive=True, treats each immediate subdirectory as a separate skill.
    """
    summary = ScanSummary()

    if not target.exists():
        summary.errors.append((str(target), "Path does not exist"))
        return summary

    if recursive:
        skill_dirs = [d for d in sorted(target.iterdir()) if d.is_dir()]
        if not skill_dirs:
            # Maybe target IS the skill
            skill_dirs = [target]
    else:
        skill_dirs = [target]

    for skill_dir in skill_dirs:
        result = scan_skill(skill_dir)
        if result.parse_error:
            summary.errors.append((str(skill_dir), result.parse_error))
        else:
            summary.results.append(result)

    return summary
