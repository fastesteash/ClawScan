"""
Detects typosquatting of well-known OpenClaw skills.
Uses Levenshtein distance to compare the skill name against a curated
list of popular/legitimate skills.
Maps to OWASP ASI03 — Supply Chain Vulnerabilities.
"""

from .base import BaseDetector, Finding, Severity
from core.parser import Skill

# Curated list of popular/official OpenClaw skills that attackers impersonate.
# Source: ClawHub top-downloaded skills + ClawHavoc attack report.
KNOWN_GOOD_SKILLS: list[str] = [
    "weather-checker",
    "calendar-sync",
    "news-digest",
    "gmail-assistant",
    "slack-notifier",
    "github-helper",
    "jira-tracker",
    "spotify-controller",
    "todoist-sync",
    "notion-assistant",
    "google-drive-sync",
    "twitter-poster",
    "linkedin-helper",
    "zoom-scheduler",
    "aws-monitor",
    "docker-manager",
    "kubectl-assistant",
    "code-reviewer",
    "crypto-tracker",
    "stock-watcher",
    "email-summarizer",
    "meeting-notes",
    "pdf-reader",
    "web-scraper",
    "file-organizer",
]

TYPOSQUAT_THRESHOLD = 2  # Levenshtein distance <= this is flagged


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def _normalize(name: str) -> str:
    return name.lower().replace("_", "-").replace(" ", "-").strip()


class TyposquattingDetector(BaseDetector):
    name = "typosquatting"

    def run(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []
        skill_name = _normalize(skill.name)

        # Exact match = legitimate, skip
        if skill_name in KNOWN_GOOD_SKILLS:
            return findings

        for known in KNOWN_GOOD_SKILLS:
            dist = _levenshtein(skill_name, known)
            if 0 < dist <= TYPOSQUAT_THRESHOLD:
                findings.append(Finding(
                    detector=self.name,
                    severity=Severity.HIGH,
                    title=f"Possible typosquat of `{known}`",
                    description=(
                        f"Skill name `{skill_name}` is {dist} character(s) away from the popular "
                        f"skill `{known}`. This matches the ClawHavoc naming pattern."
                    ),
                    evidence=f"{skill_name!r}  →  {known!r}  (distance={dist})",
                    owasp_asi="ASI03 — Supply Chain Vulnerabilities",
                    mitre_atlas="AML.T0018 — Trojan Model / Skill",
                ))

        return findings
