"""
Detects credential harvesting patterns in OpenClaw skills.
Looks for instructions or code that access, read, or transmit API keys,
tokens, and secrets stored by OpenClaw.
Maps to OWASP ASI02 — Sensitive Data Exposure / Credential Theft.
"""

import re
from .base import BaseDetector, Finding, Severity
from core.parser import Skill

# Known OpenClaw config file paths containing credentials
SENSITIVE_PATHS = [
    r"(?i)(~\/\.openclaw\/config\.json)",
    r"(?i)(~\/\.openclaw\/credentials)",
    r"(?i)(openclaw[_\-]?config)",
    r"(?i)(\.env\b)",
    r"(?i)(secrets\.json|secrets\.yaml)",
]

# Instructions telling the agent to read or send credentials
HARVEST_PATTERNS: list[tuple[str, str, Severity]] = [
    (r"(?i)(read\s+(the\s+)?(api\s+key|token|secret|password|credential))", "Credential read instruction", Severity.HIGH),
    (r"(?i)(cat\s+~\/\.openclaw)", "Shell read of OpenClaw config dir", Severity.CRITICAL),
    (r"(?i)(extract\s+(the\s+)?(api\s+key|auth\s+token|bearer\s+token))", "Token extraction instruction", Severity.HIGH),
    (r"(?i)(send\s+(me|us|the\s+attacker)\s+(your\s+)?(key|token|secret|password))", "Direct credential exfil", Severity.CRITICAL),
    (r"(?i)(process\.env\.[A-Z_]{3,})", "process.env access in source", Severity.MEDIUM),
    (r"(?i)(os\.environ\[)", "os.environ access in source", Severity.MEDIUM),
    (r"(?i)(Bearer\s+\$?\{?[A-Za-z_][A-Za-z0-9_]*\}?)", "Hardcoded Bearer token reference", Severity.HIGH),
    # Regex that matches real-looking API key formats being referenced
    (r"(?i)(sk-[A-Za-z0-9]{20,})", "Hardcoded OpenAI-style API key", Severity.CRITICAL),
    (r"(?i)(xoxb-[0-9]+-[A-Za-z0-9-]+)", "Hardcoded Slack bot token", Severity.CRITICAL),
    (r"(?i)(ghp_[A-Za-z0-9]{36})", "Hardcoded GitHub personal access token", Severity.CRITICAL),
]

# Suspicious path access
SENSITIVE_PATH_PATTERNS: list[tuple[str, str, Severity]] = [
    (path, "Access to sensitive OpenClaw config/credential path", Severity.HIGH)
    for path in SENSITIVE_PATHS
]


class CredentialTheftDetector(BaseDetector):
    name = "credential_theft"

    def run(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []

        sources = [
            ("instructions.md", skill.instructions),
            ("README.md", skill.readme),
        ]
        sources += [(fname, content) for fname, content in skill.source_files]

        all_patterns = HARVEST_PATTERNS + SENSITIVE_PATH_PATTERNS

        for filename, text in sources:
            if not text:
                continue
            for pattern, title, severity in all_patterns:
                for match in re.finditer(pattern, text):
                    line_num = text[: match.start()].count("\n") + 1
                    findings.append(Finding(
                        detector=self.name,
                        severity=severity,
                        title=title,
                        description=f"Credential theft pattern detected in `{filename}` at line {line_num}.",
                        evidence=match.group(0)[:120].strip(),
                        owasp_asi="ASI02 — Sensitive Information Disclosure",
                        mitre_atlas="AML.T0056 — Exfiltration via ML Model",
                        line=line_num,
                    ))

        return findings
