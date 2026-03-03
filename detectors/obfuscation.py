"""
Detects obfuscation techniques used in malicious OpenClaw skills:
- Base64-encoded payloads
- Hex-encoded strings
- eval() / exec() of dynamic strings
- Unicode homoglyph substitution
Maps to OWASP ASI01 / ASI03 — Prompt Injection & Supply Chain.
"""

import re
import base64
from .base import BaseDetector, Finding, Severity
from core.parser import Skill

# Minimum length for a base64 string to be suspicious (avoids short coincidental matches)
B64_MIN_LEN = 40

OBFUSCATION_PATTERNS: list[tuple[str, str, Severity]] = [
    # Dynamic execution
    (r"(?i)\beval\s*\(", "eval() call in source", Severity.HIGH),
    (r"(?i)\bexec\s*\(\s*base64", "exec(base64...) obfuscated execution", Severity.CRITICAL),
    (r"(?i)Function\s*\(\s*['\"]return\s+require", "Function constructor abuse", Severity.HIGH),
    # Encoded payloads
    (r"(?i)echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64\s+-d", "Shell base64 decode-and-pipe", Severity.CRITICAL),
    (r"(?i)base64\s*(-d|--decode)", "base64 decode command", Severity.HIGH),
    (r"(?i)\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){8,}", "Long hex-encoded string", Severity.HIGH),
    # String splitting to evade simple grep
    (r"(?i)(['\"][a-z]{1,4}['\"]\s*\+\s*['\"][a-z]{1,4}['\"]\s*\+\s*['\"][a-z]{1,4}['\"])", "String concatenation obfuscation", Severity.LOW),
    # Homoglyph / confusable unicode (Cyrillic lookalikes in latin context)
    (r"[аеіорсух]", "Cyrillic homoglyph character (possible lookalike attack)", Severity.MEDIUM),
]


def _looks_like_base64_payload(s: str) -> bool:
    """Return True if a long base64 string decodes to something executable-looking."""
    try:
        decoded = base64.b64decode(s + "==").decode("utf-8", errors="replace")
        suspicious_keywords = ["bash", "curl", "wget", "eval", "/bin/sh", "socket", "exec", "import os"]
        return any(kw in decoded.lower() for kw in suspicious_keywords)
    except Exception:
        return False


class ObfuscationDetector(BaseDetector):
    name = "obfuscation"

    def run(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []

        sources = [
            ("instructions.md", skill.instructions),
            ("README.md", skill.readme),
        ]
        sources += [(fname, content) for fname, content in skill.source_files]

        for filename, text in sources:
            if not text:
                continue

            for pattern, title, severity in OBFUSCATION_PATTERNS:
                for match in re.finditer(pattern, text):
                    line_num = text[: match.start()].count("\n") + 1
                    findings.append(Finding(
                        detector=self.name,
                        severity=severity,
                        title=title,
                        description=f"Obfuscation technique detected in `{filename}` at line {line_num}.",
                        evidence=match.group(0)[:120].strip(),
                        owasp_asi="ASI03 — Supply Chain Vulnerabilities",
                        mitre_atlas="AML.T0020 — Poison Training Data",
                        line=line_num,
                    ))

            # Standalone base64 blob check
            for match in re.finditer(r"[A-Za-z0-9+/]{%d,}={0,2}" % B64_MIN_LEN, text):
                candidate = match.group(0)
                if _looks_like_base64_payload(candidate):
                    line_num = text[: match.start()].count("\n") + 1
                    findings.append(Finding(
                        detector=self.name,
                        severity=Severity.CRITICAL,
                        title="Base64 blob decodes to executable payload",
                        description=f"A base64 string in `{filename}` decodes to content containing executable keywords.",
                        evidence=candidate[:80] + "...",
                        owasp_asi="ASI03 — Supply Chain Vulnerabilities",
                        mitre_atlas="AML.T0020",
                        line=line_num,
                    ))

        return findings
