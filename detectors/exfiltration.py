"""
Detects data exfiltration patterns in OpenClaw skills:
- Suspicious outbound URLs / IPs
- Reverse shell commands
- File upload instructions
Maps to OWASP ASI05 — Excessive Agency / Unauthorised Data Exfiltration.
"""

import re
from .base import BaseDetector, Finding, Severity
from core.parser import Skill

SUSPICIOUS_DOMAINS = [
    r"(?i)(ngrok\.io)",
    r"(?i)(requestbin\.com|webhook\.site|pipedream\.net)",
    r"(?i)(transfer\.sh|file\.io|0x0\.st)",
    r"(?i)(pastebin\.com|hastebin\.com|ghostbin\.com)",
    r"(?i)(burpcollaborator\.net)",
    r"(?i)(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b)",  # raw IP:port
]

REVERSE_SHELL_PATTERNS: list[tuple[str, str, Severity]] = [
    (r"(?i)(bash\s+-i\s+>&?\s*/dev/tcp/)", "Bash reverse shell", Severity.CRITICAL),
    (r"(?i)(nc\s+-e\s+/bin/(bash|sh))", "Netcat reverse shell", Severity.CRITICAL),
    (r"(?i)(python\s+-c\s+.{0,30}socket\.connect)", "Python reverse shell", Severity.CRITICAL),
    (r"(?i)(rm\s+/tmp/f;mkfifo)", "Named pipe reverse shell", Severity.CRITICAL),
    (r"(?i)(socat\s+TCP:)", "Socat reverse shell", Severity.CRITICAL),
    (r"(?i)(/bin/sh\s+-i)", "Interactive shell spawn", Severity.HIGH),
]

EXFIL_PATTERNS: list[tuple[str, str, Severity]] = [
    (r"(?i)(curl\s+.{0,60}(-d\s+|--data\s+))", "curl POST (potential data exfil)", Severity.MEDIUM),
    (r"(?i)(wget\s+.{0,60}--post-data)", "wget POST data exfil", Severity.HIGH),
    (r"(?i)(fetch\(\s*['\"]https?://[^'\"]{5,})", "fetch() to external URL in source", Severity.MEDIUM),
    (r"(?i)(axios\.(post|put)\s*\(\s*['\"]https?://[^'\"]{5,})", "axios POST to external URL", Severity.MEDIUM),
    (r"(?i)(upload\s+(all\s+)?(files?|documents?|screenshots?)\s+to)", "File upload instruction", Severity.HIGH),
    (r"(?i)(exfiltrat)", "Explicit exfiltration keyword", Severity.HIGH),
    (r"(?i)(zip\s+.{0,40}&&\s*curl)", "Zip-and-upload pattern", Severity.CRITICAL),
]


class ExfiltrationDetector(BaseDetector):
    name = "exfiltration"

    def run(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []

        sources = [
            ("instructions.md", skill.instructions),
            ("README.md", skill.readme),
        ]
        sources += [(fname, content) for fname, content in skill.source_files]

        suspicious_domain_patterns: list[tuple[str, str, Severity]] = [
            (p, "Suspicious/C2 domain or raw IP:port reference", Severity.HIGH)
            for p in SUSPICIOUS_DOMAINS
        ]
        all_patterns = REVERSE_SHELL_PATTERNS + EXFIL_PATTERNS + suspicious_domain_patterns

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
                        description=f"Data exfiltration / C2 pattern found in `{filename}` at line {line_num}.",
                        evidence=match.group(0)[:120].strip(),
                        owasp_asi="ASI05 — Excessive Agency",
                        mitre_atlas="AML.T0048 — Exfiltration via Cyber Means",
                        line=line_num,
                    ))

        return findings
