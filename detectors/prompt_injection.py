"""
Detects prompt injection patterns in OpenClaw skill instruction files.
Maps to OWASP ASI01 — Prompt Injection.
"""

import re
from .base import BaseDetector, Finding, Severity
from core.parser import Skill

# Patterns that attempt to override the agent's role, identity, or prior instructions.
INJECTION_PATTERNS: list[tuple[str, str, Severity]] = [
    # Role/identity hijacking
    (r"(?i)(ignore\s+(all\s+)?previous\s+instructions?)", "Ignore-previous-instructions directive", Severity.CRITICAL),
    (r"(?i)(disregard\s+(all\s+)?prior\s+instructions?)", "Disregard-prior-instructions directive", Severity.CRITICAL),
    (r"(?i)(you\s+are\s+now\s+(a\s+)?(?!an?\s+assistant)[^\n]{0,60})", "Role replacement attempt", Severity.HIGH),
    (r"(?i)(forget\s+(everything|all)\s+you\s+(know|were told))", "Memory wipe directive", Severity.HIGH),
    (r"(?i)(new\s+instructions?\s*:\s*)", "Inline instruction override", Severity.HIGH),
    (r"(?i)(system\s*prompt\s*override)", "System prompt override", Severity.CRITICAL),
    (r"(?i)(act\s+as\s+(a\s+)?(?!helpful)[^\n]{0,50})", "Persona hijack (act-as)", Severity.MEDIUM),
    # Exfiltration via injection
    (r"(?i)(send\s+(all|my|the)\s+(files?|keys?|tokens?|secrets?|credentials?)\s+to)", "Exfiltration instruction in prompt", Severity.CRITICAL),
    # Jailbreak patterns
    (r"(?i)(DAN\s*mode|do\s+anything\s+now)", "DAN jailbreak attempt", Severity.HIGH),
    (r"(?i)(developer\s+mode\s+enabled)", "Developer mode jailbreak", Severity.HIGH),
    (r"(?i)\[\s*SYSTEM\s*\]\s*:", "Fake system message injection", Severity.HIGH),
    # Invisible/unicode injection (zero-width chars used to hide instructions)
    (r"[\u200b\u200c\u200d\u2060\ufeff]", "Invisible Unicode characters (hidden injection)", Severity.HIGH),
]


class PromptInjectionDetector(BaseDetector):
    name = "prompt_injection"

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
            for pattern, title, severity in INJECTION_PATTERNS:
                for match in re.finditer(pattern, text):
                    line_num = text[: match.start()].count("\n") + 1
                    findings.append(Finding(
                        detector=self.name,
                        severity=severity,
                        title=title,
                        description=f"Potential prompt injection detected in `{filename}` at line {line_num}.",
                        evidence=match.group(0)[:120].strip(),
                        owasp_asi="ASI01 — Prompt Injection",
                        mitre_atlas="AML.T0051.000 — LLM Prompt Injection",
                        line=line_num,
                    ))

        return findings
