"""
Detects excessive or dangerous permission declarations in skill manifests.
Maps to OWASP ASI06 — Excessive Permissions / Privilege Escalation.
"""

from .base import BaseDetector, Finding, Severity
from core.parser import Skill

# Permissions that are high-risk on their own
HIGH_RISK_PERMISSIONS = {"shell", "filesystem", "browser"}

# Combinations that together are especially dangerous
DANGEROUS_COMBOS = [
    ({"network", "shell"}, "Network + Shell: can download and execute arbitrary code"),
    ({"network", "filesystem"}, "Network + Filesystem: can exfiltrate local files"),
    ({"shell", "filesystem"}, "Shell + Filesystem: can read/write/delete files via shell"),
    ({"network", "shell", "filesystem"}, "Full triad (Network+Shell+Filesystem): maximum exfil risk"),
]


class PermissionsDetector(BaseDetector):
    name = "permissions"

    def run(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []
        perms = set(skill.permissions)

        if not perms:
            return findings

        # Flag individual high-risk permissions
        for perm in perms & HIGH_RISK_PERMISSIONS:
            findings.append(Finding(
                detector=self.name,
                severity=Severity.MEDIUM,
                title=f"High-risk permission declared: `{perm}`",
                description=f"The skill requests `{perm}` permission. Verify this is strictly necessary.",
                evidence=f"permissions: {sorted(perms)}",
                owasp_asi="ASI06 — Excessive Permissions",
                mitre_atlas="AML.T0046 — Exfiltration Over Alternative Protocol",
            ))

        # Flag dangerous combinations
        for combo, reason in DANGEROUS_COMBOS:
            if combo.issubset(perms):
                findings.append(Finding(
                    detector=self.name,
                    severity=Severity.HIGH,
                    title="Dangerous permission combination",
                    description=reason,
                    evidence=f"permissions: {sorted(perms)}",
                    owasp_asi="ASI06 — Excessive Permissions",
                    mitre_atlas="AML.T0046",
                ))

        # Wildcard / all permissions
        if "*" in perms or "all" in perms:
            findings.append(Finding(
                detector=self.name,
                severity=Severity.CRITICAL,
                title="Wildcard/all permissions requested",
                description="The skill requests unrestricted permissions — a strong indicator of malicious intent.",
                evidence=f"permissions: {sorted(perms)}",
                owasp_asi="ASI06 — Excessive Permissions",
                mitre_atlas="AML.T0046",
            ))

        return findings
