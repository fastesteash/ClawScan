# ClawScan

**ClawScan** is a static-analysis security scanner for [OpenClaw](https://github.com/openclaw/openclaw) skill packages. It detects malicious patterns inspired by the real-world **ClawHavoc** supply chain attack (early 2026), in which over 1,100 trojanized skills were uploaded to the ClawHub marketplace and installed by thousands of users.

> Built as a cybersecurity portfolio project demonstrating AI agent supply chain security, mapped to **OWASP Agentic Security Initiative (ASI) Top 10** and **MITRE ATLAS**.

---

## What It Detects

| Detector | What It Finds | OWASP ASI |
|---|---|---|
| **Prompt Injection** | Role hijacking, instruction overrides, invisible Unicode characters | ASI01 |
| **Credential Theft** | Instructions to read/exfiltrate API keys, config files, tokens | ASI02 |
| **Exfiltration** | Reverse shells, suspicious domains, curl/wget POST patterns | ASI05 |
| **Obfuscation** | Base64 payloads, eval(), hex strings, string splitting | ASI03 |
| **Excessive Permissions** | Dangerous permission combinations in manifests | ASI06 |
| **Typosquatting** | Levenshtein-distance matching against 25 popular skills | ASI03 |

---

## Quick Start

Requires **Python 3.8+**

```bash
# Clone the repository
git clone https://github.com/fastesteash/ClawScan.git
cd ClawScan

# Install dependencies
pip install -r requirements.txt

# Scan a single skill directory
python scanner.py tests/malicious_samples/fake-calendar-sync --verbose

# Scan an entire skill registry (each subdirectory = one skill)
python scanner.py tests/malicious_samples --all --verbose --only-flagged

# Export results as JSON
python scanner.py tests/malicious_samples --all --json report.json

# Scan skills you've downloaded from ClawHub
python scanner.py ~/.openclaw/workspace/skills --all --verbose

# Scan OpenClaw's built-in bundled skills
python scanner.py ~/.npm-global/lib/node_modules/openclaw/skills --all --verbose
```

---

## Example Output

```
ClawScan scanning tests/malicious_samples...

╭──────────────────────┬──────────┬───────┬──────────┬──────────────╮
│ Skill                │  Risk    │ Score │ Findings │ Top Severity │
├──────────────────────┼──────────┼───────┼──────────┼──────────────┤
│ fake-calendar-sync   │ CRITICAL │   61  │    7     │  CRITICAL    │
│ fake-news-digest     │ CRITICAL │   55  │    6     │  CRITICAL    │
╰──────────────────────┴──────────┴───────┴──────────┴──────────────╯

  Scanned: 2  Clean: 0  Flagged: 2  Critical: 2
```

---

## Project Structure

```
clawscan/
├── scanner.py              # CLI entry point
├── core/
│   ├── parser.py           # Parses claw.json / skill.yaml + instruction files
│   ├── scanner.py          # Orchestrates detectors, produces ScanSummary
│   └── report.py           # Rich terminal output + JSON export
├── detectors/
│   ├── base.py             # Finding dataclass and BaseDetector
│   ├── prompt_injection.py
│   ├── credential_theft.py
│   ├── exfiltration.py
│   ├── obfuscation.py
│   ├── permissions.py
│   └── typosquatting.py
├── tests/
│   ├── malicious_samples/  # Realistic malicious skill examples
│   └── benign_samples/     # Known-clean skills (should produce 0 findings)
└── requirements.txt
```

---

## Threat Model

ClawScan's detection rules are derived from the following sources:

- [ClawHavoc Supply Chain Attack Report](https://openclawconsult.com/lab/openclaw-clawhavoc-supply-chain)
- [Adversa AI — OpenClaw Threat Model](https://adversa.ai/blog/openclaw-threat-model-mapped-owasp-mitre/)
- [OWASP Agentic Security Initiative Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [MITRE ATLAS](https://atlas.mitre.org/)

---

## Risk Scoring

Each finding contributes to a cumulative risk score:

| Severity | Score |
|---|---|
| CRITICAL | 10 |
| HIGH | 7 |
| MEDIUM | 4 |
| LOW | 1 |
| INFO | 0 |

Final risk label: `CLEAN` (0) · `LOW` (1–4) · `MEDIUM` (5–10) · `HIGH` (11–20) · `CRITICAL` (>20)

---

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | All scanned skills are clean |
| 1 | One or more skills have findings |
| 2 | One or more skills have CRITICAL findings |

This makes ClawScan suitable for use in CI/CD pipelines to gate skill installations.

---

## Limitations

- Static analysis only — does not execute skills or perform dynamic analysis
- Regex-based detection can produce false positives; findings should be reviewed manually
- Typosquatting detection is limited to the 25 most-downloaded skills; extend `KNOWN_GOOD_SKILLS` in `detectors/typosquatting.py` as needed

---

## Author

Built by Eashan Patel as a cybersecurity portfolio project exploring AI agent security.

---

## License

MIT License © 2026 Eashan Patel
