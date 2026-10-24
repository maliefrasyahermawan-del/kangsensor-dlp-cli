# KangSensor — Data Leakage Prevention CLI

> **Lightweight, local-only DLP tool tuned for Indonesian PII and UU PDP compliance.**

KangSensor scans files, monitors your clipboard, and watches directories for
sensitive data (NIK, NPWP, credit cards, API keys, …) before it leaks.
No cloud, no telemetry — all processing stays on your machine.

> **DISCLAIMER (Network Sensor)**  
> The planned network egress sensor operates in **read-only / passive mode**.
> KangSensor does **not** intercept, block, or modify any network traffic.
> It reads packet headers or proxy logs only. No MITM, no kernel module required.

---

## Built-in Rule Library

| Rule ID | Name | Severity | Confidence Base |
|---|---|---|---|
| `ID_NIK` | Nomor Induk Kependudukan (KTP) | HIGH | 70 |
| `ID_NPWP` | Nomor Pokok Wajib Pajak | HIGH | 90 |
| `ID_KK` | Nomor Kartu Keluarga | HIGH | 65 |
| `ID_BPJS_KES` | Nomor BPJS Kesehatan | MEDIUM | 60 |
| `ID_PASPOR` | Nomor Paspor Indonesia | HIGH | 75 |
| `FIN_CC_VISA` | Visa Credit Card | CRITICAL | 80 |
| `FIN_CC_MASTERCARD` | Mastercard | CRITICAL | 80 |
| `FIN_CC_AMEX` | American Express | CRITICAL | 80 |
| `FIN_REKENING_BCA` | Rekening BCA (10 digit) | HIGH | 55 |
| `FIN_REKENING_MANDIRI` | Rekening Mandiri (13 digit) | HIGH | 55 |
| `FIN_REKENING_BRI` | Rekening BRI (15 digit) | HIGH | 55 |
| `CRED_AWS_ACCESS_KEY` | AWS Access Key ID | CRITICAL | 95 |
| `CRED_AWS_SECRET_KEY` | AWS Secret Access Key | CRITICAL | 90 |
| `CRED_PRIVATE_KEY` | PEM Private Key | CRITICAL | 99 |
| `CRED_GITHUB_TOKEN` | GitHub PAT | CRITICAL | 95 |
| `CRED_GOOGLE_API_KEY` | Google API Key | CRITICAL | 95 |
| `CRED_SLACK_TOKEN` | Slack Token | CRITICAL | 95 |
| `CRED_JWT` | JSON Web Token | HIGH | 85 |
| `CRED_GENERIC_SECRET` | Generic Password Assignment | HIGH | 60 |
| `CRED_DB_CONN_STRING` | Database Connection String | HIGH | 85 |
| `PII_EMAIL` | Email Address | LOW | 80 |
| `PII_PHONE_ID` | Nomor HP Indonesia | MEDIUM | 80 |
| `PII_SSN_US` | US Social Security Number | HIGH | 85 |
| `PII_DOB` | Date of Birth | MEDIUM | 60 |
| `PII_ADDRESS_ID` | Alamat Indonesia | LOW | 55 |

**Total: 25 built-in rules** across 4 categories.

---

## Installation

```bash
# Clone
git clone https://github.com/<your-org>/kangsensor.git
cd kangsensor

# Install (editable)
pip install -e .

# Verify
kangsensor --version
kangsensor rules list
```

### Optional extras

```bash
pip install yara-python   # Yara rule support (future)
pip install pypdf         # PDF text extraction
pip install python-docx   # DOCX extraction
pip install openpyxl      # XLSX extraction
```

---

## Quick Start

### 1. One-shot file scan

```bash
# Scan a single file
kangsensor scan /tmp/data.txt

# Scan a directory with all rules, save JSON report
kangsensor scan ~/Documents --rules all --output report.json

# Scan only Indonesian PII rules
kangsensor scan ~/Downloads --rules id_indonesia,financial
```

### 2. Watch a directory (continuous)

```bash
kangsensor watch ~/Documents --policy default
```

Press **Ctrl-C** to stop.

### 3. Test a text string

```bash
kangsensor rules test "NIK saya 3273011234567890"
```

### 4. Daemon mode (all sensors)

```bash
kangsensor daemon start          # starts in background
kangsensor daemon status
kangsensor daemon stop
```

### 5. Audit log

```bash
kangsensor audit show --limit 20
kangsensor audit show --since 2024-01-01
kangsensor audit verify          # tamper-evident chain check
```

### 6. File integrity baseline

```bash
# Create baseline
kangsensor baseline create ~/Documents

# Verify later (shows added/removed/modified)
kangsensor baseline verify ~/Documents
```

---

## Configuration

Default config: `config/default.yaml`  
User config: `~/.kangsensor/config.yaml` (overrides default)

```yaml
sensors:
  file:
    enabled: true
    paths: ["~/Documents", "~/Desktop"]
  clipboard:
    enabled: true
    poll_ms: 500

policies:
  default:
    ID_NIK: alert          # desktop notification + audit log
    CRED_PRIVATE_KEY: quarantine   # move to ~/.kangsensor/quarantine/
    CRED_AWS_ACCESS_KEY: quarantine
    PII_EMAIL: log         # audit log only

audit:
  db_path: "~/.kangsensor/audit.db"
  retention_days: 90
```

Policy actions: `log` | `alert` | `quarantine`

---

## Architecture

```
KangSensor Daemon
├── Sensors
│   ├── FileSensor (watchdog)
│   └── ClipboardSensor (pyperclip poll)
├── EventBus (pub-sub)
├── RuleEngine
│   └── RuleLibrary (YAML → compiled regex + validators)
├── ActionDispatcher
│   ├── LogAction    → SQLite audit log (hash chain)
│   ├── AlertAction  → desktop notification (plyer)
│   └── QuarantineAction → move file to safe dir
└── AuditLog (append-only, SHA-256 hash chain)
```

---

## Compliance Note

KangSensor is a **tool to assist compliance** with UU PDP (Undang-Undang
Pelindungan Data Pribadi No. 27 Tahun 2022). It is **not a certified
compliance product** and does not guarantee exhaustive detection of all
regulated data. Organizations seeking formal compliance certification must
engage an accredited auditor.

This tool is designed to support:
- Data mapping and discovery (Pasal 20–22 UU PDP)
- Technical safeguards for personal data (Pasal 35 UU PDP)
- Security incident detection and logging

---

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

---

## License

MIT — see `LICENSE`.

Built for **MBC Lab, Telkom University** — Cybersecurity Research Group.
