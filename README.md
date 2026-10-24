# KangSensor DLP CLI

> A local-first command-line Data Leakage Prevention (DLP) prototype designed to identify Indonesian PII, financial data, and credentials before accidental exposure.

## What this project does

KangSensor scans files, watches directories, monitors clipboard content, and records detections in an audit trail. It uses a built-in YAML rule library to recognize sensitive patterns—such as NIK, NPWP, bank-account numbers, payment-card numbers, API keys, private keys, and tokens—then applies a configurable action.

The project is intended as a security and compliance-assistance prototype; it does not claim to replace a certified enterprise DLP product.

## Core functions

- On-demand scanning of individual files or directories.
- Continuous file watching for newly created or changed content.
- Clipboard inspection on the local machine.
- YAML-based detection rules with regex and validation logic.
- Configurable `log`, `alert`, and `quarantine` actions.
- SQLite audit log protected by a tamper-evident SHA-256 hash chain.
- File-integrity baseline creation and verification.

## Architecture

```text
Files / directories / clipboard
  │
  ▼
Sensors
  ├── FileSensor
  └── ClipboardSensor
  │
  ▼
EventBus → RuleEngine → RuleLibrary (YAML rules + validators)
  │
  ▼
Action dispatcher
  ├── LogAction        → SQLite audit trail
  ├── AlertAction      → local notification
  └── QuarantineAction → safe local directory
```

## Technology

- Python 3.10+
- Watchdog, Pyperclip, Click, Rich, and PyYAML
- SQLite for audit data
- Optional document readers for PDF, DOCX, and XLSX

## Run locally

```bash
cd kangsensor
python -m venv .venv
.venv\Scripts\activate
pip install -e .

kangsensor scan ./sample.txt
kangsensor watch ~/Documents --policy default
kangsensor rules list
```

## Repository layout

```text
kangsensor/
├── kangsensor/        # Sensors, engine, actions, audit, and rule code
├── config/            # Default policy configuration
├── tests/             # Unit tests and non-production sample data
└── pyproject.toml     # Package metadata and dependencies
```

## Safety and compliance note

Run only with appropriate authorization and respect employee privacy, data-protection obligations, and local policy. The planned network egress capability is passive/read-only; the project does not intercept, block, or modify network traffic. Detection results require human review and do not constitute compliance certification.
