# 🔒 CSV Anonymizer

> **A privacy-preserving desktop tool for safely processing CSV datasets containing Personally Identifiable Information (PII).**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GDPR](https://img.shields.io/badge/Compliant-GDPR-blue)](https://gdpr.eu/)
[![HIPAA](https://img.shields.io/badge/Compliant-HIPAA-blueviolet)](https://www.hhs.gov/hipaa/)
[![PECA](https://img.shields.io/badge/Compliant-PECA%202016-orange)](http://na.gov.pk/uploads/documents/1470910659_707.pdf)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Screenshots & Workflow](#-workflow)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Processing Modes](#-processing-modes)
- [PII Types Supported](#-pii-types-supported)
- [Anonymization Techniques](#-anonymization-techniques)
- [Use-Case Profiles](#-use-case-profiles)
- [Output Files](#-output-files)
- [Compliance Framework](#-compliance-framework)
- [Project Structure](#-project-structure)
- [Dependencies](#-dependencies)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔍 Overview

**CSV Anonymizer** is a Python desktop application (built with Tkinter) that enables users to load CSV files containing sensitive personal data, automatically detect PII columns, apply configurable anonymization or pseudonymization techniques, and export a privacy-safe version of the dataset alongside a detailed compliance audit report.

The tool is designed for:
- **Researchers** who need to share datasets without exposing personal information
- **Developers** testing systems with realistic but non-identifiable data
- **Compliance officers** documenting data minimization procedures
- **Organizations** preparing datasets for third-party processing under GDPR, PECA, or HIPAA obligations

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔍 Auto PII Detection | Two-pass engine (header keywords + regex value sampling) detects 10+ PII types automatically |
| ✏️ Manual Override | Editable table to correct, add, or skip any column detection result |
| ⚙️ Dual Processing Mode | Choose **Irreversible Anonymization** or **Reversible Pseudonymization** |
| 🎭 5 Techniques | Masking, SHA-256 Hashing, Generalization, Fake Data Replacement, Null/Deletion |
| 📋 3 Use-Case Profiles | Academic/Research, Corporate/HR, Healthcare — auto-suggest technique defaults |
| 👁️ Live Preview | Before/After comparison of sample rows before any file is written |
| 📄 Audit Report | Auto-generated compliance report mapping every technique to GDPR/PECA/HIPAA articles |
| 🔑 Reversibility Key | JSON key file for pseudonymized data, with embedded security warnings |
| 🖥️ Responsive UI | Dark-themed 5-step wizard that adapts to any window size |
| 🔄 Full Session Reset | One-click "Start New Session" wipes all state and UI widgets cleanly |

---

## 🔄 Workflow

The application guides users through a **5-step wizard**:

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Step 1      │───▶│  Step 2      │───▶│  Step 3      │───▶│  Step 4      │───▶│  Step 5      │
│  Load CSV    │    │  Detect PII  │    │  Configure   │    │  Preview     │    │  Process &   │
│              │    │              │    │              │    │              │    │  Export      │
│  Browse file │    │  Auto-detect │    │  Mode/Profile│    │  Before/After│    │  Live log +  │
│  Preview 5   │    │  + manual    │    │  per-column  │    │  5 sample    │    │  result cards│
│  rows        │    │  override    │    │  techniques  │    │  rows        │    │              │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
```

**Step 5 outputs** (all timestamped):
- `anonymized_YYYYMMDD_HHMMSS.csv` — transformed dataset
- `audit_report_YYYYMMDD_HHMMSS.txt` — full compliance report
- `pseudo_key_YYYYMMDD_HHMMSS.json` — reversibility mapping (Pseudonymization mode only)

---

## 🏗️ Architecture

```
csv-anonymizer/
│
├── main.py              ← Entry point (launches Tkinter root window)
│
├── app.py               ← CSVAnonymizerApp class
│                           AppState (shared session data)
│                           Wizard navigation (5 steps)
│                           TTK dark theme setup
│                           reset_all_steps()
│
├── steps.py             ← All 5 wizard step frames
│   ├── BaseStep         ← Abstract base (on_enter, validate, reset)
│   ├── Step1Load        ← File browse + data preview Treeview
│   ├── Step2Detect      ← PII detection table + manual override
│   ├── Step3Configure   ← Mode/Profile selection + per-column dropdowns
│   ├── Step4Preview     ← Before/After split-panel comparison
│   └── Step5Finish      ← Processing log + results cards + actions
│
├── pii_detector.py      ← PII detection engine
│   ├── PII_DEFINITIONS  ← 10 PII types with regex patterns & defaults
│   ├── detect_by_header()  ← Keyword matching on column names
│   ├── detect_by_values()  ← Regex matching on sample cell values
│   └── detect_pii()     ← Main dispatcher (two-pass detection)
│
├── anonymizer.py        ← All transformation functions
│   ├── apply_masking()
│   ├── apply_hashing()
│   ├── apply_generalization()
│   ├── apply_fake_data()
│   ├── apply_deletion()
│   ├── apply_technique()   ← Central dispatcher
│   └── export_pseudo_key() ← JSON key file export
│
├── profiles.py          ← Use-case profile definitions
│   └── PROFILES         ← Academic/Research, Corporate/HR, Healthcare
│
├── audit.py             ← Audit report & compliance matrix
│   ├── TECHNIQUE_COMPLIANCE_MAP  ← Technique → GDPR/PECA/HIPAA mapping
│   └── generate_audit_report()
│
├── sample_data.csv      ← Test dataset with realistic PII
└── requirements.txt     ← pandas, faker
```

---

## 🛠️ Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Step 1 — Clone the Repository

```bash
git clone https://github.com/yourusername/csv-anonymizer.git
cd csv-anonymizer
```

### Step 2 — Install Dependencies

```bash
pip install -r requirements.txt
```

`requirements.txt` contains:
```
pandas>=1.3.0
faker>=13.0.0
```

> **Note:** `tkinter`, `hashlib`, `re`, `json`, `csv`, `datetime`, and `os` are all Python standard library modules — no additional installation required.

### Step 3 — Run

```bash
python main.py
```

---

## 🚀 Quick Start

1. **Launch** the app: `python main.py`
2. **Step 1:** Click **Browse** → select `sample_data.csv` (included in repo)
3. **Step 2:** Click **Run Auto-Detect** → review the PII detection table
4. **Step 3:** Choose **Anonymization** mode → select **Academic/Research** profile → click **Apply Profile Defaults**
5. **Step 4:** Click **Refresh Preview** → compare original vs. transformed rows
6. **Step 5:** Click **Choose Folder** → select output directory → click **PROCESS & EXPORT**
7. View results in the right panel → click **Open Output Folder**

---

## 🔀 Processing Modes

### Irreversible Anonymization
- Transformations **cannot be reversed**
- No key file is generated
- Satisfies GDPR Article 17 (Right to Erasure)
- Recommended when: sharing data publicly, deleting PII permanently, or meeting strict data minimization requirements

### Reversible Pseudonymization
- Replacements are **consistent and reversible** using the exported key file
- Generates a `pseudo_key_*.json` file containing the original↔fake value mapping
- Satisfies GDPR Recital 26 (Pseudonymisation)
- ⚠️ **The key file is as sensitive as the original data — store it separately and securely**
- Recommended when: sharing data with third parties who may need to re-identify subjects under controlled conditions

---

## 🕵️ PII Types Supported

| PII Type | Detection Method | Example Pattern |
|----------|-----------------|-----------------|
| Email | Header + Regex | `user@domain.com` |
| Phone | Header + Regex | `+92-300-1234567` |
| CNIC (National ID) | Header + Regex | `35202-1234567-1` |
| Full Name | Header + Regex | `Ali Hassan` |
| Date of Birth | Header + Regex | `15/03/1990` |
| Address | Header + Regex | `123 Main Street, City` |
| IP Address | Header + Regex | `192.168.1.5` |
| Credit Card | Header + Regex | `4111 1111 1111 1111` |
| Student/Employee ID | Header + Regex | `EMP001`, `STU-2023-001` |
| Age | Header + Regex | `23` |

---

## 🛡️ Anonymization Techniques

| Technique | Reversible | Example (Email) | Best For |
|-----------|-----------|-----------------|----------|
| **Masking** | ❌ | `a***@domain.com` | Preserving format while hiding value |
| **Hashing** (SHA-256) | ❌ | `3a7f2c...` (64 hex chars) | Consistent linkage without exposure |
| **Generalization** | ❌ | Age `23` → `20-29` | Statistical analysis on ranges |
| **Fake Data** | ✅ (with key) | `james.cooper@fake.net` | Realistic test/dev data |
| **Null/Deletion** | ❌ | ` ` (empty) | Complete field removal |
| **Redaction** | ❌ | `[REDACTED]` | Explicit removal marker |

---

## 📂 Use-Case Profiles

### 🎓 Academic / Research
Auto-applies: Fake Data for names, Masking for emails, Generalization for DOB/Age, Hashing for IDs
> GDPR / HEC compliance focus. Preserves analytical utility for longitudinal research.

### 🏢 Corporate / HR
Auto-applies: Hashing for CNICs, Masking for contacts, Generalization for demographics
> PECA 2016 and employment privacy focus. Strong protection for national IDs and salary data.

### 🏥 Healthcare / Patient Records
Auto-applies: Redaction for names, Deletion for contacts, Generalization for dates
> HIPAA Safe Harbor de-identification. Highest protection level — removes all 18 HIPAA direct identifiers where possible.

---

## 📤 Output Files

### 1. Anonymized CSV (`anonymized_YYYYMMDD_HHMMSS.csv`)
The processed dataset with all selected transformations applied. Non-selected columns are passed through unchanged.

### 2. Audit Report (`audit_report_YYYYMMDD_HHMMSS.txt`)
A structured plain-text report containing:
- Processing summary (timestamp, file names, mode, row/column count)
- Per-column action table (column → PII type → technique → status)
- Compliance matrix (each technique mapped to GDPR articles, PECA sections, HIPAA provisions)
- Mode-specific notes (anonymization vs. pseudonymization guidance)
- Ethical disclaimer

### 3. Pseudonymization Key (`pseudo_key_YYYYMMDD_HHMMSS.json`) *(Pseudonymization mode only)*
```json
{
  "metadata": {
    "generated_at": "2026-05-05T18:00:00",
    "source_file": "employees.csv",
    "pseudonymized_cols": ["Name", "Email"],
    "total_mappings": 150
  },
  "SECURITY_WARNING": "THIS FILE IS HIGHLY SENSITIVE...",
  "mapping": {
    "Ali Hassan": "James Cooper",
    "ali@example.com": "jcooper@fakeemail.net"
  }
}
```
> ⚠️ **This file must be stored separately from the anonymized CSV, encrypted at rest, and access-controlled.**

---

## ⚖️ Compliance Framework

| Regulation | Articles/Sections Covered | How |
|-----------|--------------------------|-----|
| **GDPR** | Art. 4 (personal data definition), Art. 5 (principles), Art. 17 (erasure), Art. 25 (privacy by design), Art. 32 (security), Recital 26 (pseudonymisation) | PII detection maps to Art. 4; each technique maps to relevant principles; audit log satisfies Art. 5(2) accountability |
| **PECA 2016** | Section 3 (unauthorized access), Section 4 (data damage/unauthorized modification) | Processing is authorized and logged; key management guidance prevents unauthorized re-identification |
| **HIPAA** | Security Rule § 164.514 (Safe Harbor de-identification), § 164.312 (audit controls) | Healthcare profile applies HIPAA-compliant generalizations; audit report serves as § 164.312 evidence |
| **CIA Triad** | Confidentiality (primary focus) | Every technique reduces information accessible to unauthorized parties |

---

## 📦 Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `pandas` | ≥ 1.3.0 | CSV reading, DataFrame manipulation, column-level `.apply()` transforms |
| `faker` | ≥ 13.0.0 | Generating realistic locale-aware fake PII for pseudonymization |
| `tkinter` | stdlib | GUI framework (standard library — no install needed) |
| `hashlib` | stdlib | SHA-256 cryptographic hashing |
| `re` | stdlib | Regular expression PII pattern matching |
| `json` | stdlib | Key file serialization |
| `datetime` | stdlib | Timestamping output files and audit reports |
| `os` | stdlib | File path operations |

---

## 🤝 Contributing

Contributions are welcome. Please follow these guidelines:

1. Fork the repository and create a feature branch: `git checkout -b feature/my-feature`
2. Keep code style consistent — clear function names, inline comments explaining *why* not just *what*
3. To add a new **PII type**: add an entry to `PII_DEFINITIONS` in `pii_detector.py`
4. To add a new **technique**: add a function in `anonymizer.py`, register it in `TECHNIQUE_NAMES`, add routing in `apply_technique()`, and add compliance mapping in `audit.py`
5. Submit a pull request with a clear description of changes

---

## 📄 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## 🔐 Ethical Notice

This tool is intended for **authorized data processing only**. You must have legal authority over any data you process. Unauthorized processing of personal data may violate GDPR, PECA 2016, HIPAA, and other applicable laws. The authors assume no liability for misuse.
