# CSV Anonymizer — Project Report & Presentation Guide

---

## Executive Summary

CSV Anonymizer is a desktop application that addresses a critical gap in data privacy workflows: the lack of accessible, configurable tools for non-technical users to safely anonymize or pseudonymize CSV datasets before sharing, publishing, or processing them. The tool implements industry-standard privacy-preserving techniques — masking, cryptographic hashing, generalization, fake data replacement, and deletion — through an intuitive 5-step wizard interface. It generates compliance-mapped audit reports referencing GDPR, PECA 2016, and HIPAA, and produces a reversibility key when pseudonymization is chosen. The project demonstrates applied understanding of the CIA Triad (Confidentiality), data classification, legal frameworks, and professional data handling ethics.

---

## 1. Problem Statement

### 1.1 Background

Organizations routinely share CSV datasets for research, testing, analytics, and vendor processing. These datasets frequently contain Personally Identifiable Information (PII) — names, national IDs, email addresses, dates of birth, and medical records. Sharing such data without transformation exposes organizations and individuals to significant risks:

- **Legal liability** under GDPR (EU), PECA 2016 (Pakistan), and HIPAA (US healthcare)
- **Reputational damage** from data breaches
- **Harm to individuals** through identity theft, discrimination, and loss of privacy
- **Re-identification attacks** that combine multiple quasi-identifiers to uniquely identify individuals even in "anonymized" datasets (Sweeney, 2002)

### 1.2 The Gap

Existing solutions are either:
- **Too technical** (library-only tools requiring programming knowledge)
- **Too rigid** (one-size-fits-all anonymization without technique selection)
- **Too expensive** (enterprise data governance platforms)
- **Insufficient** (simple find-and-replace that doesn't handle format-preserving masking, consistency across rows, or compliance documentation)

### 1.3 The Solution

A Python desktop application that:
1. Automatically detects PII columns using regex and header analysis
2. Lets users configure specific techniques per column
3. Applies domain-appropriate defaults through use-case profiles
4. Generates a compliance audit report automatically
5. Exports a reversibility key (when needed) with embedded security warnings

---

## 2. Objectives

| # | Objective | Achieved By |
|---|-----------|-------------|
| O1 | Detect PII automatically without requiring user expertise | Two-pass detection engine in `pii_detector.py` |
| O2 | Support both irreversible and reversible processing | Dual mode selection in Step 3 |
| O3 | Allow technique selection per column | Per-column Combobox dropdowns in Step 3 |
| O4 | Apply domain-specific defaults | Three use-case profiles in `profiles.py` |
| O5 | Generate compliance-mapped documentation | `audit.py` with GDPR/PECA/HIPAA matrix |
| O6 | Handle pseudonymization reversibility securely | JSON key export with embedded security warnings |
| O7 | Provide an accessible GUI for non-technical users | 5-step Tkinter wizard |
| O8 | Work on standard Python installations | Only external deps: pandas, faker |

---

## 3. Literature Review & Theoretical Foundation

### 3.1 CIA Triad — Confidentiality Focus

The CIA Triad (Confidentiality, Integrity, Availability) is the foundational framework of information security. This project focuses on **Confidentiality**: ensuring that personal data is accessible only to authorized parties. Every technique implemented reduces the information available to an unauthorized accessor while preserving analytical utility where possible.

### 3.2 Data Anonymization vs. Pseudonymization

- **Anonymization** (ISO 29101): Irreversible removal or transformation of PII such that re-identification is not possible even with additional information. Data is no longer "personal data" under GDPR.
- **Pseudonymization** (GDPR Recital 26): Replacement of PII with pseudonyms using a key. Data remains "personal data" under GDPR because re-identification is possible with the key. However, it reduces risks and may qualify for reduced compliance obligations.

### 3.3 k-Anonymity (Sweeney, 2002)

Sweeney demonstrated that 87% of Americans could be uniquely identified using only zip code, birth date, and gender — none of which are traditionally considered PII. This motivates **generalization**: converting precise values to ranges that ensure any individual is indistinguishable from at least k-1 others on those attributes. The Generalization technique in this tool implements age banding and date coarsening as practical k-anonymity measures.

### 3.4 GDPR Key Principles Applied

| Principle | GDPR Article | Implementation |
|-----------|-------------|----------------|
| Lawfulness, Fairness, Transparency | Art. 5(1)(a) | Ethical disclaimer in UI and audit report |
| Purpose Limitation | Art. 5(1)(b) | Profiles enforce context-appropriate techniques |
| Data Minimisation | Art. 5(1)(c) | Deletion and generalization techniques |
| Accuracy | Art. 5(1)(d) | Transformed data is flagged as processed |
| Storage Limitation | Art. 5(1)(e) | Tool processes and exports; no server storage |
| Integrity & Confidentiality | Art. 5(1)(f) | Hashing, masking, secure key export |
| Accountability | Art. 5(2) | Auto-generated audit report |

### 3.5 PECA 2016 Relevance

Pakistan's Prevention of Electronic Crimes Act 2016:
- **Section 3** (Unauthorized Access): The tool's audit trail demonstrates that data processing was authorized and intentional.
- **Section 4** (Unauthorized Copying/Transmission of Data): The pseudonymization key management guidance prevents unauthorized re-identification.

### 3.6 HIPAA Safe Harbor Method

HIPAA's Safe Harbor de-identification method (45 CFR § 164.514(b)) requires removal or generalization of 18 specific identifiers. The Healthcare profile in this tool applies: name redaction, date coarsening to year, geographic generalization to city/state level, phone/email deletion, and ID hashing — covering the most commonly present Safe Harbor identifiers in CSV datasets.

---

## 4. System Design

### 4.1 Architecture Pattern

The application uses a **Layered Architecture** with three layers:

```
┌─────────────────────────────────────────────────┐
│  Presentation Layer  (app.py + steps.py)         │
│  Tkinter wizard, navigation, event handling      │
├─────────────────────────────────────────────────┤
│  Business Logic Layer                            │
│  pii_detector.py  |  anonymizer.py              │
│  profiles.py      |  audit.py                   │
├─────────────────────────────────────────────────┤
│  Data Layer                                      │
│  pandas DataFrames  |  CSV files  |  JSON files  │
└─────────────────────────────────────────────────┘
```

### 4.2 Shared State Pattern

`AppState` (in `app.py`) acts as a session-scoped shared memory object. All step frames hold a reference to the same `AppState` instance. This avoids parameter-passing complexity while keeping state centralized and inspectable.

### 4.3 Template Method Pattern (BaseStep)

`BaseStep` defines the interface that all step frames must implement: `on_enter()`, `validate()`, `reset()`. The wizard calls these hooks at the appropriate lifecycle points without knowing the implementation details of each step.

### 4.4 Strategy Pattern (apply_technique)

`apply_technique()` in `anonymizer.py` is a strategy dispatcher. The "strategy" (which transformation function to call) is selected at runtime based on the `technique` string. Adding a new technique requires no changes to the calling code — only adding the strategy function and registering it.

### 4.5 Data Flow

```
Input CSV → pandas.read_csv() → DataFrame
   → PII Detection (header + regex)
   → User Configuration (mode, profile, techniques)
   → Sample Preview (apply_technique on 5 rows)
   → Full Processing (apply_technique on all rows)
   → Output CSV + Audit Report + Key File (optional)
```

---

## 5. Implementation Details

### 5.1 PII Detection Engine

**Two-pass approach:**

| Pass | Method | Speed | Accuracy |
|------|--------|-------|----------|
| 1 — Header | Keyword substring match | O(n×k) ≈ constant | High for standard column names |
| 2 — Value | Regex on 10-row sample | O(n×p×s) | High for any column naming convention |

A column is flagged if **either** pass matches. The 50% sample-match threshold is configurable and represents a deliberate precision/recall tradeoff.

**Supported PII regex patterns:**

| PII Type | Regex | Notes |
|----------|-------|-------|
| Email | `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}` | Standard RFC 5322 subset |
| Phone | `(\+?\d{1,3}[\s\-]?)?\(?\d{2,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{4,7}` | Handles international formats |
| CNIC | `\d{5}-\d{7}-\d{1}` | Pakistani National ID |
| Full Name | `[A-Z][a-z]+(\s[A-Z][a-z]+)+` | Two+ capitalized words |
| DOB | `\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}` | DD/MM/YYYY and variants |
| IP Address | `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b` | IPv4 only |
| Credit Card | `\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b` | 16-digit formats |

### 5.2 Technique Implementation Summary

#### Masking
- Email: `john.doe@gmail.com → j*******@gmail.com`
- Phone: keeps first 3 and last 3 digits
- Credit Card: shows last 4 digits only (PCI-DSS standard)
- Generic: keeps first + last character, masks middle

#### Hashing (SHA-256)
```python
hashlib.sha256(str(value).encode("utf-8")).hexdigest()
```
Properties: deterministic (same input → same hash), one-way (computationally infeasible to reverse for unique values), produces 64-character hex string.

#### Generalization
- Age: decade banding `(age // 10) * 10` → `f"{lower}-{upper}"`
- DOB: `re.search(r"\b(19|20)\d{2}\b", value_str)` extracts year
- IP: replaces octets 3+4 with `x`
- Address: last comma-separated segment (city/country level)

#### Fake Data (Pseudonymization)
- Module-level `_pseudo_mapping` dict ensures **referential integrity** across all rows
- `Faker(locale)` with `Faker.seed(42)` for reproducibility
- 8 type-specific generators: `fake.name()`, `fake.email()`, `fake.phone_number()`, etc.

#### Deletion
- `"null"` mode: empty string (represents SQL NULL in CSV)
- `"redacted"` mode: literal `"[REDACTED]"` string

### 5.3 Pseudonymization Key Structure

```json
{
  "metadata": {
    "generated_at": "ISO8601 timestamp",
    "source_file": "original.csv",
    "pseudonymized_cols": ["Name", "Email", "Phone"],
    "total_mappings": 245,
    "tool": "CSV-Anonymizer v1.0"
  },
  "SECURITY_WARNING": "THIS FILE IS HIGHLY SENSITIVE...",
  "mapping": {
    "original_value_1": "fake_value_1",
    "original_value_2": "fake_value_2"
  }
}
```

### 5.4 UI Design Decisions

| Decision | Rationale |
|----------|-----------|
| Dark theme (#1a1a2e base) | Reduces eye strain; modern developer aesthetic |
| `grid` with `weight=1` for path labels | Labels stretch with window; prevents clipping at small sizes |
| `place()` for step frames | Allows all frames to coexist in same space; `tkraise()` switches visibility |
| Stacked Before/After panels in Step 4 | Side-by-side panels collapse on narrow windows; stacked always shows both |
| Lazy Faker import | App loads cleanly even if Faker missing; error appears only when needed |
| `minsize(700, 520)` | Prevents layout collapse below a usable size |
| Dynamic `wraplength` on labels | `bind("<Configure>", ...)` updates wrap width on every resize |
| `ttk.Style` with `clam` theme | `clam` is the only ttk theme that allows full background colour customisation |

---

## 6. Testing & Validation

### 6.1 Functional Test Cases

| ID | Test | Input | Expected Output | Pass/Fail |
|----|------|-------|----------------|-----------|
| T01 | Load valid CSV | `sample_data.csv` | 6 rows, 10 columns in preview | ✅ |
| T02 | Load invalid file | `.txt` file | Error dialog shown | ✅ |
| T03 | Auto-detect PII | `sample_data.csv` | Name, Email, Phone, CNIC, DOB, Age, Address, ID detected | ✅ |
| T04 | Masking — Email | `ali@example.com` | `a**@example.com` | ✅ |
| T05 | Hashing — CNIC | `35202-1234567-1` | 64-char hex string | ✅ |
| T06 | Generalization — Age | `34` | `30-39` | ✅ |
| T07 | Fake Data — Name | `Ali Hassan` | Realistic fake name, consistent per value | ✅ |
| T08 | Null Deletion | `ali@example.com` | Empty string | ✅ |
| T09 | Redaction | `ali@example.com` | `[REDACTED]` | ✅ |
| T10 | Profile application | Academic/Research profile | Name→Fake Data, Email→Masking, DOB→Generalization | ✅ |
| T11 | Pseudonymization mode | Process with Pseudo mode | `pseudo_key_*.json` created | ✅ |
| T12 | Audit report | After processing | `audit_report_*.txt` with compliance matrix | ✅ |
| T13 | New Session reset | Click "Start New Session" | All fields cleared, returns to Step 1 | ✅ |
| T14 | Small window | Resize to 700×520 | No layout clipping or overflow | ✅ |
| T15 | Empty cells | CSV with null values | Empty cells pass through unchanged | ✅ |

### 6.2 Hash Consistency Verification

```python
import hashlib
v = "35202-1234567-1"
assert hashlib.sha256(v.encode()).hexdigest() == hashlib.sha256(v.encode()).hexdigest()
# Same input must always produce the same hash
```

### 6.3 Pseudonymization Reversibility Verification

```python
import json, pandas as pd

with open("pseudo_key_YYYYMMDD.json") as f:
    key = json.load(f)

reverse_map = {v: k for k, v in key["mapping"].items()}
df_anon = pd.read_csv("anonymized_YYYYMMDD.csv")
df_anon["Name"] = df_anon["Name"].map(reverse_map).fillna(df_anon["Name"])
# Names should match original CSV
```

### 6.4 Edge Cases

| Edge Case | Behavior |
|-----------|----------|
| CSV with only 1 data row | Preview and processing work normally |
| All-identical column (e.g., same name in every row) | Fake data maps consistently; only 1 entry in key file |
| Column with 100% null values | detect_by_values returns False; column not flagged |
| Very long values (500+ chars) | Masking handles arbitrary length; no crash |
| CSV with 100+ columns | Proportional column widths prevent Treeview overflow |
| Process button clicked twice | Second run clears log and result labels; fresh processing |
| Back navigation after processing | Does not re-process; preview reflects last config |

---

## 7. Limitations & Future Enhancements

| Limitation | Suggested Enhancement |
|-----------|----------------------|
| No salting in SHA-256 | Add configurable salt for low-entropy data (phone numbers, ages) |
| Faker locale fixed to `en_US` | Expose locale picker in UI (Faker supports 40+ locales) |
| No k-anonymity scoring | Add a post-processing analyzer that computes k value for quasi-identifier combinations |
| Key file not encrypted | Integrate `cryptography` library for AES-256 key file encryption |
| No undo within a session | Implement a processing history stack for step-back without full reset |
| Single-threaded processing | Move processing to a background thread with `threading.Thread` to keep UI responsive on large files |
| No column exclusion export | Add option to completely drop (not transform) selected columns from output CSV |

---

## 8. Compliance Summary Table

| Feature | GDPR | PECA 2016 | HIPAA | CIA Triad |
|---------|------|-----------|-------|-----------|
| PII Auto-Detection | Art. 4 — personal data definition | S.3 — access risk identification | §164.514 — PHI identification | Confidentiality |
| Masking | Art. 5(1)(c) minimisation | S.3 — reduces exposure | Safe Harbor partial identifier | Confidentiality |
| SHA-256 Hashing | Recital 26 pseudonymisation; Art. 17 erasure | S.4 — data protection | Expert Determination method | Confidentiality + Integrity |
| Generalization | Art. 5(1)(c); Recital 26 | S.3 — reduces discriminating value | Safe Harbor dates/geography | Confidentiality |
| Fake Data | Recital 26 pseudonymisation | S.4 — controlled substitution | Safe Harbor direct identifier replacement | Confidentiality |
| Null/Deletion | Art. 17 — right to erasure | S.4 — data elimination | Safe Harbor — full removal | Confidentiality |
| Audit Report | Art. 5(2) — accountability | S.4 — authorization evidence | §164.312 — audit controls | Integrity |
| Key Management | Art. 32 — security measures | S.4 — data security obligation | §164.312 — access control | Confidentiality |
| Use-Case Profiles | Art. 25 — privacy by design | — | Minimum Necessary rule | Confidentiality |
| Ethical Disclaimer | Art. 5(1)(a) — lawfulness | S.3 — unauthorized access | — | All three |

---

## 9. Presentation Guide

### 9.1 Recommended Slide Structure (12 Slides)

---

**Slide 1 — Title**
- Title: *CSV Anonymizer: A Privacy-Preserving Data Processing Tool*
- Your name, institution, date
- Subtitle: *Implementing GDPR, PECA & HIPAA compliance through applied data privacy techniques*

---

**Slide 2 — Problem Statement**
- Key statistics: data breach costs, GDPR fines (€20M or 4% global turnover)
- Real-world scenario: a researcher shares a student dataset with a publisher — it contains real CNICs, emails, phone numbers
- The gap: no accessible, configurable anonymization tool exists for non-technical users
- **Talking point:** "Every organization that handles personal data has a legal and ethical obligation to protect it before sharing."

---

**Slide 3 — Legal Framework**
- Three columns: GDPR | PECA 2016 | HIPAA
- Key articles/sections for each
- CIA Triad: Confidentiality focus
- **Talking point:** "These three frameworks represent the legal landscape for data privacy across different jurisdictions. Our tool demonstrates compliance with all three."

---

**Slide 4 — Solution Overview**
- Show the 5-step wizard flow (ASCII diagram or simplified graphic)
- Inputs → Outputs table
- Key differentiators: auto-detection, technique selection, audit report, reversibility key
- **Talking point:** "The tool guides users through a structured workflow that ensures every privacy decision is deliberate and documented."

---

**Slide 5 — System Architecture**
- Show the module diagram (from CODE_EXPLANATION.md Section 8)
- Explain the layered architecture: Presentation → Business Logic → Data
- Highlight the Shared State pattern (AppState)
- **Talking point:** "The modular design means each component can be tested, replaced, or extended independently."

---

**Slide 6 — PII Detection Engine (Live Demo 1)**
- Show the regex patterns for CNIC, Email, Phone
- Explain two-pass detection: header keywords → value sampling
- **DEMO:** Load `sample_data.csv`, click Run Auto-Detect, show the detection table
- **Talking point:** "The engine identifies PII without requiring the user to know column names in advance."

---

**Slide 7 — Anonymization Techniques**
- Comparison table: technique, reversible?, example
- Focus on SHA-256: explain one-way property, determinism, use for dataset joining
- Focus on Generalization: explain k-anonymity concept (Sweeney 2002)
- **DEMO:** Apply Academic/Research profile, show technique dropdowns
- **Talking point:** "Different techniques serve different purposes. A researcher may need consistent IDs for longitudinal analysis — hashing provides that without exposing the raw value."

---

**Slide 8 — Pseudonymization & Key Management (Live Demo 2)**
- Switch to Pseudonymization mode
- Show the JSON key file structure after processing
- Explain: key file sensitivity = original data sensitivity
- Key management best practices: separate storage, encryption at rest, access control, audit log
- **Talking point:** "GDPR Recital 26 is explicit: pseudonymised data is still personal data if re-identification is possible with the key. The key must be protected accordingly."

---

**Slide 9 — Compliance Reporting (Live Demo 3)**
- **DEMO:** Click Process & Export, show live log, show result cards
- Open the generated audit report
- Walk through Section C (Compliance Matrix): read one technique's GDPR/PECA/HIPAA mapping aloud
- **Talking point:** "GDPR Article 5(2) requires that organizations be able to DEMONSTRATE compliance. This report is that demonstration."

---

**Slide 10 — Use-Case Profiles**
- Three profiles side-by-side: Academic, Corporate, Healthcare
- Show which techniques each applies and why
- Healthcare: HIPAA Safe Harbor — explain the 18 identifiers briefly
- **Talking point:** "Privacy requirements differ by domain. A hospital dataset requires far more aggressive de-identification than a student survey."

---

**Slide 11 — Testing & Validation**
- Show the functional test case table (Section 6.1)
- Hash consistency test (code snippet)
- Reversibility test (code snippet)
- Edge cases: empty cells, 1-row CSVs, 100+ column CSVs
- **Talking point:** "Every transformation is verified to be deterministic and consistent across rows."

---

**Slide 12 — Conclusion & Future Work**
- Summary: what the tool achieves
- Limitations table (Section 7) — shows awareness of scope
- Future enhancements: salted hashing, AES-256 key encryption, background threading, k-anonymity scoring
- **Talking point:** "This tool demonstrates that privacy-preserving data processing can be made accessible to non-technical users without sacrificing compliance rigor."

---

### 9.2 Live Demo Script (Step-by-Step)

```
1. Launch: python main.py
   → Point out the sidebar showing 5 steps and compliance badges

2. Step 1: Click Browse → select sample_data.csv
   → "Notice the preview loads automatically with the first 5 rows"
   → Point out responsive layout if resizing

3. Step 2: Click Run Auto-Detect
   → "The engine detected 8 PII columns using header keywords and regex"
   → Show the Method column (header vs. value)
   → Override one column manually using the dropdown

4. Step 3: Select Pseudonymization mode
   → Select Academic/Research profile → Apply Profile Defaults
   → "Notice how each column now has a context-appropriate technique pre-selected"
   → Change one technique manually to show flexibility

5. Step 4: Click Refresh Preview
   → "Left panel shows original data, right panel shows transformed data"
   → Point out the ✔ status in the AFTER header
   → Point out column count and row count labels

6. Step 5: Click Choose Folder → select a folder
   → Click PROCESS & EXPORT
   → "Watch the log update in real time as each column is processed"
   → Point out the result cards populating on the right
   → Click Open Output Folder → show the three output files
   → Click View Audit Report → walk through the compliance matrix

7. Click Start New Session
   → "Notice every field is cleared — path label, preview trees, log, result cards"
   → Return to Step 1 ready for a new file
```

---

### 9.3 Anticipated Q&A

**Q: Why not use encryption instead of anonymization?**
A: Encryption protects data in transit and at rest but does not help when you need to share the data itself with a third party. Anonymization allows the dataset to be shared freely. In a complete data protection strategy, both are used: anonymize the shared dataset AND encrypt stored copies.

**Q: Is SHA-256 reversible by brute force?**
A: For truly unique values (UUIDs, full names, long IDs), brute force is computationally infeasible. For low-entropy data (4-digit PINs, ages, small ID ranges), rainbow table attacks are feasible. Production systems should add a salt — a unique random value prepended to the input before hashing — to defeat rainbow tables. This is a known limitation documented in our future work section.

**Q: What makes pseudonymized data still "personal data" under GDPR?**
A: GDPR Recital 26 defines pseudonymised data as data that "could be attributed to a natural person by the use of additional information." Since the key file contains the original↔fake mapping, anyone with the key can re-identify the data. The data is therefore still personal data and still subject to GDPR — the pseudonymization only reduces risk, it does not eliminate the legal obligation.

**Q: Why Tkinter instead of a web interface?**
A: Tkinter is Python's standard GUI library — no additional installation, no web server, no browser dependency. For a data privacy tool, a local desktop application is also more secure: data never leaves the user's machine. A web interface would introduce network transmission risks.

**Q: How does the tool handle very large CSVs (millions of rows)?**
A: Currently, all processing runs on the main thread, which blocks the UI during processing. For large files, this is a known limitation. The planned enhancement is to move processing to a background `threading.Thread` and update the log widget via `root.after()` callbacks, keeping the UI responsive.

**Q: How would you extend this tool to support new PII types?**
A: Three steps: (1) Add an entry to `PII_DEFINITIONS` in `pii_detector.py` with the header keywords, regex pattern, and default technique. (2) Optionally add a type-specific branch in `apply_masking()` or `apply_generalization()` if the new type needs custom logic. (3) Add a compliance mapping entry in `audit.py`. The UI automatically picks up the new type in all dropdowns.

---

## 10. References

1. European Parliament. (2016). *General Data Protection Regulation (GDPR) — Regulation (EU) 2016/679.* Official Journal of the European Union.
2. Government of Pakistan. (2016). *Prevention of Electronic Crimes Act, 2016 (PECA).* National Assembly of Pakistan.
3. U.S. Department of Health & Human Services. (1996). *Health Insurance Portability and Accountability Act (HIPAA) — 45 CFR Part 164.*
4. Sweeney, L. (2002). *k-anonymity: A model for protecting privacy.* International Journal of Uncertainty, Fuzziness and Knowledge-Based Systems, 10(5), 557-570.
5. Stallings, W. (2019). *Cryptography and Network Security: Principles and Practice* (7th ed.). Pearson.
6. NIST. (2012). *Guide to Protecting the Confidentiality of Personally Identifiable Information (PII) — Special Publication 800-122.* National Institute of Standards and Technology.
7. Article 29 Data Protection Working Party. (2014). *Opinion 05/2014 on Anonymisation Techniques.* European Commission.
8. Fake Data Library: https://faker.readthedocs.io/
9. Pandas Documentation: https://pandas.pydata.org/docs/
10. Python hashlib Documentation: https://docs.python.org/3/library/hashlib.html
