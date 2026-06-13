# =============================================================================
# audit.py  –  Audit Trail & Compliance Reporting
# =============================================================================
# PURPOSE:
#   Generates human-readable processing logs and compliance reports after
#   every anonymization/pseudonymization run.
#
# WHY AUDIT TRAILS?
#   GDPR Article 5(2) – "Accountability": the data controller must be able
#   to DEMONSTRATE compliance with data protection principles. An audit log
#   is the primary mechanism for this demonstration.
#
#   PECA Section 4 (Unauthorized Damage to Data) – maintaining an audit
#   trail proves that any data modification was authorized and intentional.
#
#   In a real enterprise system, audit logs would be write-once and
#   cryptographically signed. For this academic tool, we generate a
#   plain-text report that covers all the essential fields.
#
# CIA TRIAD LINK:
#   Integrity – the audit log provides evidence that data transformations
#   were deliberate and controlled. It supports non-repudiation: you can
#   prove WHAT was done, WHEN, and HOW.
# =============================================================================

import os
from datetime import datetime

# =============================================================================
# SECTION 1 – COMPLIANCE FRAMEWORK MAPPINGS
# =============================================================================
# Maps each technique to the privacy/legal principles it satisfies.
# Used to auto-generate the Compliance Matrix section of the report.
#
# TEACHING NOTE:
#   This mapping is intentionally simplified for educational purposes.
#   Real compliance mapping requires legal expertise and context-specific
#   analysis. Do NOT use this as a substitute for legal advice.
# =============================================================================

TECHNIQUE_COMPLIANCE_MAP = {
    "Masking": {
        "GDPR"  : [
            "Art. 5(1)(c) – Data Minimisation (reduces exposed PII)",
            "Art. 25    – Privacy by Design (PII obscured at output)"
        ],
        "PECA"  : [
            "S. 3 – Reduces risk of unauthorized identity exposure",
        ],
        "HIPAA" : [
            "Safe Harbor (§164.514) – Partial masking of direct identifiers"
        ],
        "CIA"   : "Confidentiality – restricts information visible to unauthorized viewers"
    },

    "Hashing": {
        "GDPR"  : [
            "Recital 26  – Pseudonymisation (value cannot be re-attributed without key)",
            "Art. 5(1)(f)– Integrity and Confidentiality (one-way transformation)",
            "Art. 17     – Right to Erasure (original effectively unrecoverable)"
        ],
        "PECA"  : [
            "S. 4 – Protects data integrity; prevents value tampering from having meaning"
        ],
        "HIPAA" : [
            "Expert Determination (§164.514(b)) – statistically irreversible"
        ],
        "CIA"   : "Confidentiality + Integrity – irreversible transform with consistent output"
    },

    "Generalization": {
        "GDPR"  : [
            "Art. 5(1)(c) – Data Minimisation (precision reduced to what is necessary)",
            "Recital 26   – De-identification (aggregation reduces re-identification risk)"
        ],
        "PECA"  : [
            "S. 3 – Reduces information value to potential unauthorized accessor"
        ],
        "HIPAA" : [
            "Safe Harbor (§164.514) – Dates to year; geographies to state/region"
        ],
        "CIA"   : "Confidentiality – reduces discriminating power of individual attributes"
    },

    "Fake Data": {
        "GDPR"  : [
            "Recital 26  – Pseudonymisation (replaced with realistic but fake values)",
            "Art. 5(1)(b)– Purpose Limitation (fake data cannot identify original subject)"
        ],
        "PECA"  : [
            "S. 4 – Controlled substitution; mapping key must be secured separately"
        ],
        "HIPAA" : [
            "Safe Harbor (§164.514) – Direct identifiers replaced"
        ],
        "CIA"   : "Confidentiality – identity obscured; utility preserved for testing/research"
    },

    "Null/Deletion": {
        "GDPR"  : [
            "Art. 5(1)(c) – Data Minimisation (field eliminated entirely)",
            "Art. 17      – Right to Erasure (value permanently removed)"
        ],
        "PECA"  : [
            "S. 4 – Prevents any possible unauthorized access to the data"
        ],
        "HIPAA" : [
            "Safe Harbor (§164.514) – Direct identifier fully removed"
        ],
        "CIA"   : "Confidentiality – maximum protection; zero residual information"
    },

    "Redaction": {
        "GDPR"  : [
            "Art. 5(1)(c) – Data Minimisation",
            "Art. 17      – Right to Erasure"
        ],
        "PECA"  : [
            "S. 4 – Explicit [REDACTED] label signals intentional removal"
        ],
        "HIPAA" : [
            "Safe Harbor (§164.514) – Direct identifier replaced with explicit marker"
        ],
        "CIA"   : "Confidentiality – value removed; placeholder maintains field structure"
    },
}


# =============================================================================
# SECTION 2 – GENERATE AUDIT REPORT
# =============================================================================

def generate_audit_report(
    input_file,
    output_file,
    mode,
    profile,
    column_configs,
    row_count,
    output_dir,
    key_file=None
):
    """
    Generate a plain-text audit report and compliance matrix.

    The report contains:
      1. Processing summary (who, what, when, how many rows)
      2. Per-column action table
      3. Compliance matrix (maps each technique to legal principles)
      4. Ethical disclaimer

    Parameters:
        input_file     (str)  : Path to the original CSV file.
        output_file    (str)  : Path to the anonymized CSV file.
        mode           (str)  : "Anonymization" or "Pseudonymization".
        profile        (str)  : Profile name used (or "Custom").
        column_configs (dict) : { col_name: { "pii_type": ..., "technique": ...,
                                              "include": bool } }
        row_count      (int)  : Number of data rows processed.
        output_dir     (str)  : Directory to save the report file.
        key_file       (str)  : Path to the pseudonymization key file, if any.

    Returns:
        str: Path of the generated report file.
    """

    # Generate a timestamped filename for the report
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"audit_report_{timestamp_str}.txt"
    report_path = os.path.join(output_dir, report_filename)

    # Collect the techniques actually used (for the compliance matrix)
    techniques_used = set()

    # Track which columns were processed vs skipped
    processed_cols = []
    skipped_cols = []

    for col, cfg in column_configs.items():
        if cfg.get("include", True):
            processed_cols.append((col, cfg.get("pii_type", "?"),
                                   cfg.get("technique", "?")))
            techniques_used.add(cfg.get("technique", "?"))
        else:
            skipped_cols.append(col)

    # -------------------------------------------------------------------------
    # BUILD THE REPORT STRING
    # -------------------------------------------------------------------------
    lines = []

    # --- HEADER ---
    lines.append("=" * 72)
    lines.append("  CSV ANONYMIZER – PROCESSING AUDIT REPORT")
    lines.append("  Academic Information Security Project")
    lines.append("  Course: Information Security | BS Computer Science / IT")
    lines.append("=" * 72)
    lines.append("")

    # --- SECTION A: PROCESSING SUMMARY ---
    lines.append("A. PROCESSING SUMMARY")
    lines.append("-" * 72)
    lines.append(f"  Timestamp         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Input File        : {os.path.basename(input_file)}")
    lines.append(f"  Output File       : {os.path.basename(output_file)}")
    lines.append(f"  Processing Mode   : {mode}")
    lines.append(f"  Use-Case Profile  : {profile}")
    lines.append(f"  Rows Processed    : {row_count:,}")
    lines.append(f"  Columns Analysed  : {len(column_configs)}")
    lines.append(f"  Columns Modified  : {len(processed_cols)}")
    lines.append(f"  Columns Skipped   : {len(skipped_cols)}")
    if key_file:
        lines.append(f"  Pseudonym Key File: {os.path.basename(key_file)}")
        lines.append("  [!] KEY FILE IS SENSITIVE – STORE SEPARATELY & SECURELY")
    lines.append("")

    # --- SECTION B: PER-COLUMN ACTION TABLE ---
    lines.append("B. PER-COLUMN PROCESSING DETAILS")
    lines.append("-" * 72)
    # Header row
    lines.append(f"  {'Column Name':<25} {'PII Type':<22} {'Technique':<18} {'Status'}")
    lines.append(f"  {'-'*24} {'-'*21} {'-'*17} {'-'*8}")

    for col, pii_type, technique in processed_cols:
        col_display = col[:24] if len(col) > 24 else col
        pii_display = pii_type[:21] if len(pii_type) > 21 else pii_type
        lines.append(f"  {col_display:<25} {pii_display:<22} {technique:<18} PROCESSED")

    for col in skipped_cols:
        col_display = col[:24] if len(col) > 24 else col
        lines.append(f"  {col_display:<25} {'(skipped)':<22} {'–':<18} SKIPPED")

    lines.append("")

    # --- SECTION C: COMPLIANCE MATRIX ---
    lines.append("C. COMPLIANCE MATRIX")
    lines.append("-" * 72)
    lines.append("  Maps each applied technique to relevant legal/ethical principles.")
    lines.append("")

    for technique in sorted(techniques_used):
        mapping = TECHNIQUE_COMPLIANCE_MAP.get(technique, {})
        lines.append(f"  ▶ Technique: {technique}")

        if mapping:
            lines.append(f"    GDPR:")
            for item in mapping.get("GDPR", ["N/A"]):
                lines.append(f"      • {item}")

            lines.append(f"    PECA 2016:")
            for item in mapping.get("PECA", ["N/A"]):
                lines.append(f"      • {item}")

            lines.append(f"    HIPAA:")
            for item in mapping.get("HIPAA", ["N/A"]):
                lines.append(f"      • {item}")

            lines.append(f"    CIA Triad:")
            lines.append(f"      • {mapping.get('CIA', 'N/A')}")
        else:
            lines.append("    No compliance mapping available for this technique.")

        lines.append("")

    # --- SECTION D: MODE-SPECIFIC NOTES ---
    lines.append("D. MODE-SPECIFIC NOTES")
    lines.append("-" * 72)

    if mode == "Anonymization":
        lines.append(
            "  IRREVERSIBLE ANONYMIZATION was applied. Transformations cannot be\n"
            "  undone. Original PII values are permanently unrecoverable from the\n"
            "  output file. This satisfies GDPR Article 17 (Right to Erasure)\n"
            "  and PECA Section 4 (data protection through elimination of risk)."
        )
    else:  # Pseudonymization
        lines.append(
            "  REVERSIBLE PSEUDONYMIZATION was applied. The pseudonymization\n"
            "  key file (listed above) MUST be stored separately and securely.\n"
            "  GDPR Recital 26 treats pseudonymised data as personal data if\n"
            "  re-identification is possible with the key. Treat the key file\n"
            "  with the same security controls as the original dataset.\n"
            "\n"
            "  Key Management Recommendations (PECA / GDPR Article 32):\n"
            "    1. Encrypt the key file at rest (AES-256 recommended).\n"
            "    2. Store the key file separately from the anonymized CSV.\n"
            "    3. Restrict access to the key file (need-to-know basis).\n"
            "    4. Log all access to the key file in a separate audit trail.\n"
            "    5. Establish a key rotation and destruction policy."
        )

    lines.append("")

    # --- SECTION E: ETHICAL DISCLAIMER ---
    lines.append("E. ETHICAL DISCLAIMER")
    lines.append("-" * 72)
    lines.append(
        "  This tool is intended for AUTHORIZED DATA PROCESSING ONLY.\n"
        "  Users must have legal authority over the data being processed.\n"
        "  Unauthorized processing of personal data may violate:\n"
        "    • PECA 2016 – Prevention of Electronic Crimes Act (Pakistan)\n"
        "    • GDPR 2018 – General Data Protection Regulation (EU)\n"
        "    • HIPAA 1996 – Health Insurance Portability & Accountability Act\n"
        "\n"
        "  Professional Conduct (aligned with Information Security principles):\n"
        "    • Act with integrity and transparency in all data operations.\n"
        "    • Respect data subjects' rights (access, erasure, portability).\n"
        "    • Report data breaches promptly to relevant authorities.\n"
        "    • Never use anonymization as a pretext for data misuse.\n"
        "\n"
        "  Confidentiality (CIA Triad):\n"
        "    • Only authorized personnel should access the original dataset.\n"
        "    • The anonymized output should still be stored securely.\n"
        "    • Even anonymized data can sometimes be re-identified via\n"
        "      linkage attacks – apply defence-in-depth."
    )
    lines.append("")
    lines.append("=" * 72)
    lines.append("  END OF AUDIT REPORT")
    lines.append("=" * 72)

    # Write all lines to the report file
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return report_path
