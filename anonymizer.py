# =============================================================================
# anonymizer.py  –  Anonymization & Pseudonymization Techniques
# =============================================================================
# PURPOSE:
#   Implements all data transformation functions. Each function takes a
#   pandas Series (a single column of data) and returns a transformed Series.
#
# WHY THESE TECHNIQUES? (Course Alignment)
#   GDPR Article 5 requires "data minimisation" – data must be "adequate,
#   relevant and limited to what is necessary." The techniques below each
#   serve a different point on the privacy–utility tradeoff:
#
#   Masking       → Low utility, HIGH privacy  (irreversible)
#   Hashing       → Zero utility, MAXIMUM privacy (irreversible)
#   Generalization→ Medium utility, high privacy (irreversible)
#   Fake Data     → HIGH utility, medium privacy (reversible if key saved)
#   Deletion      → Zero utility, MAXIMUM privacy (irreversible)
#
# CIA TRIAD LINK:
#   Confidentiality – each technique reduces the information an attacker
#   can extract if the dataset is leaked (PECA Section 3 threat model).
# =============================================================================

import hashlib        # Built-in: cryptographic hash functions (SHA-256)
import re             # Built-in: regular expressions
import pandas as pd   # Third-party: DataFrame/Series manipulation
import json           # Built-in: saving the pseudonymization key as JSON
import os             # Built-in: file path operations
from datetime import datetime   # Built-in: timestamps for key metadata

# Faker is imported lazily inside the functions that need it to avoid
# an ImportError on machines where it isn't installed yet. This gives
# a user-friendly error message rather than a crash at startup.

# =============================================================================
# SECTION 1 – MASKING / REDACTION
# =============================================================================

def apply_masking(series, pii_type="Generic"):
    """
    Replace the middle portion of each value with asterisks (*).

    EXAMPLES:
      "john.doe@example.com"  → "j*******@example.com"
      "0300-1234567"          → "03**-****567"
      "Ali Hassan"            → "A** H*****"

    WHY MASKING?
      Masking preserves the FORMAT of the data (so downstream systems
      still validate the field type) while hiding the actual value.
      It's commonly used in log files, receipts, and support tickets.

    IRREVERSIBLE: Once masked, the original value cannot be recovered.
    This satisfies GDPR "right to erasure" in many practical contexts.

    Parameters:
        series   (pd.Series): Column of string values.
        pii_type (str)      : The PII type (used for type-specific masking).

    Returns:
        pd.Series: Masked values.
    """

    def mask_value(value):
        """Inner function – masks a single cell value."""
        # Convert to string; handle NaN/None gracefully
        if pd.isna(value) or str(value).strip() == "":
            return value   # Leave empty cells unchanged

        value = str(value)

        # --- Email-specific masking ---
        # Keep the first char of local part and the whole domain.
        # e.g.  john.doe@gmail.com  →  j*******@gmail.com
        if pii_type == "Email" and "@" in value:
            local, domain = value.split("@", 1)
            masked_local = local[0] + "*" * (len(local) - 1)
            return f"{masked_local}@{domain}"

        # --- Phone-specific masking ---
        # Keep first 3 and last 3 digits; mask the middle.
        elif pii_type == "Phone":
            digits = re.sub(r"\D", "", value)   # Strip non-digits
            if len(digits) >= 6:
                return digits[:3] + "*" * (len(digits) - 6) + digits[-3:]
            return "*" * len(value)

        # --- Credit Card masking ---
        # Industry standard: show only last 4 digits.
        elif pii_type == "Credit Card":
            digits = re.sub(r"\D", "", value)
            return "*" * (len(digits) - 4) + digits[-4:]

        # --- Generic masking ---
        # For short strings (≤3 chars), mask everything.
        # For longer strings, keep first and last character, mask middle.
        else:
            if len(value) <= 3:
                return "*" * len(value)
            return value[0] + "*" * (len(value) - 2) + value[-1]

    # Apply the inner function to every cell in the column
    return series.apply(mask_value)


# =============================================================================
# SECTION 2 – CRYPTOGRAPHIC HASHING (SHA-256)
# =============================================================================

def apply_hashing(series):
    """
    Replace each value with its SHA-256 cryptographic hash (hex digest).

    EXAMPLE:
      "12345-6789012-3"  →  "a3f1c2d...8e4b" (64 hex characters)

    WHY SHA-256?
      SHA-256 is a one-way hash function: it always produces the SAME
      output for the same input (deterministic), but you cannot work
      backwards from the hash to the original value. This is ideal for:
        - Joining datasets without exposing PII (both datasets hash the
          same ID → same hash → can be linked without sharing raw IDs)
        - GDPR pseudonymisation (recital 26) – "no longer attributed
          to a specific data subject without additional information"
        - PECA compliance – hashed data leaked in a breach is useless
          to an attacker without the original values.

    TEACHING NOTE:
      hashlib.sha256() is Python's interface to the SHA-256 algorithm.
      .encode() converts the string to bytes (required by hashlib).
      .hexdigest() returns the hash as a 64-character hex string.

    IRREVERSIBLE (computationally): Brute-forcing SHA-256 is infeasible
    for unique values. For low-entropy data (e.g., 4-digit PINs), a
    rainbow table attack is possible – always salt such data in production!

    Parameters:
        series (pd.Series): Column of values.

    Returns:
        pd.Series: SHA-256 hex digests.
    """

    def hash_value(value):
        if pd.isna(value) or str(value).strip() == "":
            return value   # Leave empty cells unchanged
        # Encode to bytes, compute SHA-256, return hex string
        return hashlib.sha256(str(value).encode("utf-8")).hexdigest()

    return series.apply(hash_value)


# =============================================================================
# SECTION 3 – GENERALIZATION / AGGREGATION
# =============================================================================

def apply_generalization(series, pii_type="Generic"):
    """
    Replace precise values with broader ranges or categories.

    EXAMPLES:
      Age 23        → "20-29"
      DOB 15/03/1998 → "1998"
      IP 192.168.1.5 → "192.168.x.x"
      Address "123 Main St, Lahore" → "Lahore"

    WHY GENERALIZATION?
      Generalization is the core technique of k-anonymity (Sweeney, 2002).
      By replacing specific values with ranges, we ensure that any record
      looks identical to at least k-1 other records on those attributes,
      making individual re-identification much harder.

      GDPR "data minimisation" principle: we retain only what is necessary.
      A researcher studying age trends doesn't need exact ages – ranges
      (age bands) provide the same analytical value.

    Parameters:
        series   (pd.Series): Column values.
        pii_type (str)      : Controls which generalization logic to apply.

    Returns:
        pd.Series: Generalized values.
    """

    def generalize_age(value):
        """Convert an exact age integer to a decade range."""
        try:
            age = int(float(str(value)))
            lower = (age // 10) * 10     # e.g., 23 → 20
            upper = lower + 9            # e.g., 23 → 29
            return f"{lower}-{upper}"
        except (ValueError, TypeError):
            return value   # Can't parse – return as-is

    def generalize_dob(value):
        """Extract just the year from a date of birth string."""
        if pd.isna(value) or str(value).strip() == "":
            return value
        value_str = str(value)
        # Try to find a 4-digit year in the string
        year_match = re.search(r"\b(19|20)\d{2}\b", value_str)
        if year_match:
            return year_match.group()
        return value_str   # Couldn't find year – return original

    def generalize_ip(value):
        """Mask last two octets of an IPv4 address."""
        if pd.isna(value) or str(value).strip() == "":
            return value
        # Replace 3rd and 4th octet with 'x'
        parts = str(value).split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.x.x"
        return value

    def generalize_address(value):
        """Keep only city-level information from an address."""
        if pd.isna(value) or str(value).strip() == "":
            return value
        # Heuristic: the last comma-separated segment is usually city/country
        parts = [p.strip() for p in str(value).split(",")]
        if len(parts) >= 2:
            return parts[-1]   # Return last part (likely city or country)
        return "[Location Generalized]"

    # --- Select the appropriate generalization strategy ---
    if pii_type == "Age":
        return series.apply(lambda v: generalize_age(v) if not pd.isna(v) else v)

    elif pii_type == "Date of Birth":
        return series.apply(generalize_dob)

    elif pii_type == "IP Address":
        return series.apply(generalize_ip)

    elif pii_type == "Address":
        return series.apply(generalize_address)

    else:
        # Generic generalization: replace with a placeholder that signals
        # the data was reduced but the field type is preserved.
        return series.apply(
            lambda v: "[GENERALIZED]" if not pd.isna(v) and str(v).strip() != "" else v
        )


# =============================================================================
# SECTION 4 – FAKE DATA REPLACEMENT (PSEUDONYMIZATION)
# =============================================================================

# This dictionary stores the pseudonymization mapping for the current session.
# Key   → original value (what was in the CSV)
# Value → fake replacement (generated by Faker)
#
# WHY A GLOBAL MAPPING DICT?
#   Consistency: if "Ali Hassan" appears 50 times, it should map to the
#   SAME fake name every time. We check this dict first before generating
#   a new fake value. This is essential for data integrity – if you're
#   pseudonymizing a student roster and the same student appears in
#   multiple rows, all rows must use the same pseudonym.
#
# REVERSIBILITY:
#   This mapping is exported as a JSON file. An authorized user with the
#   key file can reverse the pseudonymization. The key file itself must
#   be secured separately (GDPR Article 32, PECA Section 4).

_pseudo_mapping = {}   # { original_value: fake_value }


def apply_fake_data(series, pii_type="Generic", locale="en_US"):
    """
    Replace each unique value with realistic fake data using the Faker library.

    EXAMPLES:
      "Ali Hassan"           → "James Cooper"
      "ali@example.com"      → "jcooper@fakeemail.net"
      "0300-1234567"         → "+1-800-555-0199"

    WHY FAKER?
      Faker generates statistically realistic (but entirely fictional) data.
      Realistic fake data is important for:
        - Testing systems without using real PII in dev/QA environments
        - Sharing datasets with third parties (researchers, vendors)
          while maintaining analytical value.
      This technique is REVERSIBLE if the mapping dictionary is saved.

    ETHICAL NOTE:
      The generated mapping file (key) must be treated as SENSITIVE DATA.
      Losing the key means permanent irreversibility. Leaking the key
      means the pseudonymization is broken. Treat it like a password!

    Parameters:
        series   (pd.Series): Column values.
        pii_type (str)      : Controls which Faker generator to use.
        locale   (str)      : Faker locale (default English, US).

    Returns:
        pd.Series: Pseudonymized values.
    """
    # Import Faker here (lazy import) to give a clear error if not installed
    try:
        from faker import Faker
    except ImportError:
        raise ImportError(
            "The 'faker' library is not installed.\n"
            "Please run: pip install faker"
        )

    # Create a Faker instance with the chosen locale
    fake = Faker(locale)
    # Seed Faker for reproducibility during the same session
    # (same input → same output if seeded the same way)
    Faker.seed(42)

    def get_fake_value(value):
        """Return a consistent fake replacement for a single value."""
        global _pseudo_mapping

        if pd.isna(value) or str(value).strip() == "":
            return value   # Leave empty cells unchanged

        original = str(value).strip()

        # If we've already generated a fake for this exact value, reuse it
        # (ensures consistency across multiple rows with the same PII)
        if original in _pseudo_mapping:
            return _pseudo_mapping[original]

        # --- Generate a new fake value based on PII type ---
        if pii_type == "Full Name":
            fake_val = fake.name()
        elif pii_type == "Email":
            fake_val = fake.email()
        elif pii_type == "Phone":
            fake_val = fake.phone_number()
        elif pii_type == "Address":
            fake_val = fake.address().replace("\n", ", ")
        elif pii_type == "Date of Birth":
            fake_val = fake.date_of_birth(minimum_age=18, maximum_age=80).strftime("%Y-%m-%d")
        elif pii_type == "Credit Card":
            fake_val = fake.credit_card_number()
        elif pii_type == "Student/Employee ID":
            fake_val = "ID-" + fake.numerify("######")
        elif pii_type == "CNIC":
            # Generate a fake CNIC in the correct Pakistani format
            fake_val = fake.numerify("#####-#######-#")
        elif pii_type == "IP Address":
            fake_val = fake.ipv4_private()
        else:
            # Generic: use a UUID-like random word combination
            fake_val = fake.bothify(text="??##-??##", letters="ABCDEFGHIJKLMNOPQRSTUVWXYZ")

        # Store in the mapping dictionary for consistency
        _pseudo_mapping[original] = fake_val
        return fake_val

    return series.apply(get_fake_value)


# =============================================================================
# SECTION 5 – DELETION / NULL REPLACEMENT
# =============================================================================

def apply_deletion(series, mode="null"):
    """
    Replace column values with NULL or [REDACTED], or drop the column entirely.

    MODES:
      "null"     → Replace with empty string (represents SQL NULL in CSV)
      "redacted" → Replace with the literal string "[REDACTED]"

    Note: Actual column DROPPING is handled in the main processing pipeline
    (app.py), not here. This function handles value-level deletion.

    WHY DELETION?
      The most aggressive privacy technique. Used when:
        - The data is unnecessary for the intended purpose (data minimisation)
        - The data subject exercised GDPR "right to erasure" (Article 17)
        - The column contains highly sensitive data with no analytical need

    Parameters:
        series (pd.Series): Column values.
        mode   (str)      : "null" or "redacted".

    Returns:
        pd.Series: All values replaced.
    """
    if mode == "redacted":
        # Replace every non-empty cell with the literal string [REDACTED]
        return series.apply(
            lambda v: "[REDACTED]" if not pd.isna(v) and str(v).strip() != "" else v
        )
    else:
        # Replace every non-empty cell with an empty string (NULL equivalent)
        return series.apply(
            lambda v: "" if not pd.isna(v) and str(v).strip() != "" else v
        )


# =============================================================================
# SECTION 6 – DISPATCHER: APPLY TECHNIQUE BY NAME
# =============================================================================

def apply_technique(series, technique, pii_type="Generic"):
    """
    Central dispatcher – calls the correct transformation function based on
    the technique name selected by the user in the UI.

    Parameters:
        series    (pd.Series): The column to transform.
        technique (str)      : One of: "Masking", "Hashing", "Generalization",
                               "Fake Data", "Null/Deletion", "Redaction".
        pii_type  (str)      : PII type (passed through to sub-functions).

    Returns:
        pd.Series: Transformed column.
    """
    if technique == "Masking":
        return apply_masking(series, pii_type)

    elif technique == "Hashing":
        return apply_hashing(series)

    elif technique == "Generalization":
        return apply_generalization(series, pii_type)

    elif technique == "Fake Data":
        return apply_fake_data(series, pii_type)

    elif technique == "Null/Deletion":
        return apply_deletion(series, mode="null")

    elif technique == "Redaction":
        return apply_deletion(series, mode="redacted")

    else:
        # Unknown technique – return original column with a warning
        print(f"[WARNING] Unknown technique '{technique}'. Column left unchanged.")
        return series


# =============================================================================
# SECTION 7 – PSEUDONYMIZATION KEY MANAGEMENT
# =============================================================================

def get_pseudo_mapping():
    """
    Return the current session's pseudonymization mapping dictionary.
    Called after processing to export the key file.
    """
    return dict(_pseudo_mapping)   # Return a copy to prevent external mutation


def clear_pseudo_mapping():
    """
    Clear the session mapping. Call this before processing a new file
    so mappings from a previous run don't contaminate the new session.
    """
    global _pseudo_mapping
    _pseudo_mapping = {}


def export_pseudo_key(output_path, input_file, columns_processed):
    """
    Export the pseudonymization mapping to a JSON file.

    The key file contains:
      - Metadata (timestamp, source file, columns)
      - A WARNING that this file is SENSITIVE
      - The full mapping: { original_value: fake_value }

    SECURITY NOTE (PECA / GDPR Article 32):
      This file is as sensitive as the original dataset. It should be:
        1. Stored separately from the anonymized CSV
        2. Encrypted at rest (AES-256 in production)
        3. Access-controlled (only authorized personnel)
        4. Logged whenever it is accessed (audit trail)

    Parameters:
        output_path       (str)  : Full path for the JSON key file.
        input_file        (str)  : Original CSV filename (for metadata).
        columns_processed (list) : List of column names that were pseudonymized.

    Returns:
        str: The path where the key file was saved.
    """
    mapping = get_pseudo_mapping()

    key_data = {
        # ---- METADATA ----
        "metadata": {
            "generated_at"      : datetime.now().isoformat(),
            "source_file"       : os.path.basename(input_file),
            "pseudonymized_cols": columns_processed,
            "total_mappings"    : len(mapping),
            "tool"              : "CSV-Anonymizer v1.0"
        },

        # ---- ETHICAL / LEGAL WARNING ----
        "SECURITY_WARNING": (
            "THIS FILE IS HIGHLY SENSITIVE. It contains the mapping between "
            "original PII values and their pseudonymized replacements. "
            "Unauthorized disclosure of this file defeats the purpose of "
            "pseudonymization and may constitute a GDPR/PECA violation. "
            "Store this file separately from the anonymized dataset, "
            "encrypt it at rest, and restrict access to authorized personnel only."
        ),

        # ---- THE ACTUAL MAPPING ----
        "mapping": mapping
    }

    # Write the key file as formatted (indented) JSON for readability
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(key_data, f, indent=4, ensure_ascii=False)

    return output_path


# =============================================================================
# SECTION 8 – LIST OF AVAILABLE TECHNIQUE NAMES (for UI dropdowns)
# =============================================================================

TECHNIQUE_NAMES = [
    "Masking",
    "Hashing",
    "Generalization",
    "Fake Data",
    "Null/Deletion",
    "Redaction",
]
