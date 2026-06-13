# =============================================================================
# pii_detector.py  –  PII Detection Engine
# =============================================================================
# PURPOSE:
#   Scans CSV column headers and sample values using regular expressions
#   to automatically identify columns that likely contain Personally
#   Identifiable Information (PII).
#
# WHY THIS MATTERS (Course Alignment):
#   GDPR Article 4 defines personal data as "any information relating to an
#   identified or identifiable natural person." Before we can protect data,
#   we must FIND it. This module implements the discovery phase of a data
#   privacy workflow.
#
# CIA TRIAD LINK:
#   Confidentiality – we must know what is sensitive before we can
#   restrict access and apply protective transformations.
# =============================================================================

import re   # Python's built-in regular expression library

# -----------------------------------------------------------------------------
# SECTION 1 – PII TYPE DEFINITIONS
# -----------------------------------------------------------------------------
# Each entry maps a human-readable PII type name to:
#   "header_keywords" : words likely to appear in a column header
#   "pattern"         : a regex that matches a typical VALUE in that column
#   "default_tech"    : the recommended anonymization technique for this type
#
# TEACHING NOTE:
#   A regex (regular expression) is a sequence of characters that defines a
#   search pattern. For example, r"\d{3}-\d{7}" matches Pakistani phone
#   numbers like "021-1234567".
# -----------------------------------------------------------------------------

PII_DEFINITIONS = {

    "Email": {
        "header_keywords": ["email", "e-mail", "mail", "contact_email"],
        # Standard email pattern: local-part @ domain . tld
        "pattern": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "default_tech": "Masking"
    },

    "Phone": {
        "header_keywords": ["phone", "mobile", "cell", "contact", "tel", "number"],
        # Matches common phone formats: +92-300-1234567, 0300-1234567, etc.
        "pattern": r"(\+?\d{1,3}[\s\-]?)?\(?\d{2,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{4,7}",
        "default_tech": "Masking"
    },

    "CNIC": {
        "header_keywords": ["cnic", "nic", "national_id", "id_card", "identity"],
        # Pakistani CNIC format: 12345-1234567-1
        "pattern": r"\d{5}-\d{7}-\d{1}",
        "default_tech": "Hashing"
    },

    "Full Name": {
        "header_keywords": ["name", "full_name", "firstname", "lastname",
                            "first_name", "last_name", "student_name",
                            "employee_name", "patient_name"],
        # Two or more words starting with capital letters
        "pattern": r"[A-Z][a-z]+(\s[A-Z][a-z]+)+",
        "default_tech": "Fake Data"
    },

    "Date of Birth": {
        "header_keywords": ["dob", "date_of_birth", "birthdate", "birth_date",
                            "birthday", "born"],
        # Common date formats: DD/MM/YYYY, YYYY-MM-DD, DD-MM-YYYY
        "pattern": r"\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}[\/\-]\d{1,2}[\/\-]\d{1,2}",
        "default_tech": "Generalization"
    },

    "Address": {
        "header_keywords": ["address", "addr", "street", "location",
                            "residence", "city", "zip", "postal"],
        # Matches strings beginning with a number followed by words (e.g. "123 Main St")
        "pattern": r"\d+\s+[A-Za-z\s,\.]+",
        "default_tech": "Generalization"
    },

    "IP Address": {
        "header_keywords": ["ip", "ip_address", "ipaddress", "host", "client_ip"],
        # IPv4 format: four groups of 1-3 digits separated by dots
        "pattern": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "default_tech": "Generalization"
    },

    "Credit Card": {
        "header_keywords": ["card", "credit", "cc", "credit_card",
                            "card_number", "payment"],
        # 16-digit card numbers, optionally grouped with spaces or dashes
        "pattern": r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
        "default_tech": "Masking"
    },

    "Student/Employee ID": {
        "header_keywords": ["id", "student_id", "employee_id", "emp_id",
                            "reg_no", "registration", "roll_no", "staff_id"],
        # Alphanumeric IDs like "STU-2023-001" or "EMP12345"
        "pattern": r"[A-Z]{2,4}[\-]?\d{3,8}",
        "default_tech": "Hashing"
    },

    "Age": {
        "header_keywords": ["age", "years_old", "patient_age"],
        # Age: 1 to 3 digit number (0–130 is reasonable)
        "pattern": r"\b(1[0-2]\d|[1-9]\d|\d)\b",
        "default_tech": "Generalization"
    },
}

# -----------------------------------------------------------------------------
# SECTION 2 – HEADER-BASED DETECTION
# -----------------------------------------------------------------------------

def detect_by_header(column_name):
    """
    Check if a column name (header) suggests it contains a specific PII type.

    HOW IT WORKS:
      1. Convert the column name to lowercase (so "Email" matches "email")
      2. For each PII type, check if any keyword appears in the column name
      3. Return the first matching PII type, or None if no match

    Parameters:
        column_name (str): The CSV column header string.

    Returns:
        str or None: The detected PII type name, or None.
    """
    # Normalize: lowercase and strip whitespace
    col_lower = column_name.lower().strip()

    for pii_type, definition in PII_DEFINITIONS.items():
        for keyword in definition["header_keywords"]:
            # Check if the keyword is contained within the column name
            if keyword in col_lower:
                return pii_type   # Found a match – return immediately

    return None   # No PII type matched this column header


# -----------------------------------------------------------------------------
# SECTION 3 – VALUE-BASED DETECTION
# -----------------------------------------------------------------------------

def detect_by_values(sample_values, pii_type):
    """
    Check if a sample of cell values matches the regex pattern for a given
    PII type.

    WHY SAMPLE? Checking every row in a large CSV would be slow. We check
    the first few non-empty rows (sample) for speed and simplicity.

    Parameters:
        sample_values (list): A list of string cell values from one column.
        pii_type      (str) : The PII type name (key in PII_DEFINITIONS).

    Returns:
        bool: True if a meaningful proportion of samples match the pattern.
    """
    pattern = PII_DEFINITIONS[pii_type]["pattern"]

    matched   = 0   # How many sample values match the pattern
    non_empty = 0   # How many sample values are not empty/null

    for value in sample_values:
        # Skip empty or null-like cells
        if value is None or str(value).strip() in ("", "nan", "NaN", "None"):
            continue
        non_empty += 1
        # re.search() returns a match object if the pattern is found anywhere
        # in the string, or None if there's no match.
        if re.search(pattern, str(value)):
            matched += 1

    if non_empty == 0:
        return False   # Column is entirely empty – not PII

    # Require at least 50% of non-empty samples to match
    # This threshold reduces false positives while catching real PII
    match_ratio = matched / non_empty
    return match_ratio >= 0.5


# -----------------------------------------------------------------------------
# SECTION 4 – MAIN DETECTION FUNCTION
# -----------------------------------------------------------------------------

def detect_pii(dataframe, sample_rows=10):
    """
    Main function: auto-detect PII columns in a pandas DataFrame.

    STRATEGY (two-pass detection):
      Pass 1 – Header match: fast, keyword-based scan of column names.
      Pass 2 – Value match: regex scan of sample cell values.

    A column is flagged if EITHER pass detects a match. This maximises
    recall (catching more PII) at the cost of possible false positives,
    which the user can correct in the manual override table.

    Parameters:
        dataframe  (pd.DataFrame): The loaded CSV data.
        sample_rows (int)        : Number of rows to sample for value matching.

    Returns:
        dict: { column_name: { "pii_type": str, "method": str,
                               "default_tech": str, "include": bool } }
              "method" is "header" or "value" – tells the UI HOW it was found.
              "include" defaults to True (user can uncheck to skip a column).
    """
    results = {}   # We will populate this dictionary and return it

    for col in dataframe.columns:
        # --- Pass 1: Header-based detection ---
        pii_type = detect_by_header(col)
        detection_method = "header"

        # --- Pass 2: Value-based detection (if header didn't match) ---
        if pii_type is None:
            # Extract a sample of non-null values from this column
            sample = dataframe[col].dropna().head(sample_rows).astype(str).tolist()

            # Try every known PII type's regex against the sample
            for pt in PII_DEFINITIONS:
                if detect_by_values(sample, pt):
                    pii_type = pt
                    detection_method = "value"
                    break   # Stop at first match to avoid duplicates

        # --- Store result if PII was found ---
        if pii_type is not None:
            results[col] = {
                "pii_type"    : pii_type,
                "method"      : detection_method,
                "default_tech": PII_DEFINITIONS[pii_type]["default_tech"],
                "include"     : True    # User can set this to False to skip
            }

    return results


# -----------------------------------------------------------------------------
# SECTION 5 – HELPER: GET ALL PII TYPE NAMES
# -----------------------------------------------------------------------------

def get_pii_type_names():
    """
    Return a sorted list of all known PII type names.
    Used by the UI to populate dropdown menus for manual column mapping.
    """
    return sorted(PII_DEFINITIONS.keys())


# -----------------------------------------------------------------------------
# SECTION 6 – HELPER: GET DEFAULT TECHNIQUE FOR A PII TYPE
# -----------------------------------------------------------------------------

def get_default_technique(pii_type):
    """
    Return the recommended (default) anonymization technique for a PII type.
    Returns 'Masking' as a safe fallback for unknown types.
    """
    if pii_type in PII_DEFINITIONS:
        return PII_DEFINITIONS[pii_type]["default_tech"]
    return "Masking"   # Safe default
