# =============================================================================
# profiles.py  –  Use-Case Profiles (Pre-configured Templates)
# =============================================================================
# PURPOSE:
#   Provides pre-built configuration templates for common real-world
#   use cases. Each profile defines:
#     - Which PII types to prioritize detecting
#     - Default techniques for each PII type in that context
#     - Compliance frameworks applicable to that domain
#     - A brief description for display in the UI
#
# WHY PROFILES?
#   Different domains have different legal obligations and risk profiles.
#   A healthcare dataset containing diagnoses has different requirements
#   than a university student roster. Profiles allow users to apply
#   context-appropriate settings with a single click, reducing the chance
#   of misconfiguration and demonstrating awareness of domain-specific
#   compliance requirements.
#
# COURSE ALIGNMENT:
#   This feature directly maps to the "Data Classification" lecture topic
#   (confidential vs. sensitive vs. public data) and the idea that privacy
#   controls must be proportionate to the sensitivity of the data.
# =============================================================================


# =============================================================================
# PROFILE DEFINITIONS
# =============================================================================
# Each profile is a dictionary with:
#   "name"        : Display name in the UI
#   "description" : Short description for tooltips/labels
#   "icon"        : An emoji for visual distinction
#   "compliance"  : Applicable legal/regulatory frameworks
#   "techniques"  : { pii_type: recommended_technique }
#                   (overrides the PII_DEFINITIONS defaults for this context)
#   "priority_pii": PII types this profile focuses on (for UI highlighting)
# =============================================================================

PROFILES = {

    # -------------------------------------------------------------------------
    # PROFILE 1: Academic / Research
    # -------------------------------------------------------------------------
    # Context: University datasets – student records, survey data, research
    # datasets containing grades, attendance, or demographic information.
    #
    # Key legal considerations:
    #   - GDPR (if EU institutions or EU data subjects involved)
    #   - HEC (Higher Education Commission Pakistan) data protection guidelines
    #   - Purpose limitation: research data should only be used for stated
    #     research purposes. Student IDs should be pseudonymized to allow
    #     longitudinal analysis without exposing identity.
    # -------------------------------------------------------------------------
    "Academic/Research": {
        "name"       : "Academic / Research",
        "icon"       : "🎓",
        "description": (
            "For university student records, survey data, and research "
            "datasets. Balances analytical utility with GDPR and HEC "
            "data protection requirements. Student IDs are pseudonymized "
            "to allow longitudinal research while protecting identity."
        ),
        "compliance" : ["GDPR", "HEC Guidelines", "Data Minimisation (Art. 5)"],
        "techniques" : {
            "Full Name"         : "Fake Data",        # Replace with realistic fake name
            "Email"             : "Masking",           # Partial mask preserves format
            "Date of Birth"     : "Generalization",    # Year only (age band for DOB)
            "Student/Employee ID": "Hashing",          # Consistent hash for re-linking
            "Phone"             : "Masking",
            "Address"           : "Generalization",    # City-level only
            "CNIC"              : "Hashing",           # Irreversible – high sensitivity
            "Age"               : "Generalization",    # Age band (e.g. 20–29)
            "Credit Card"       : "Null/Deletion",     # No legitimate research need
            "IP Address"        : "Generalization",    # Network-level only
        },
        "priority_pii": [
            "Full Name", "Student/Employee ID", "Email", "Date of Birth", "CNIC"
        ]
    },

    # -------------------------------------------------------------------------
    # PROFILE 2: Corporate / HR
    # -------------------------------------------------------------------------
    # Context: Enterprise HR datasets – employee records, payroll data,
    # performance reviews, contact directories.
    #
    # Key legal considerations:
    #   - PECA 2016 (Prevention of Electronic Crimes Act – Pakistan)
    #     Sections 3 & 4: Unauthorized access to data systems.
    #   - Employment data is classified as SENSITIVE under most privacy laws.
    #   - Salary data, CNICs, and contact info require strong protection.
    #   - Internal analytics (e.g., workforce demographics) can use
    #     generalized data rather than raw PII.
    # -------------------------------------------------------------------------
    "Corporate/HR": {
        "name"       : "Corporate / HR",
        "icon"       : "🏢",
        "description": (
            "For employee records, HR datasets, and corporate contact "
            "directories. Aligned with PECA 2016 data protection principles "
            "and general employment privacy standards. Strong protection for "
            "CNICs, salaries, and personal contacts."
        ),
        "compliance" : ["PECA 2016 (S.3 & S.4)", "GDPR", "Employment Privacy"],
        "techniques" : {
            "Full Name"         : "Fake Data",       # Pseudonymize for internal analytics
            "Email"             : "Masking",
            "CNIC"              : "Hashing",         # CNICs are highly sensitive in Pakistan
            "Phone"             : "Masking",
            "Address"           : "Generalization",
            "Student/Employee ID": "Hashing",        # Consistent internal identifier
            "Date of Birth"     : "Generalization",
            "Age"               : "Generalization",
            "Credit Card"       : "Null/Deletion",   # No HR justification
            "IP Address"        : "Generalization",
        },
        "priority_pii": [
            "Full Name", "CNIC", "Phone", "Email", "Student/Employee ID"
        ]
    },

    # -------------------------------------------------------------------------
    # PROFILE 3: Healthcare / Patient Records
    # -------------------------------------------------------------------------
    # Context: Medical records, patient data, clinical research datasets,
    # hospital management systems.
    #
    # Key legal considerations:
    #   - HIPAA (Health Insurance Portability and Accountability Act – US)
    #     Security Rule requires administrative, physical, and technical
    #     safeguards for Protected Health Information (PHI).
    #   - GDPR Article 9: Health data is a "special category" requiring
    #     explicit consent and heightened protection.
    #   - Medical IDs and diagnoses combined with demographics create
    #     high re-identification risk (Latanya Sweeney, 2002 study).
    #   - Principle of Minimum Necessary: only the minimum PHI needed
    #     for the specific purpose should be disclosed.
    # -------------------------------------------------------------------------
    "Healthcare": {
        "name"       : "Healthcare / Patient Records",
        "icon"       : "🏥",
        "description": (
            "For patient records, clinical datasets, and medical research. "
            "Implements HIPAA-style 'Safe Harbor' de-identification: removes "
            "or generalizes all 18 HIPAA identifiers where applicable. "
            "Highest level of protection for diagnoses and medical IDs."
        ),
        "compliance" : ["HIPAA Security Rule", "GDPR Art. 9 (Special Categories)",
                        "Data Minimisation"],
        "techniques" : {
            "Full Name"         : "Redaction",        # Complete removal for PHI
            "Date of Birth"     : "Generalization",   # Year only (HIPAA Safe Harbor)
            "Phone"             : "Null/Deletion",    # Remove entirely
            "Address"           : "Generalization",   # City or state level only
            "Email"             : "Null/Deletion",    # Remove entirely
            "Student/Employee ID": "Hashing",         # Medical record number → hash
            "CNIC"              : "Hashing",
            "Age"               : "Generalization",   # Age ≥ 90 → "90+" (HIPAA rule)
            "IP Address"        : "Null/Deletion",    # Remove entirely
            "Credit Card"       : "Null/Deletion",
        },
        "priority_pii": [
            "Full Name", "Date of Birth", "Phone", "Address",
            "Student/Employee ID", "CNIC"
        ]
    },
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_profile_names():
    """
    Return a list of profile display names for the UI dropdown.

    Returns:
        list[str]: Profile keys (also used as display names).
    """
    return list(PROFILES.keys())


def get_profile(profile_name):
    """
    Retrieve a profile configuration dictionary by name.

    Parameters:
        profile_name (str): Key from PROFILES dict.

    Returns:
        dict or None: The profile dict, or None if not found.
    """
    return PROFILES.get(profile_name, None)


def get_technique_for_pii(profile_name, pii_type):
    """
    Look up the recommended technique for a given PII type within a profile.
    Falls back to the global PII_DEFINITIONS default if not in the profile.

    Parameters:
        profile_name (str): The profile to look up.
        pii_type     (str): PII type name.

    Returns:
        str: Technique name (e.g. "Masking", "Hashing").
    """
    profile = get_profile(profile_name)
    if profile and pii_type in profile["techniques"]:
        return profile["techniques"][pii_type]

    # Fallback: import and use the global default from pii_detector
    from pii_detector import get_default_technique
    return get_default_technique(pii_type)
