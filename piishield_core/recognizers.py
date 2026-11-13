from presidio_analyzer import Pattern, PatternRecognizer

def get_custom_recognizers():
    recognizers = []

    # 1. Indian PAN Card (Boosts confidence when KYC/tax words are nearby)
    pan_pattern = Pattern(name="pan_regex", regex=r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", score=0.6)
    recognizers.append(
        PatternRecognizer(
            supported_entity="IN_PAN",
            patterns=[pan_pattern],
            context=["pan", "tax", "kyc", "income", "permanent"]
        )
    )

    # 2. Indian Aadhaar (12 digits starting with 2-9, low base score to avoid false positives)
    aadhaar_pattern = Pattern(name="aadhaar_regex", regex=r"\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b", score=0.4)
    recognizers.append(
        PatternRecognizer(
            supported_entity="IN_AADHAAR",
            patterns=[aadhaar_pattern],
            context=["aadhaar", "uidai", "uid", "kyc", "identity", "govt"]
        )
    )

    # 3. Context-Dependent Indian Mobile Number (Distinguishes Phone vs 10-digit SKU/Order ID)
    phone_pattern = Pattern(name="in_phone_regex", regex=r"\b[6-9][0-9]{9}\b", score=0.35)
    recognizers.append(
        PatternRecognizer(
            supported_entity="IN_PHONE",
            patterns=[phone_pattern],
            context=["phone", "mobile", "contact", "call", "whatsapp", "sms", "cell"]
        )
    )

    # 4. Configured Secrets (API Keys, Bearer Tokens, AWS/Stripe style keys)
    secret_pattern = Pattern(
        name="secret_regex",
        regex=r"\b(sk-[a-zA-Z0-9]{16,}|ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|Bearer\s+[a-zA-Z0-9_\-\.]+)\b",
        score=0.85
    )
    recognizers.append(
        PatternRecognizer(
            supported_entity="CONFIG_SECRET",
            patterns=[secret_pattern],
            context=["key", "secret", "token", "auth", "password", "credential", "api"]
        )
    )

    return recognizers