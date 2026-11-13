# 🛡️ PIIShield — Context-Aware Privacy & Data Transformation Engine

**PIIShield** is a reusable Python privacy library and evaluation suite that detects sensitive personal information and secrets across structured tables, deeply nested JSON payloads, and free-form logs. It applies configurable transformation policies, preserves cross-record referential integrity via deterministic HMAC tokenization, and quantifies both residual disclosure risk and downstream analytical utility.

---

## ✨ Key Capabilities & Requirements Coverage

| Hackathon Requirement | PIIShield Implementation |
| :--- | :--- |
| **Context-Aware PII & Secret Detection** | Combines NLP Named Entity Recognition (`spaCy` / `Presidio`) with lexical context-boosting for Indian PII (`IN_PAN`, `IN_AADHAAR`, `IN_PHONE`) and configured secrets (`Bearer` JWTs, `sk-` API keys, AWS keys). Distinguishes 10-digit phone numbers from 10-digit order SKUs using field/sentence context. |
| **Multi-Format & Incremental Processing** | Recursively parses nested dicts/lists (`transform_record`), free-form text logs (`transform_text`), and streams large tabular datasets in chunks (`process_dataframe_incrementally`). |
| **Referential Consistency (Stable Tokenization)** | Uses keyed `HMAC-SHA256` normalization so identical entities map to the exact same token (e.g., `<EMAIL_ADDRESS_a2937fe17c>`) across relational tables, nested arrays, and server logs—preserving 100% `INNER JOIN` integrity. |
| **Hierarchical Policy Conflict Resolution** | Resolves conflicting rules deterministically: **Field-Level Policy** (`kyc_pan: mask`) $\rightarrow$ **Entity-Level Policy** (`IN_PAN: tokenize`) $\rightarrow$ **Global Default Policy** (`tokenize`), logging every resolved conflict in the audit report. |
| **Zero-Leakage Error & Malformed Input Handling** | Safely traps malformed/binary inputs and runtime exceptions without printing raw sensitive values in stack traces or diagnostic logs. |
| **Precision, Recall & Risk/Utility Benchmarking** | Built-in `PIIShieldEvaluator` computes entity-level Precision, Recall, and $F_1$ on labelled synthetic datasets, $k$-anonymity quasi-identifier re-identification risk (`0–100`), and pre- vs. post-transformation analytical query retention. |

---

## 📂 Project Architecture

```text
piishield/
├── piishield_core/
│   ├── __init__.py
│   ├── recognizers.py    # Custom context-aware recognizers (PAN, Aadhaar, Phone, API Secrets)
│   ├── engine.py         # Core transformation engine, HMAC tokenizer, policy resolver & audit logger
│   └── evaluator.py      # Synthetic benchmark, Precision/Recall, k-Anonymity Risk & Utility metrics
├── app.py                # Interactive 4-tab Streamlit demonstration dashboard
├── test_acceptance.py    # Automated pytest acceptance suite verifying protection & utility
└── README.md             # Documentation, risk assumptions, and architectural limitations
```

---

## 🚀 Quickstart & Installation

### 1. Clone & Set Up Environment
```bash
git clone https://github.com/Chetan-Gupta-R/PII-Shield
cd piishield
python -m venv venv

# Activate on Windows:
venv\Scripts\activate
# Activate on macOS/Linux:
source venv/bin/activate

pip install presidio-analyzer presidio-anonymizer spacy pandas pyyaml faker streamlit pytest
python -m spacy download en_core_web_lg
```

### 2. Run Automated Acceptance Tests
Verify context-aware detection, false-positive prevention, zero-leakage error handling, policy conflict resolution, and 100% downstream `JOIN` utility preservation:
```bash
pytest -v test_acceptance.py
```

### 3. Launch Interactive Demonstration Dashboard
```bash
streamlit run app.py
```

---

## 💻 Library Usage Example

```python
from piishield_core.engine import PIIShieldEngine

engine = PIIShieldEngine(secret_key="production-hmac-secret-key", score_threshold=0.5)

policies = {
    "default_policy": "tokenize",
    "entity_policies": {"CONFIG_SECRET": "redact", "IN_PAN": "tokenize"},
    "field_policies": {"kyc_pan": "mask"}  # Overrides entity_policies['IN_PAN']
}

payload = {
    "customer_email": "rahul.verma@gmail.com",
    "kyc_pan": "ABCDE1234F",
    "order_sku": "9876543210",          # Ignored (no phone context)
    "whatsapp_mobile": "9876543210",    # Tokenized as <IN_PHONE_...>
    "audit_log": "Auth succeeded for rahul.verma@gmail.com with Bearer eyJhbGciOiJIUzI1Ni..."
}

transformed = engine.transform_record(payload, policies=policies)
print(transformed)
print(engine.audit_log)
```

---

## 📐 Privacy-Risk Scoring Assumptions & Methodology

PIIShield calculates a configurable **Residual Privacy Risk Score (`0–100`)** on transformed tabular datasets using an equivalence-class ($k$-anonymity) prosecutor attack model:
1. **Quasi-Identifier Grouping:** User-specified quasi-identifiers (e.g., `["city", "age_group"]`) partition the dataset into equivalence classes.
2. **Uniqueness Penalty (`0–70 points`):** Records belonging to an equivalence class of size $k = 1$ are uniquely re-identifiable if an adversary possesses external demographic knowledge. The base risk scales proportionally with the ratio of unique rows ($\frac{\text{rows with } k=1}{\text{total rows}} \times 70$).
3. **Direct Identifier Penalty (`0–30 points`):** Any unmasked direct PII columns remaining in the dataset add a direct penalty of `15 points` per column (capped at `30`).
4. **Cryptographic Assumption:** Deterministic tokens (`HMAC-SHA256`) are assumed computationally irreversible without the 256-bit secret key.

---

## ⚠️ Known Limitations & Trade-Offs

To support informed deployment decisions, PIIShield explicitly documents the boundaries of its detection and anonymization methods:

1. **Obfuscated or Out-of-Context Unstructured PII:** Context-aware scoring relies on field names and surrounding lexical cues. Highly obfuscated sensitive data (e.g., Base64-encoded Aadhaar numbers, leetspeak, or phone numbers written out in regional transliterated text without context words) may result in False Negatives.
2. **Frequency Analysis on Deterministic Tokens:** While stable `HMAC-SHA256` tokenization preserves 100% relational `JOIN` and `GROUP BY` utility, identical inputs always yield identical tokens. In skewed datasets (e.g., a single power-user accounting for 40% of all orders), an adversary with prior distributional knowledge could link the highest-frequency token back to that individual.
3. **Quasi-Identifier Linkage ($k=1$):** Tokenizing direct identifiers (`email`, `phone`, `PAN`) does not protect against linkage attacks if rare combinations of quasi-identifiers (`city + age_group + profession`) uniquely single out an individual. High-risk tables ($k = 1$) require downstream generalization or suppression before external release.