import hashlib
import hmac
import logging
from typing import Any, Dict, Iterable, Iterator, List
import pandas as pd
from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from .recognizers import get_custom_recognizers

# Silence noisy Presidio internal logs
logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)
logging.getLogger("presidio-anonymizer").setLevel(logging.ERROR)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("PIIShield")

# Only scan for relevant PII & Secrets (prevents false positives like UK_NHS on 10-digit SKUs)
TARGET_ENTITIES = [
    "PERSON",
    "EMAIL_ADDRESS",
    "IN_PHONE",
    "IN_PAN",
    "IN_AADHAAR",
    "CREDIT_CARD",
    "CRYPTO",
    "IP_ADDRESS",
    "IBAN_CODE",
    "CONFIG_SECRET"
]

class PIIShieldEngine:
    def __init__(self, secret_key: str = "piishield-default-secret", score_threshold: float = 0.5):
        self.secret_key = secret_key.encode("utf-8")
        self.score_threshold = score_threshold
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        
        for rec in get_custom_recognizers():
            self.analyzer.registry.add_recognizer(rec)
            
        self.reset_audit_log()

    def reset_audit_log(self):
        self.audit_log = {
            "scanned_fields": 0,
            "transformed_entities": 0,
            "by_entity_type": {},
            "by_policy_applied": {},
            "malformed_inputs_handled": 0,
            "policy_conflicts_resolved": 0
        }

    def generate_stable_token(self, raw_value: str, entity_type: str) -> str:
        """Deterministic HMAC-SHA256 token preserving referential integrity across datasets."""
        normalized = raw_value.strip().lower().encode("utf-8")
        digest = hmac.new(self.secret_key, normalized, hashlib.sha256).hexdigest()[:10]
        return f"<{entity_type}_{digest}>"

    def _deduplicate_results(self, results: List[RecognizerResult]) -> List[RecognizerResult]:
        """Removes overlapping entity spans, keeping the highest-scoring or longest match."""
        if not results:
            return []
        # Sort by score descending, then span length descending
        sorted_res = sorted(results, key=lambda r: (r.score, r.end - r.start), reverse=True)
        filtered = []
        for candidate in sorted_res:
            overlap = any(
                not (candidate.end <= kept.start or candidate.start >= kept.end)
                for kept in filtered
            )
            if not overlap:
                filtered.append(candidate)
        return filtered

    def _resolve_policy(self, field_name: str, entity_type: str, policies: Dict[str, Any]) -> str:
        field_pol = policies.get("field_policies", {}).get(field_name)
        entity_pol = policies.get("entity_policies", {}).get(entity_type)
        
        if field_pol and entity_pol and field_pol != entity_pol:
            self.audit_log["policy_conflicts_resolved"] += 1
            return field_pol
            
        return field_pol or entity_pol or policies.get("default_policy", "tokenize")

    def transform_text(self, text: Any, field_name: str = "", policies: Dict[str, Any] = None) -> Any:
        policies = policies or {}
        if text is None or isinstance(text, (int, float, bool)):
            return text
        if not isinstance(text, str):
            self.audit_log["malformed_inputs_handled"] += 1
            logger.warning(f"Malformed non-string input encountered at field '{field_name}'. Safely skipped.")
            return "[MALFORMED_INPUT]"

        text = text.strip()
        if not text:
            return text

        self.audit_log["scanned_fields"] += 1
        # Split field_name into individual context tokens (e.g. "mobile_contact" -> ["mobile", "contact"])
        context_words = field_name.lower().replace("-", "_").split("_") if field_name else None

        try:
            raw_results = self.analyzer.analyze(
                text=text,
                language="en",
                entities=TARGET_ENTITIES,
                context=context_words,
                score_threshold=self.score_threshold
            )
            results = self._deduplicate_results(raw_results)
            if not results:
                return text

            operators = {}
            for res in results:
                chosen_policy = self._resolve_policy(field_name, res.entity_type, policies)
                self.audit_log["transformed_entities"] += 1
                self.audit_log["by_entity_type"][res.entity_type] = self.audit_log["by_entity_type"].get(res.entity_type, 0) + 1
                self.audit_log["by_policy_applied"][chosen_policy] = self.audit_log["by_policy_applied"].get(chosen_policy, 0) + 1

                if chosen_policy == "mask":
                    operators[res.entity_type] = OperatorConfig("mask", {"chars_to_mask": 4, "masking_char": "*", "from_end": True})
                elif chosen_policy == "redact":
                    operators[res.entity_type] = OperatorConfig("replace", {"new_value": f"[REDACTED_{res.entity_type}]"})
                else:
                    operators[res.entity_type] = OperatorConfig(
                        "custom",
                        {"lambda": lambda val, et=res.entity_type: self.generate_stable_token(val, et)}
                    )

            return self.anonymizer.anonymize(text=text, analyzer_results=results, operators=operators).text

        except Exception as e:
            self.audit_log["malformed_inputs_handled"] += 1
            logger.error(f"Transformation error in field '{field_name}' ({type(e).__name__}). Value suppressed to prevent PII leak.")
            return "[ERROR_VALUE_SUPPRESSED]"

    def transform_record(self, record: Any, policies: Dict[str, Any] = None, parent_key: str = "") -> Any:
        if isinstance(record, dict):
            return {k: self.transform_record(v, policies, parent_key=k) for k, v in record.items()}
        elif isinstance(record, list):
            return [self.transform_record(item, policies, parent_key=parent_key) for item in record]
        elif isinstance(record, str):
            return self.transform_text(record, field_name=parent_key, policies=policies)
        return record

    def process_dataframe_incrementally(self, df_iterator: Iterable[pd.DataFrame], policies: Dict[str, Any] = None) -> Iterator[pd.DataFrame]:
        for chunk in df_iterator:
            transformed_chunk = chunk.copy()
            for col in transformed_chunk.select_dtypes(include=["object", "string"]).columns:
                transformed_chunk[col] = transformed_chunk[col].apply(
                    lambda val: self.transform_text(val, field_name=col, policies=policies)
                )
            yield transformed_chunk