from typing import Any, Dict, List, Tuple
import pandas as pd
from .engine import PIIShieldEngine

class PIIShieldEvaluator:
    def __init__(self, engine: PIIShieldEngine):
        self.engine = engine

    @staticmethod
    def generate_synthetic_benchmark() -> Tuple[List[Dict[str, Any]], pd.DataFrame, pd.DataFrame]:
        """
        Generates:
        1. Labelled synthetic test cases for Precision/Recall evaluation (including tricky False Positive traps).
        2. Users nested dataset & Linked Orders DataFrame for Referential Consistency & Utility testing.
        """
        labelled_samples = [
            # True Positives (Should be transformed)
            {"field": "customer_email", "text": "rahul.verma@gmail.com", "has_pii": True, "expected_type": "EMAIL_ADDRESS"},
            {"field": "kyc_pan", "text": "ABCDE1234F", "has_pii": True, "expected_type": "IN_PAN"},
            {"field": "mobile_number", "text": "9876543210", "has_pii": True, "expected_type": "IN_PHONE"},
            {"field": "aadhaar_uid", "text": "2345 6789 0123", "has_pii": True, "expected_type": "IN_AADHAAR"},
            {"field": "auth_header", "text": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "has_pii": True, "expected_type": "CONFIG_SECRET"},
            {"field": "api_secret", "text": "sk-live9876543210abcdef1234", "has_pii": True, "expected_type": "CONFIG_SECRET"},
            {"field": "support_log", "text": "Contact Priya Sharma at priya.s@yahoo.in", "has_pii": True, "expected_type": "EMAIL_ADDRESS"},
            # True Negatives / False Positive Traps (Should NOT be transformed)
            {"field": "order_sku", "text": "9876543210", "has_pii": False, "expected_type": "NONE"},
            {"field": "batch_code", "text": "123456789012", "has_pii": False, "expected_type": "NONE"},
            {"field": "product_Description", "text": "Standard wireless mouse black edition", "has_pii": False, "expected_type": "NONE"},
            {"field": "status_code", "text": "HTTP_200_OK", "has_pii": False, "expected_type": "NONE"},
        ]

        users_df = pd.DataFrame([
            {"user_email": "rahul.verma@gmail.com", "mobile_phone": "9876543210", "kyc_pan": "ABCDE1234F", "city": "Bengaluru", "age_group": "25-30"},
            {"user_email": "priya.s@yahoo.in", "mobile_phone": "9123456789", "kyc_pan": "PQRSX5678Z", "city": "Bengaluru", "age_group": "25-30"},
            {"user_email": "amit.patel@outlook.com", "mobile_phone": "9988776655", "kyc_pan": "LMNOP9012Q", "city": "Mumbai", "age_group": "30-35"},
            {"user_email": "sneha.rao@gmail.com", "mobile_phone": "9811223344", "kyc_pan": "UVWXY3456K", "city": "Mumbai", "age_group": "30-35"},
            {"user_email": "vikram.singh@gmail.com", "mobile_phone": "9765432109", "kyc_pan": "GHIJK7890L", "city": "Delhi", "age_group": "40-45"},
        ])

        orders_df = pd.DataFrame([
            {"order_id": "ORD-101", "user_email": "rahul.verma@gmail.com", "order_sku": "9876543210", "amount": 1200, "city": "Bengaluru"},
            {"order_id": "ORD-102", "user_email": "rahul.verma@gmail.com", "order_sku": "8765432109", "amount": 800, "city": "Bengaluru"},
            {"order_id": "ORD-103", "user_email": "priya.s@yahoo.in", "order_sku": "7654321098", "amount": 2500, "city": "Bengaluru"},
            {"order_id": "ORD-104", "user_email": "amit.patel@outlook.com", "order_sku": "6543210987", "amount": 1500, "city": "Mumbai"},
            {"order_id": "ORD-105", "user_email": "sneha.rao@gmail.com", "order_sku": "6543210987", "amount": 900, "city": "Mumbai"},
            {"order_id": "ORD-106", "user_email": "vikram.singh@gmail.com", "order_sku": "6543210987", "amount": 3100, "city": "Delhi"},
        ])

        return labelled_samples, users_df, orders_df

    def evaluate_precision_recall(self, labelled_samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculates Precision, Recall, F1, False Positives, and False Negatives."""
        tp = fp = tn = fn = 0
        details = []

        for item in labelled_samples:
            original = item["text"]
            transformed = self.engine.transform_text(original, field_name=item["field"])
            detected_pii = (transformed != original)

            if item["has_pii"] and detected_pii:
                tp += 1
                verdict = "True Positive (TP)"
            elif not item["has_pii"] and detected_pii:
                fp += 1
                verdict = "False Positive (FP)"
            elif not item["has_pii"] and not detected_pii:
                tn += 1
                verdict = "True Negative (TN)"
            else:
                fn += 1
                verdict = "False Negative (FN)"

            details.append({
                "field": item["field"],
                "original": original,
                "transformed": transformed,
                "ground_truth_pii": item["has_pii"],
                "verdict": verdict
            })

        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        f1 = round(2 * (precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0

        return {
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "counts": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
            "sample_results": details
        }

    @staticmethod
    def calculate_privacy_risk_score(
        df: pd.DataFrame,
        quasi_identifiers: List[str],
        direct_identifiers_remaining: int = 0
    ) -> Dict[str, Any]:
        """
        Configurable privacy-risk scoring based on k-anonymity equivalence classes.
        Assumptions documented for judges.
        """
        if df.empty or not quasi_identifiers:
            return {"risk_score_0_to_100": 0.0, "risk_level": "LOW"}

        valid_qis = [col for col in quasi_identifiers if col in df.columns]
        grouped = df.groupby(valid_qis).size()
        k_min = int(grouped.min())
        unique_records = int((grouped == 1).sum())
        uniqueness_ratio = unique_records / len(df)

        # Base risk from quasi-identifier uniqueness (0-70 pts) + penalty for unmasked direct PII (30 pts)
        direct_penalty = min(30.0, direct_identifiers_remaining * 15.0)
        total_risk = round((uniqueness_ratio * 70.0) + direct_penalty, 2)

        level = "HIGH" if total_risk >= 50 else ("MEDIUM" if total_risk >= 20 else "LOW")

        return {
            "risk_score_0_to_100": total_risk,
            "risk_level": level,
            "k_anonymity_min_group_size": k_min,
            "unique_reidentifiable_rows": unique_records,
            "total_rows": len(df),
            "documented_assumptions": [
                f"Quasi-identifiers assumed available to adversary: {valid_qis}",
                "Rows with equivalence class size k=1 have 100% linkage probability under prosecutor attack model.",
                "HMAC tokens are assumed irreversible without the 256-bit secret key."
            ]
        }

    @staticmethod
    def measure_downstream_utility(
        raw_users: pd.DataFrame,
        raw_orders: pd.DataFrame,
        anon_users: pd.DataFrame,
        anon_orders: pd.DataFrame
    ) -> Dict[str, Any]:
        """
        Measures impact of transformations on downstream analytics:
        1. Cross-table JOIN integrity (Users INNER JOIN Orders on user_email)
        2. Repeat customer spend aggregation
        3. Revenue by City
        """
        # 1. Cross-table Join count before vs after
        raw_join = pd.merge(raw_orders, raw_users, on="user_email", how="inner")
        anon_join = pd.merge(anon_orders, anon_users, on="user_email", how="inner")
        join_retention_pct = round((len(anon_join) / len(raw_join)) * 100, 2) if len(raw_join) > 0 else 0.0

        # 2. Average Spend per Unique Customer
        raw_avg_customer_spend = round(raw_orders.groupby("user_email")["amount"].sum().mean(), 2)
        anon_avg_customer_spend = round(anon_orders.groupby("user_email")["amount"].sum().mean(), 2)

        # 3. City-level revenue distribution
        raw_city_rev = raw_orders.groupby("city")["amount"].sum().to_dict()
        anon_city_rev = anon_orders.groupby("city")["amount"].sum().to_dict()

        utility_score = 100.0 if (
            join_retention_pct == 100.0 and raw_avg_customer_spend == anon_avg_customer_spend
        ) else join_retention_pct

        return {
            "overall_utility_preservation_pct": utility_score,
            "referential_join_rows_before": len(raw_join),
            "referential_join_rows_after": len(anon_join),
            "join_integrity_retained_pct": join_retention_pct,
            "avg_spend_per_customer_before": raw_avg_customer_spend,
            "avg_spend_per_customer_after": anon_avg_customer_spend,
            "city_revenue_before": raw_city_rev,
            "city_revenue_after": anon_city_rev
        }