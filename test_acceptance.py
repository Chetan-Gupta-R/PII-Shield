from piishield_core.engine import PIIShieldEngine
from piishield_core.evaluator import PIIShieldEvaluator

def test_context_aware_detection_and_false_positive_prevention():
    engine = PIIShieldEngine(secret_key="test-key")
    # 10-digit number in an SKU field must NOT be transformed
    assert engine.transform_text("9876543210", field_name="order_sku") == "9876543210"
    # Same 10-digit number in a mobile field MUST be transformed
    assert engine.transform_text("9876543210", field_name="mobile_phone").startswith("<IN_PHONE_")

def test_stable_tokenization_and_referential_integrity():
    engine = PIIShieldEngine(secret_key="test-key")
    token_table_a = engine.transform_text("rahul.verma@gmail.com", field_name="user_email")
    token_table_b = engine.transform_text("RAHUL.VERMA@gmail.com ", field_name="customer_email")
    log_transformed = engine.transform_text("Login by rahul.verma@gmail.com succeeded", field_name="server_log")

    assert token_table_a == token_table_b
    assert token_table_a in log_transformed

def test_policy_conflict_resolution():
    engine = PIIShieldEngine(secret_key="test-key")
    policies = {
        "default_policy": "tokenize",
        "entity_policies": {"IN_PAN": "tokenize"},
        "field_policies": {"kyc_pan": "mask"}  # Field-level must override entity-level
    }
    res = engine.transform_text("ABCDE1234F", field_name="kyc_pan", policies=policies)
    assert res == "ABCDE1****"
    assert engine.audit_log["policy_conflicts_resolved"] == 1

def test_zero_leakage_on_malformed_input():
    engine = PIIShieldEngine(secret_key="test-key")
    # Passing an unexpected object type (e.g. raw bytes or custom object) must not leak data
    malformed = b"secret_binary_pan_ABCDE1234F"
    res = engine.transform_text(malformed, field_name="corrupt_field")
    assert res == "[MALFORMED_INPUT]"
    assert "ABCDE1234F" not in res
    assert engine.audit_log["malformed_inputs_handled"] == 1

def test_protection_and_downstream_utility_preservation():
    engine = PIIShieldEngine(secret_key="test-key")
    evaluator = PIIShieldEvaluator(engine)
    samples, raw_users, raw_orders = evaluator.generate_synthetic_benchmark()

    # Verify Precision & Recall >= 95%
    pr = evaluator.evaluate_precision_recall(samples)
    assert pr["precision"] >= 0.95
    assert pr["recall"] >= 0.95

    # Verify 100% Referential Join & Analytical Utility Preservation
    anon_users = next(engine.process_dataframe_incrementally([raw_users]))
    anon_orders = next(engine.process_dataframe_incrementally([raw_orders]))
    utility = evaluator.measure_downstream_utility(raw_users, raw_orders, anon_users, anon_orders)

    assert utility["join_integrity_retained_pct"] == 100.0
    assert utility["avg_spend_per_customer_before"] == utility["avg_spend_per_customer_after"]
    assert utility["city_revenue_before"] == utility["city_revenue_after"]