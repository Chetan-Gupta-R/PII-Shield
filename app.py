import json
import streamlit as st
import pandas as pd
from piishield_core.engine import PIIShieldEngine
from piishield_core.evaluator import PIIShieldEvaluator

st.set_page_config(page_title="PIIShield — Privacy & Transformation Engine", layout="wide")

st.title("🛡️ PIIShield — Context-Aware Privacy & Data Transformation Engine")
st.markdown(
    "Detects context-dependent PII & secrets, enforces field-level transformation policies, "
    "preserves referential integrity across linked records, and quantifies residual privacy risk vs. analytical utility."
)

# Sidebar Configuration
st.sidebar.header("⚙️ Policy & Engine Configuration")
secret_key = st.sidebar.text_input("HMAC Tokenization Secret Key", value="hackathon-demo-key-2026", type="password")
score_threshold = st.sidebar.slider("Detection Confidence Threshold", min_value=0.2, max_value=0.9, value=0.5, step=0.05)

default_policy = st.sidebar.selectbox("Default Global Policy", ["tokenize", "mask", "redact"], index=0)
pan_field_policy = st.sidebar.selectbox("Field Policy: 'kyc_pan'", ["mask", "tokenize", "redact"], index=0)
secret_entity_policy = st.sidebar.selectbox("Entity Policy: 'CONFIG_SECRET'", ["redact", "mask", "tokenize"], index=0)

policies = {
    "default_policy": default_policy,
    "entity_policies": {"CONFIG_SECRET": secret_entity_policy, "IN_PAN": "tokenize"},
    "field_policies": {"kyc_pan": pan_field_policy}
}

st.sidebar.markdown("### Active Policy JSON")
st.sidebar.json(policies)

# Initialize Engine & Evaluator
engine = PIIShieldEngine(secret_key=secret_key, score_threshold=score_threshold)
evaluator = PIIShieldEvaluator(engine)
samples, raw_users, raw_orders = evaluator.generate_synthetic_benchmark()

tab1, tab2, tab3, tab4 = st.tabs([
    "🔗 1. Linked Records & Nested Data",
    "🎯 2. Precision, Recall & False Positives",
    "📊 3. Analytical Utility & Risk Scoring",
    "⚠️ 4. Audit Log & Method Limitations"
])

with tab1:
    st.subheader("Nested Record & Free-Form Log Transformation")
    default_nested = {
        "event_id": "EVT-9001",
        "customer_profile": {
            "user_email": "rahul.verma@gmail.com",
            "kyc_pan": "ABCDE1234F",
            "aadhaar_uid": "2345 6789 0123",
            "mobile_phone": "9876543210"
        },
        "order_context": {
            "order_sku": "9876543210",
            "note": "10-digit SKU above matches phone regex but is ignored due to non-phone context!"
        },
        "diagnostic_log": "Auth failed for rahul.verma@gmail.com using token Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    }

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Raw Nested Input (JSON & Unstructured Logs)**")
        raw_json_str = st.text_area("Edit Raw JSON Input:", value=json.dumps(default_nested, indent=2), height=320)
    with col2:
        st.markdown("**Transformed Output (Context-Aware & Tokenized)**")
        try:
            parsed_json = json.loads(raw_json_str)
            transformed_json = engine.transform_record(parsed_json, policies=policies)
            st.code(json.dumps(transformed_json, indent=2), language="json")
        except Exception:
            st.error("Invalid JSON input format.")

    st.divider()
    st.subheader("Referential Integrity Across Linked Tables (Users ↔ Orders)")
    anon_users = next(engine.process_dataframe_incrementally([raw_users], policies=policies))
    anon_orders = next(engine.process_dataframe_incrementally([raw_orders], policies=policies))

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Raw `users` Table**")
        st.dataframe(raw_users, use_container_width=True)
        st.markdown("**Raw `orders` Table (Notice `order_sku` is a 10-digit number)**")
        st.dataframe(raw_orders, use_container_width=True)
    with c2:
        st.markdown("**Transformed `users` Table**")
        st.dataframe(anon_users, use_container_width=True)
        st.markdown("**Transformed `orders` Table (`user_email` token matches `users` table & `order_sku` untouched!)**")
        st.dataframe(anon_orders, use_container_width=True)

with tab2:
    st.subheader("Detection Precision & Recall on Labelled Synthetic Benchmark")
    pr_report = evaluator.evaluate_precision_recall(samples)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Precision", f"{pr_report['precision'] * 100:.1f}%")
    m2.metric("Recall", f"{pr_report['recall'] * 100:.1f}%")
    m3.metric("F1 Score", f"{pr_report['f1_score'] * 100:.1f}%")
    m4.metric("False Positives / Negatives", f"{pr_report['counts']['FP']} FP / {pr_report['counts']['FN']} FN")

    st.markdown("**Detailed Benchmark Verification Table (True Positives vs. False Positive Traps)**")
    st.dataframe(pd.DataFrame(pr_report["sample_results"]), use_container_width=True)

with tab3:
    st.subheader("Downstream Analytical Utility Impact")
    utility = evaluator.measure_downstream_utility(raw_users, raw_orders, anon_users, anon_orders)

    u1, u2, u3 = st.columns(3)
    u1.metric("Overall Utility Preservation", f"{utility['overall_utility_preservation_pct']}%")
    u2.metric(
        "Cross-Table INNER JOIN Rows",
        f"{utility['referential_join_rows_after']} / {utility['referential_join_rows_before']}",
        delta="100% Referential Integrity" if utility["join_integrity_retained_pct"] == 100 else "Broken Links"
    )
    u3.metric(
        "Avg Spend per Unique Customer",
        f"₹{utility['avg_spend_per_customer_after']}",
        delta=f"Raw: ₹{utility['avg_spend_per_customer_before']}"
    )

    chart_df = pd.DataFrame({
        "Before Anonymization (Raw)": utility["city_revenue_before"],
        "After PIIShield Transformation": utility["city_revenue_after"]
    })
    st.markdown("**Sample Analytical Query: Total Order Revenue by City (Before vs. After Transformation)**")
    st.bar_chart(chart_df)

    st.divider()
    st.subheader("Configurable Privacy-Risk Scoring (k-Anonymity & Quasi-Identifiers)")
    selected_qis = st.multiselect(
        "Select Quasi-Identifiers to Evaluate Linkage Risk:",
        options=["city", "age_group"],
        default=["city", "age_group"]
    )
    risk = evaluator.calculate_privacy_risk_score(anon_users, quasi_identifiers=selected_qis)

    r1, r2, r3 = st.columns(3)
    r1.metric("Residual Privacy Risk Score (0-100)", f"{risk['risk_score_0_to_100']}", delta=risk["risk_level"], delta_color="inverse")
    r2.metric("Min Equivalence Group Size (k)", f"k = {risk.get('k_anonymity_min_group_size', 0)}")
    r3.metric("Unique Re-identifiable Rows (k=1)", f"{risk.get('unique_reidentifiable_rows', 0)} of {risk.get('total_rows', 0)}")

    st.info("**Documented Risk Scoring Assumptions:**\n- " + "\n- ".join(risk.get("documented_assumptions", [])))

with tab4:
    st.subheader("Transformation Audit Report & Zero-Leakage Guarantee")
    st.json(engine.audit_log)

    st.subheader("Communicated System Limitations (Acceptance Criteria)")
    st.warning(
        """
        **1. Context-Window & Unseen Formats:** Context-aware detection relies on field names and local lexical tokens. Highly obfuscated PII (e.g., base64-encoded Aadhaar numbers or numbers spelled out in regional transliterated text like 'nine eight seven...') may cause False Negatives.
        
        **2. Deterministic Tokenization vs. Frequency Analysis:** Stable HMAC-SHA256 tokenization preserves 100% join utility, but if an adversary knows that 'Rahul' has the highest transaction count in the raw database, they can map the most frequent token `<EMAIL_ADDRESS_...>` back to Rahul via frequency analysis.
        
        **3. Quasi-Identifier Linkage (k-Anonymity):** Masking direct identifiers does not prevent re-identification if rare combinations of quasi-identifiers (e.g., `city = Delhi` + `age_group = 40-45` where `k = 1`) remain ungeneralized.
        """
    )