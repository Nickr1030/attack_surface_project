import streamlit as st
from sqlmodel import Session, select

from correlator import correlate_asset
from database import engine
from models import Asset, Vulnerability
from risk_engine import calculate_risk, classify_risk

st.set_page_config(
    page_title="Attack Surface Correlator",
    layout="wide",
)

st.title("Attack Surface Correlator")

st.success("Dashboard Loaded Successfully")

with Session(engine) as session:
    assets = session.exec(select(Asset)).all()
    vulnerabilities = session.exec(select(Vulnerability)).all()

search = st.text_input("Search Assets")
filtered_assets = [
    asset
    for asset in assets
    if search.lower() in asset.asset_name.lower()
]

col1, col2 = st.columns(2)

with col1:
    st.metric("Total Assets", len(assets))

with col2:
    st.metric("Total Vulnerabilities", len(vulnerabilities))

st.header("Assets")

for asset in filtered_assets:
    st.subheader(asset.asset_name)
    st.write(f"IP Address: {asset.ip_address}")
    st.write(f"Criticality: {asset.criticality}")

    matches = correlate_asset({"vendor": asset.vendor}, vulnerabilities)
    if matches:
        for vulnerability in matches:
            st.write(
                f"{vulnerability.cve_id} (CVSS {vulnerability.cvss_score})"
            )

        highest_cvss = max(matches, key=lambda vulnerability: vulnerability.cvss_score)
        ransomware = any(vulnerability.ransomware_flag for vulnerability in matches)
        score = calculate_risk(
            highest_cvss.cvss_score,
            ransomware,
            asset.criticality,
        )
        severity = classify_risk(score)
    else:
        st.write("No matching known exploited vulnerabilities found.")
        score = 0
        severity = "LOW"

    st.write(f"Risk Score: {score}")
    if severity == "CRITICAL":
        st.error(f"Severity: {severity}")
    elif severity == "HIGH":
        st.warning(f"Severity: {severity}")
    else:
        st.info(f"Severity: {severity}")
