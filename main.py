from typing import Iterable

from sqlmodel import Session, select

from correlator import correlate_asset
from database import engine
from models import Asset, Vulnerability
from risk_engine import calculate_risk, classify_risk


def save_vulnerability(vulnerability: Vulnerability) -> bool:
    return save_vulnerabilities([vulnerability]) == 1


def save_vulnerabilities(vulnerabilities: Iterable[Vulnerability]) -> int:
    saved_count = 0
    seen_cves = set()
    with Session(engine) as session:
        for vulnerability in vulnerabilities:
            if vulnerability.cve_id in seen_cves:
                continue
            seen_cves.add(vulnerability.cve_id)

            existing = session.exec(
                select(Vulnerability).where(
                    Vulnerability.cve_id == vulnerability.cve_id
                )
            ).first()
            if existing is not None:
                continue

            session.add(vulnerability)
            saved_count += 1

        session.commit()
    return saved_count


def generate_asset_reports(
    assets: Iterable[Asset],
    vulnerabilities: Iterable[Vulnerability],
) -> list[str]:
    vulnerability_list = list(vulnerabilities)
    reports = []

    for asset in assets:
        matches = correlate_asset(
            {"vendor": asset.vendor},
            vulnerability_list,
        )
        if not matches:
            reports.append(
                f"Asset: {asset.asset_name}\n"
                "No matching known exploited vulnerability was found."
            )
            continue

        vulnerability = max(matches, key=lambda item: item.cvss_score)
        risk_score = calculate_risk(
            vulnerability.cvss_score,
            vulnerability.ransomware_flag,
            asset.criticality,
        )
        ransomware = "Yes" if vulnerability.ransomware_flag else "No"
        critical_asset = "Yes" if asset.criticality == "Critical" else "No"
        reports.append(
            f"Asset: {asset.asset_name}\n"
            f"CVSS: {vulnerability.cvss_score:g}\n"
            f"Ransomware: {ransomware}\n"
            f"Critical Asset: {critical_asset}\n"
            f"Risk Score: {risk_score:g}\n"
            f"SEVERITY: {classify_risk(risk_score)}"
        )

    return reports


def main() -> None:
    with Session(engine) as session:
        assets = session.exec(select(Asset)).all()
        vulnerabilities = session.exec(select(Vulnerability)).all()

    reports = generate_asset_reports(assets, vulnerabilities)
    if reports:
        print("\n\n".join(reports))


if __name__ == "__main__":
    main()