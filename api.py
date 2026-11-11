from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, func, select

from correlator import correlate_asset
from database import engine
from models import Asset, Vulnerability
from risk_engine import calculate_risk, classify_risk


app = FastAPI()


class AssetRiskAssessment(BaseModel):
    asset_id: int
    asset_name: str
    ip_address: str
    criticality: str
    vulnerability_count: int
    highest_cvss: float
    ransomware_exposure: bool
    risk_score: float
    severity: str


class AssetWithoutRiskAssessment(BaseModel):
    asset_id: int
    asset_name: str
    risk_score: int
    severity: str


@app.get("/")
def home():
    return {
        "application": "Attack Surface Correlator",
        "status": "running",
    }


@app.get("/assets")
def assets() -> list[Asset]:
    with Session(engine) as session:
        return session.exec(select(Asset)).all()


@app.get("/assets/{id}")
def asset_by_id(id: int) -> Asset:
    with Session(engine) as session:
        asset = session.get(Asset, id)
        if asset is None:
            raise HTTPException(status_code=404, detail="Asset not found")
        return asset


@app.get(
    "/assets/{asset_id}/risk",
    response_model=AssetRiskAssessment | AssetWithoutRiskAssessment,
)
def asset_risk(
    asset_id: int,
) -> AssetRiskAssessment | AssetWithoutRiskAssessment:
    with Session(engine) as session:
        asset = session.get(Asset, asset_id)
        if asset is None:
            raise HTTPException(status_code=404, detail="Asset not found")
        known_vulnerabilities = session.exec(select(Vulnerability)).all()

    matches = correlate_asset({"vendor": asset.vendor}, known_vulnerabilities)
    if not matches:
        return AssetWithoutRiskAssessment(
            asset_id=asset_id,
            asset_name=asset.asset_name,
            risk_score=0,
            severity="LOW",
        )

    highest_cvss_vulnerability = max(matches, key=lambda item: item.cvss_score)
    ransomware_exposure = any(item.ransomware_flag for item in matches)
    risk_score = calculate_risk(
        highest_cvss_vulnerability.cvss_score,
        ransomware_exposure,
        asset.criticality,
    )
    return AssetRiskAssessment(
        asset_id=asset_id,
        asset_name=asset.asset_name,
        ip_address=asset.ip_address,
        criticality=asset.criticality,
        vulnerability_count=len(matches),
        highest_cvss=highest_cvss_vulnerability.cvss_score,
        ransomware_exposure=ransomware_exposure,
        risk_score=risk_score,
        severity=classify_risk(risk_score),
    )


@app.get("/vulnerabilities")
def vulnerabilities() -> list[Vulnerability]:
    with Session(engine) as session:
        return session.exec(select(Vulnerability)).all()


@app.get("/stats")
def stats() -> dict[str, int]:
    with Session(engine) as session:
        asset_count = session.exec(select(func.count()).select_from(Asset)).one()
        vulnerability_count = session.exec(
            select(func.count()).select_from(Vulnerability)
        ).one()
        critical_asset_count = session.exec(
            select(func.count())
            .select_from(Asset)
            .where(Asset.criticality == "Critical")
        ).one()

    return {
        "assets": asset_count,
        "vulnerabilities": vulnerability_count,
        "critical_assets": critical_asset_count,
    }