from typing import Optional

from sqlmodel import Field, SQLModel


class Asset(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    asset_name: str
    vendor: str
    product: str
    ip_address: str
    criticality: str


class Vulnerability(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    cve_id: str = Field(index=True)
    vendor: str = Field(index=True)
    product: str = Field(index=True)
    description: str
    ransomware_flag: bool = False
    date_added: str
    cvss_score: float