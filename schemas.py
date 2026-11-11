from pydantic import BaseModel


class KEVRecord(BaseModel):
    cveID: str
    vendorProject: str
    product: str
    vulnerabilityName: str
    dateAdded: str
    knownRansomwareCampaignUse: str