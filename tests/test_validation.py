import pytest

from schemas import KEVRecord
from validate import validate_records


def test_valid_record():
    record = KEVRecord(
        cveID="CVE-2025-1000",
        vendorProject="Cisco",
        product="IOS XE",
        vulnerabilityName="Test Vulnerability",
        dateAdded="2025-01-01",
        knownRansomwareCampaignUse="Unknown",
    )

    assert record.cveID == "CVE-2025-1000"


def test_validate_records_keeps_valid_rows_and_skips_invalid_rows():
    valid_record = {
        "cveID": "CVE-2025-0001",
        "vendorProject": "Example Vendor",
        "product": "Example Product",
        "vulnerabilityName": "Example vulnerability",
        "dateAdded": "2025-01-01",
        "knownRansomwareCampaignUse": "Unknown",
    }

    records = validate_records(
        {"vulnerabilities": [valid_record, {"cveID": "CVE-2025-0002"}]}
    )

    assert [record.model_dump() for record in records] == [valid_record]


def test_validate_records_propagates_unexpected_item_errors():
    with pytest.raises(TypeError):
        validate_records({"vulnerabilities": [None]})
