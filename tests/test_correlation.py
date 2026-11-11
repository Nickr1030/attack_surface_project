from types import SimpleNamespace

import correlator
from correlator import correlate_asset, load_inventory


def test_load_inventory_reads_csv_at_configured_path(tmp_path, monkeypatch):
    inventory_path = tmp_path / "inventory.csv"
    inventory_path.write_text(
        "vendor,product\nCisco,IOS XE\nApache,Tomcat\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(correlator, "INVENTORY_PATH", inventory_path)

    assert load_inventory() == [
        {"vendor": "Cisco", "product": "IOS XE"},
        {"vendor": "Apache", "product": "Tomcat"},
    ]


def test_correlate_asset_matches_vendor_case_insensitively():
    vulnerabilities = [
        SimpleNamespace(vendor="cIsCo", cve_id="CVE-2025-0001"),
        SimpleNamespace(vendor="Apache", cve_id="CVE-2025-0002"),
    ]

    matches = correlate_asset({"vendor": "CISCO", "product": "IOS XE"}, vulnerabilities)

    assert [vulnerability.cve_id for vulnerability in matches] == ["CVE-2025-0001"]


def test_correlate_asset_matches_cisco_not_microsoft():
    vulnerabilities = [
        SimpleNamespace(vendor="Cisco"),
        SimpleNamespace(vendor="Microsoft"),
    ]

    matches = correlate_asset({"vendor": "Cisco"}, vulnerabilities)

    assert len(matches) == 1
    assert matches[0].vendor == "Cisco"


def test_correlate_asset_with_no_vulnerabilities():
    assert correlate_asset({"vendor": "Cisco"}, []) == []
