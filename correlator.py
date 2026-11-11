import csv
from pathlib import Path
from typing import Any


INVENTORY_PATH = Path(__file__).with_name("inventory.csv")


def load_inventory() -> list[dict[str, str]]:
    inventory = []
    with INVENTORY_PATH.open(newline="") as file:
        reader = csv.DictReader(file)
        inventory.extend(reader)
    return inventory


def correlate_asset(
    asset: dict[str, str],
    vulnerabilities: list[Any],
) -> list[Any]:
    results = []
    for vulnerability in vulnerabilities:
        if asset["vendor"].lower() == vulnerability.vendor.lower():
            results.append(vulnerability)
    return results