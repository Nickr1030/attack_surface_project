import pytest

from risk_engine import calculate_risk
from risk_engine import classify_risk


def test_calculate_risk_applies_ransomware_and_criticality_bonuses():
    assert calculate_risk(9.8, True, "Critical") == 19.8


def test_calculate_risk_without_bonuses():
    assert calculate_risk(4.0, False, "Low") == 4.0


def test_calculate_risk_adds_critical_asset_bonus():
    assert calculate_risk(7.0, False, "Critical") == 12.0


def test_calculate_risk_requires_exact_criticality_and_does_not_round():
    assert calculate_risk(6.234, False, "critical") == 6.234
    assert calculate_risk(6.234, True, "High") == 11.234


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (19.8, "CRITICAL"),
        (14.0, "HIGH"),
        (10.0, "MEDIUM"),
        (3.0, "LOW"),
    ],
)
def test_classify_risk_examples(score, expected):
    assert classify_risk(score) == expected


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (18, "CRITICAL"),
        (17.99, "HIGH"),
        (13, "HIGH"),
        (12.99, "MEDIUM"),
        (8, "MEDIUM"),
        (7.99, "LOW"),
    ],
)
def test_classify_risk_boundaries(score, expected):
    assert classify_risk(score) == expected
