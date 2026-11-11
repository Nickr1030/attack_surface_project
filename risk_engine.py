def calculate_risk(cvss: float, ransomware: bool, criticality: str) -> float:
    score = cvss
    if ransomware:
        score += 5
    if criticality == "Critical":
        score += 5
    return score


def classify_risk(score: float) -> str:
    if score >= 18:
        return "CRITICAL"
    if score >= 13:
        return "HIGH"
    if score >= 8:
        return "MEDIUM"
    return "LOW"