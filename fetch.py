import requests

from logger import logger


KEV_URL = (
    "https://www.cisa.gov/sites/default/files/"
    "feeds/known_exploited_vulnerabilities.json"
)


def fetch_kev():
    logger.info("Starting KEV download")
    response = requests.get(
        KEV_URL,
        timeout=30,
    )
    response.raise_for_status()
    return response.json()