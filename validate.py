from pydantic import ValidationError

from logger import logger
from schemas import KEVRecord


def validate_records(json_data):
    records = []
    for item in json_data["vulnerabilities"]:
        try:
            records.append(KEVRecord(**item))
        except ValidationError:
            continue
    logger.info(f"Validated {len(records)} records")
    return records