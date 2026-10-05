import json
import os
import uuid
from datetime import datetime, timezone

from forensics.hashing import sha256_text


LEDGER_FILE = os.path.join(
    os.path.dirname(__file__),
    "evidence_ledger.json"
)


def _load_ledger():
    if not os.path.exists(LEDGER_FILE):
        return []

    try:
        with open(LEDGER_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return []


def _save_ledger(records):
    with open(LEDGER_FILE, "w", encoding="utf-8") as file:
        json.dump(records, file, indent=2)


def add_evidence(
    evidence_type,
    source,
    evidence,
    risk_score=0,
    risk_level="LOW"
):
    """
    Add an evidence record to the CyberNexus evidence chain.
    """

    records = _load_ledger()

    previous_hash = (
        records[-1]["ledger_hash"]
        if records
        else "GENESIS"
    )

    event_id = str(uuid.uuid4())

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    evidence_text = json.dumps(
        evidence,
        sort_keys=True,
        default=str
    )

    evidence_hash = sha256_text(evidence_text)

    record_data = {
        "event_id": event_id,
        "timestamp": timestamp,
        "evidence_type": evidence_type,
        "source": source,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "evidence_hash": evidence_hash,
        "previous_hash": previous_hash
    }

    record_text = json.dumps(
        record_data,
        sort_keys=True
    )

    ledger_hash = sha256_text(record_text)

    record_data["ledger_hash"] = ledger_hash

    records.append(record_data)

    _save_ledger(records)

    return record_data


def get_evidence():
    """
    Return all evidence records.
    """
    return _load_ledger()


def verify_ledger():
    """
    Verify the integrity of the evidence chain.
    """

    records = _load_ledger()

    if not records:
        return {
            "valid": True,
            "records": 0,
            "message": "Evidence ledger is empty."
        }

    previous_hash = "GENESIS"

    for record in records:

        if record["previous_hash"] != previous_hash:
            return {
                "valid": False,
                "records": len(records),
                "message": "Chain linkage failure.",
                "event_id": record["event_id"]
            }

        record_copy = dict(record)

        stored_ledger_hash = record_copy.pop(
            "ledger_hash"
        )

        expected_hash = sha256_text(
            json.dumps(
                record_copy,
                sort_keys=True
            )
        )

        if expected_hash != stored_ledger_hash:
            return {
                "valid": False,
                "records": len(records),
                "message": "Evidence record was modified.",
                "event_id": record["event_id"]
            }

        previous_hash = stored_ledger_hash

    return {
        "valid": True,
        "records": len(records),
        "message": "Evidence ledger integrity verified."
    }