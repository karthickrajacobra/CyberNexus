from datetime import datetime, timezone
import os

from forensics.hashing import sha256_file, sha256_text
from forensics.evidence_ledger import (
    add_evidence,
    get_evidence,
    verify_ledger
)


class ForensicAgent:
    """
    CyberNexus Ω - Forensic Agent

    Responsibilities:
    - Generate SHA-256 hashes
    - Preserve forensic evidence
    - Create evidence-ledger records
    - Verify evidence-ledger integrity
    - Provide forensic investigation results
    """

    AGENT_NAME = "CyberNexus Forensic Agent"
    AGENT_VERSION = "1.0"

    def __init__(self):
        self.status = "READY"

    def _timestamp(self):
        return datetime.now(timezone.utc).isoformat()

    # ---------------------------------------------------------
    # TEXT HASHING
    # ---------------------------------------------------------

    def hash_text(self, text):
        """
        Generate SHA-256 hash for text evidence.
        """

        if not isinstance(text, str):
            return {
                "success": False,
                "agent": self.AGENT_NAME,
                "type": "TEXT",
                "status": "ERROR",
                "message": "Text input is required.",
                "timestamp": self._timestamp()
            }

        try:
            text_hash = sha256_text(text)

            return {
                "success": True,
                "agent": self.AGENT_NAME,
                "version": self.AGENT_VERSION,
                "type": "TEXT",
                "status": "HASHED",
                "sha256": text_hash,
                "size_bytes": len(text.encode("utf-8")),
                "timestamp": self._timestamp()
            }

        except Exception as error:
            return {
                "success": False,
                "agent": self.AGENT_NAME,
                "type": "TEXT",
                "status": "ERROR",
                "message": str(error),
                "timestamp": self._timestamp()
            }

    # ---------------------------------------------------------
    # FILE HASHING
    # ---------------------------------------------------------

    def hash_file(self, file_path):
        """
        Generate SHA-256 hash for a forensic file.
        """

        if not file_path or not isinstance(file_path, str):
            return {
                "success": False,
                "agent": self.AGENT_NAME,
                "type": "FILE",
                "status": "ERROR",
                "message": "A valid file path is required.",
                "timestamp": self._timestamp()
            }

        if not os.path.isfile(file_path):
            return {
                "success": False,
                "agent": self.AGENT_NAME,
                "type": "FILE",
                "status": "ERROR",
                "message": "File not found.",
                "timestamp": self._timestamp()
            }

        try:
            file_hash = sha256_file(file_path)
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)

            return {
                "success": True,
                "agent": self.AGENT_NAME,
                "version": self.AGENT_VERSION,
                "type": "FILE",
                "status": "HASHED",
                "file_name": file_name,
                "file_path": file_path,
                "size_bytes": file_size,
                "sha256": file_hash,
                "timestamp": self._timestamp()
            }

        except Exception as error:
            return {
                "success": False,
                "agent": self.AGENT_NAME,
                "type": "FILE",
                "status": "ERROR",
                "message": str(error),
                "timestamp": self._timestamp()
            }

    # ---------------------------------------------------------
    # ADD EVIDENCE
    # ---------------------------------------------------------

    def preserve_evidence(
        self,
        evidence_type,
        source,
        evidence,
        risk_score=0,
        risk_level="LOW"
    ):
        """
        Add forensic evidence to the tamper-evident ledger.
        """

        try:
            record = add_evidence(
                evidence_type=evidence_type,
                source=source,
                evidence=evidence,
                risk_score=risk_score,
                risk_level=risk_level
            )

            return {
                "success": True,
                "agent": self.AGENT_NAME,
                "version": self.AGENT_VERSION,
                "type": "EVIDENCE",
                "status": "PRESERVED",
                "record": record,
                "timestamp": self._timestamp()
            }

        except Exception as error:
            return {
                "success": False,
                "agent": self.AGENT_NAME,
                "type": "EVIDENCE",
                "status": "ERROR",
                "message": str(error),
                "timestamp": self._timestamp()
            }

    # ---------------------------------------------------------
    # VERIFY LEDGER
    # ---------------------------------------------------------

    def verify_evidence(self):
        """
        Verify the integrity of the complete evidence ledger.
        """

        try:
            verification = verify_ledger()

            return {
                "success": True,
                "agent": self.AGENT_NAME,
                "version": self.AGENT_VERSION,
                "type": "LEDGER",
                "status": (
                    "VERIFIED"
                    if verification.get("valid")
                    else "COMPROMISED"
                ),
                "verification": verification,
                "timestamp": self._timestamp()
            }

        except Exception as error:
            return {
                "success": False,
                "agent": self.AGENT_NAME,
                "type": "LEDGER",
                "status": "ERROR",
                "message": str(error),
                "timestamp": self._timestamp()
            }

    # ---------------------------------------------------------
    # GET EVIDENCE
    # ---------------------------------------------------------

    def get_all_evidence(self):
        """
        Retrieve all forensic evidence records.
        """

        try:
            records = get_evidence()

            return {
                "success": True,
                "agent": self.AGENT_NAME,
                "version": self.AGENT_VERSION,
                "type": "EVIDENCE",
                "status": "RETRIEVED",
                "record_count": len(records),
                "records": records,
                "timestamp": self._timestamp()
            }

        except Exception as error:
            return {
                "success": False,
                "agent": self.AGENT_NAME,
                "type": "EVIDENCE",
                "status": "ERROR",
                "message": str(error),
                "timestamp": self._timestamp()
            }

    # ---------------------------------------------------------
    # COMPLETE FILE FORENSICS
    # ---------------------------------------------------------

    def investigate_file(
        self,
        file_path,
        source="Forensic Investigation",
        risk_score=0,
        risk_level="LOW"
    ):
        """
        Complete forensic workflow for a file.

        Flow:

        File
          ↓
        SHA-256
          ↓
        Evidence Record
          ↓
        Ledger Verification
        """

        hash_result = self.hash_file(file_path)

        if not hash_result.get("success"):
            return hash_result

        evidence = {
            "file_name": hash_result["file_name"],
            "file_path": hash_result["file_path"],
            "size_bytes": hash_result["size_bytes"],
            "sha256": hash_result["sha256"]
        }

        preservation = self.preserve_evidence(
            evidence_type="FILE",
            source=source,
            evidence=evidence,
            risk_score=risk_score,
            risk_level=risk_level
        )

        verification = self.verify_evidence()

        return {
            "success": True,
            "agent": self.AGENT_NAME,
            "version": self.AGENT_VERSION,
            "type": "FILE_FORENSICS",
            "status": "COMPLETED",
            "hash": hash_result,
            "preservation": preservation,
            "verification": verification,
            "timestamp": self._timestamp()
        }


def run_forensic_agent(
    action,
    value=None,
    evidence_type=None,
    source="Forensic Agent",
    risk_score=0,
    risk_level="LOW"
):
    """
    Convenience function for other CyberNexus modules.
    """

    agent = ForensicAgent()

    action = str(action).upper().strip()

    if action == "HASH_TEXT":
        return agent.hash_text(value)

    if action == "HASH_FILE":
        return agent.hash_file(value)

    if action == "PRESERVE":
        return agent.preserve_evidence(
            evidence_type=evidence_type or "UNKNOWN",
            source=source,
            evidence=value,
            risk_score=risk_score,
            risk_level=risk_level
        )

    if action == "VERIFY":
        return agent.verify_evidence()

    if action == "GET_EVIDENCE":
        return agent.get_all_evidence()

    if action == "INVESTIGATE_FILE":
        return agent.investigate_file(
            file_path=value,
            source=source,
            risk_score=risk_score,
            risk_level=risk_level
        )

    return {
        "success": False,
        "agent": agent.AGENT_NAME,
        "status": "ERROR",
        "message": (
            "Unsupported action. "
            "Supported actions: "
            "HASH_TEXT, HASH_FILE, PRESERVE, "
            "VERIFY, GET_EVIDENCE, INVESTIGATE_FILE."
        ),
        "timestamp": agent._timestamp()
    }


# =============================================================
# DIRECT TEST
# =============================================================

if __name__ == "__main__":

    print("\n" + "=" * 70)
    print("CYBERNEXUS Ω - FORENSIC AGENT TEST")
    print("=" * 70)

    agent = ForensicAgent()

    # ---------------------------------------------------------
    # TEXT HASH TEST
    # ---------------------------------------------------------

    print("\n[1] TEXT HASH TEST")
    print("-" * 70)

    text_result = agent.hash_text(
        "CyberNexus Omega forensic evidence test"
    )

    print("Agent        :", text_result.get("agent"))
    print("Status       :", text_result.get("status"))

    if text_result.get("success"):
        print("SHA-256      :", text_result.get("sha256"))
        print("Size         :", text_result.get("size_bytes"), "bytes")
    else:
        print("Error        :", text_result.get("message"))

    # ---------------------------------------------------------
    # FILE HASH TEST
    # ---------------------------------------------------------

    print("\n[2] FILE HASH TEST")
    print("-" * 70)

    test_file = "test.txt"

    if os.path.isfile(test_file):

        file_result = agent.hash_file(test_file)

        print("Agent        :", file_result.get("agent"))
        print("Status       :", file_result.get("status"))

        if file_result.get("success"):
            print("File         :", file_result.get("file_name"))
            print("Size         :", file_result.get("size_bytes"), "bytes")
            print("SHA-256      :", file_result.get("sha256"))
        else:
            print("Error        :", file_result.get("message"))

    else:

        print("test.txt not found.")
        print("File hash test skipped.")

    # ---------------------------------------------------------
    # EVIDENCE PRESERVATION TEST
    # ---------------------------------------------------------

    print("\n[3] EVIDENCE PRESERVATION TEST")
    print("-" * 70)

    evidence_result = agent.preserve_evidence(
        evidence_type="TEST",
        source="Forensic Agent Test",
        evidence={
            "description": "CyberNexus forensic test evidence",
            "category": "TEST"
        },
        risk_score=25,
        risk_level="MEDIUM"
    )

    print("Agent        :", evidence_result.get("agent"))
    print("Status       :", evidence_result.get("status"))

    if evidence_result.get("success"):
        record = evidence_result.get("record", {})

        print("Event ID     :", record.get("event_id"))
        print("Evidence Hash:", record.get("evidence_hash"))
        print("Ledger Hash  :", record.get("ledger_hash"))
    else:
        print("Error        :", evidence_result.get("message"))

    # ---------------------------------------------------------
    # LEDGER VERIFICATION TEST
    # ---------------------------------------------------------

    print("\n[4] LEDGER VERIFICATION TEST")
    print("-" * 70)

    verification_result = agent.verify_evidence()

    print("Agent        :", verification_result.get("agent"))
    print("Status       :", verification_result.get("status"))

    verification = verification_result.get(
        "verification",
        {}
    )

    print(
        "Valid        :",
        verification.get("valid")
    )

    print(
        "Records      :",
        verification.get("records")
    )

    print(
        "Message      :",
        verification.get("message")
    )

    # ---------------------------------------------------------
    # FINAL STATUS
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("FORENSIC AGENT TEST COMPLETED")
    print("=" * 70)