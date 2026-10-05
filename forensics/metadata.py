import hashlib
import math
import mimetypes
import os
import stat
from datetime import datetime, timezone


class ForensicMetadata:
    """
    CyberNexus Ω - Forensic Metadata Engine

    Collects and analyzes file metadata for defensive
    forensic investigation.

    This module does not modify the analyzed file.
    """

    ENGINE_NAME = "CyberNexus Forensic Metadata Engine"
    ENGINE_VERSION = "1.0"

    SUSPICIOUS_EXTENSIONS = {
        ".exe",
        ".dll",
        ".scr",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".jar",
        ".msi",
        ".hta"
    }

    def __init__(self):
        self.status = "READY"

    # =========================================================
    # UTILITY
    # =========================================================

    def _timestamp(self):
        return datetime.now(
            timezone.utc
        ).isoformat()

    def _utc_from_timestamp(self, timestamp):
        return datetime.fromtimestamp(
            timestamp,
            tz=timezone.utc
        ).isoformat()

    # =========================================================
    # HASHING
    # =========================================================

    def _calculate_sha256(self, file_path):

        sha256 = hashlib.sha256()

        with open(
            file_path,
            "rb"
        ) as file:

            for chunk in iter(
                lambda: file.read(
                    1024 * 1024
                ),
                b""
            ):

                sha256.update(chunk)

        return sha256.hexdigest()

    # =========================================================
    # ENTROPY
    # =========================================================

    def _calculate_entropy(
        self,
        file_path,
        max_bytes=5 * 1024 * 1024
    ):

        frequency = [
            0
        ] * 256

        total = 0

        with open(
            file_path,
            "rb"
        ) as file:

            remaining = max_bytes

            while remaining > 0:

                chunk = file.read(
                    min(
                        1024 * 1024,
                        remaining
                    )
                )

                if not chunk:
                    break

                for byte in chunk:

                    frequency[byte] += 1

                total += len(chunk)

                remaining -= len(chunk)

        if total == 0:
            return 0.0

        entropy = 0.0

        for count in frequency:

            if count == 0:
                continue

            probability = (
                count / total
            )

            entropy -= (
                probability
                * math.log2(probability)
            )

        return round(
            entropy,
            4
        )

    # =========================================================
    # FILE TYPE
    # =========================================================

    def _detect_mime_type(
        self,
        file_path
    ):

        mime_type, encoding = (
            mimetypes.guess_type(
                file_path
            )
        )

        if mime_type is None:

            mime_type = (
                "application/octet-stream"
            )

        return {
            "mime_type": mime_type,
            "encoding": encoding
        }

    # =========================================================
    # FILE ATTRIBUTES
    # =========================================================

    def _get_attributes(
        self,
        file_path
    ):

        attributes = []

        filename = os.path.basename(
            file_path
        )

        if filename.startswith("."):

            attributes.append(
                "Hidden or dot-prefixed filename"
            )

        try:

            file_mode = os.stat(
                file_path
            ).st_mode

            if not (
                file_mode
                & stat.S_IWRITE
            ):

                attributes.append(
                    "File is not writable by current process"
                )

        except OSError:
            pass

        return attributes

    # =========================================================
    # SUSPICIOUS METADATA
    # =========================================================

    def _analyze_metadata(
        self,
        filename,
        extension,
        size_bytes,
        entropy,
        mime_type
    ):

        findings = []
        score = 0

        extension = extension.lower()

        # -----------------------------------------------------
        # SUSPICIOUS EXTENSION
        # -----------------------------------------------------

        if extension in self.SUSPICIOUS_EXTENSIONS:

            score += 25

            findings.append(
                "Suspicious executable or script extension."
            )

        # -----------------------------------------------------
        # DOUBLE EXTENSION
        # -----------------------------------------------------

        parts = filename.lower().split(".")

        if len(parts) >= 3:

            last_part = "." + parts[-1]
            previous_part = "." + parts[-2]

            if (
                last_part in self.SUSPICIOUS_EXTENSIONS
                and previous_part
                in {
                    ".txt",
                    ".pdf",
                    ".doc",
                    ".docx",
                    ".jpg",
                    ".png",
                    ".xlsx"
                }
            ):

                score += 30

                findings.append(
                    "Possible double-extension deception."
                )

        # -----------------------------------------------------
        # HIGH ENTROPY
        # -----------------------------------------------------

        if entropy >= 7.2:

            score += 25

            findings.append(
                "Very high file entropy detected."
            )

        elif entropy >= 6.5:

            score += 10

            findings.append(
                "High file entropy detected."
            )

        # -----------------------------------------------------
        # LARGE FILE
        # -----------------------------------------------------

        if size_bytes >= 500 * 1024 * 1024:

            score += 10

            findings.append(
                "Very large file size detected."
            )

        # -----------------------------------------------------
        # MIME MISMATCH INDICATOR
        # -----------------------------------------------------

        if (
            extension in self.SUSPICIOUS_EXTENSIONS
            and mime_type.startswith("text/")
        ):

            score += 15

            findings.append(
                "File extension and detected MIME type "
                "may not match."
            )

        score = min(
            score,
            100
        )

        if score >= 70:

            risk_level = "CRITICAL"

        elif score >= 45:

            risk_level = "HIGH"

        elif score >= 20:

            risk_level = "MEDIUM"

        else:

            risk_level = "LOW"

        return {
            "score": score,
            "risk_level": risk_level,
            "findings": findings
        }

    # =========================================================
    # MAIN ANALYSIS
    # =========================================================

    def analyze_file(
        self,
        file_path
    ):

        if not file_path:

            return {
                "success": False,
                "engine": self.ENGINE_NAME,
                "status": "NO_FILE",
                "message": "File path is required.",
                "timestamp": self._timestamp()
            }

        if not os.path.exists(
            file_path
        ):

            return {
                "success": False,
                "engine": self.ENGINE_NAME,
                "status": "NOT_FOUND",
                "message": "File does not exist.",
                "file_path": file_path,
                "timestamp": self._timestamp()
            }

        if not os.path.isfile(
            file_path
        ):

            return {
                "success": False,
                "engine": self.ENGINE_NAME,
                "status": "INVALID_FILE",
                "message": "Provided path is not a regular file.",
                "file_path": file_path,
                "timestamp": self._timestamp()
            }

        try:

            file_stats = os.stat(
                file_path
            )

            filename = os.path.basename(
                file_path
            )

            extension = os.path.splitext(
                filename
            )[1].lower()

            size_bytes = file_stats.st_size

            created_time = (
                self._utc_from_timestamp(
                    file_stats.st_ctime
                )
            )

            modified_time = (
                self._utc_from_timestamp(
                    file_stats.st_mtime
                )
            )

            accessed_time = (
                self._utc_from_timestamp(
                    file_stats.st_atime
                )
            )

            mime_info = (
                self._detect_mime_type(
                    file_path
                )
            )

            sha256 = (
                self._calculate_sha256(
                    file_path
                )
            )

            entropy = (
                self._calculate_entropy(
                    file_path
                )
            )

            attributes = (
                self._get_attributes(
                    file_path
                )
            )

            metadata_analysis = (
                self._analyze_metadata(
                    filename=filename,
                    extension=extension,
                    size_bytes=size_bytes,
                    entropy=entropy,
                    mime_type=mime_info[
                        "mime_type"
                    ]
                )
            )

            return {
                "success": True,
                "engine": self.ENGINE_NAME,
                "version": self.ENGINE_VERSION,
                "status": "ANALYZED",
                "timestamp": self._timestamp(),

                "file": {
                    "file_name": filename,
                    "file_path": os.path.abspath(
                        file_path
                    ),
                    "extension": extension,
                    "size_bytes": size_bytes,
                    "size_kb": round(
                        size_bytes / 1024,
                        2
                    ),
                    "size_mb": round(
                        size_bytes / (
                            1024 * 1024
                        ),
                        4
                    )
                },

                "timestamps": {
                    "created_utc": created_time,
                    "modified_utc": modified_time,
                    "accessed_utc": accessed_time
                },

                "identity": {
                    "sha256": sha256,
                    "mime_type": mime_info[
                        "mime_type"
                    ],
                    "encoding": mime_info[
                        "encoding"
                    ]
                },

                "forensic": {
                    "entropy": entropy,
                    "attributes": attributes
                },

                "assessment": {
                    "risk_score": metadata_analysis[
                        "score"
                    ],
                    "risk_level": metadata_analysis[
                        "risk_level"
                    ],
                    "findings": metadata_analysis[
                        "findings"
                    ]
                }
            }

        except PermissionError:

            return {
                "success": False,
                "engine": self.ENGINE_NAME,
                "status": "PERMISSION_DENIED",
                "message": (
                    "Permission denied while reading the file."
                ),
                "file_path": file_path,
                "timestamp": self._timestamp()
            }

        except OSError as error:

            return {
                "success": False,
                "engine": self.ENGINE_NAME,
                "status": "READ_ERROR",
                "message": str(error),
                "file_path": file_path,
                "timestamp": self._timestamp()
            }


def analyze_file_metadata(
    file_path
):
    """
    Convenience function for other CyberNexus modules.
    """

    engine = ForensicMetadata()

    return engine.analyze_file(
        file_path
    )


# =============================================================
# DIRECT TEST
# =============================================================

if __name__ == "__main__":

    print("\n" + "=" * 70)
    print("CYBERNEXUS Ω - FORENSIC METADATA TEST")
    print("=" * 70)

    engine = ForensicMetadata()

    # ---------------------------------------------------------
    # TEST FILE
    # ---------------------------------------------------------

    test_file = os.path.join(
        os.path.dirname(
            os.path.dirname(
                os.path.abspath(
                    __file__
                )
            )
        ),
        "test_data",
        "metadata_test.txt"
    )

    test_directory = os.path.dirname(
        test_file
    )

    os.makedirs(
        test_directory,
        exist_ok=True
    )

    # ---------------------------------------------------------
    # CREATE TEST FILE
    # ---------------------------------------------------------

    if not os.path.exists(
        test_file
    ):

        with open(
            test_file,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(
                "CyberNexus forensic metadata test file.\n"
                "This file is used only for defensive testing.\n"
            )

    # ---------------------------------------------------------
    # ANALYSIS
    # ---------------------------------------------------------

    print("\n[1] FILE METADATA ANALYSIS")
    print("-" * 70)

    result = engine.analyze_file(
        test_file
    )

    print(
        "Engine       :",
        result.get("engine")
    )

    print(
        "Status       :",
        result.get("status")
    )

    if result.get("success"):

        file_info = result["file"]
        identity = result["identity"]
        timestamps = result["timestamps"]
        forensic = result["forensic"]
        assessment = result["assessment"]

        print(
            "File         :",
            file_info["file_name"]
        )

        print(
            "Extension    :",
            file_info["extension"]
        )

        print(
            "Size         :",
            file_info["size_bytes"],
            "bytes"
        )

        print(
            "SHA-256      :",
            identity["sha256"]
        )

        print(
            "MIME Type    :",
            identity["mime_type"]
        )

        print(
            "Entropy      :",
            forensic["entropy"]
        )

        print(
            "Risk Score   :",
            assessment["risk_score"]
        )

        print(
            "Risk Level   :",
            assessment["risk_level"]
        )

        print(
            "\nCreated UTC  :",
            timestamps["created_utc"]
        )

        print(
            "Modified UTC :",
            timestamps["modified_utc"]
        )

        print(
            "Accessed UTC :",
            timestamps["accessed_utc"]
        )

        print(
            "\nAttributes:"
        )

        if forensic["attributes"]:

            for attribute in forensic["attributes"]:

                print(
                    " -",
                    attribute
                )

        else:

            print(
                " - No unusual file attributes detected."
            )

        print(
            "\nFindings:"
        )

        if assessment["findings"]:

            for finding in assessment["findings"]:

                print(
                    " -",
                    finding
                )

        else:

            print(
                " - No significant metadata indicators detected."
            )

    else:

        print(
            "Message      :",
            result.get("message")
        )

    # ---------------------------------------------------------
    # MISSING FILE TEST
    # ---------------------------------------------------------

    print("\n[2] MISSING FILE TEST")
    print("-" * 70)

    missing_result = engine.analyze_file(
        os.path.join(
            test_directory,
            "does_not_exist.xyz"
        )
    )

    print(
        "Status       :",
        missing_result.get("status")
    )

    print(
        "Message      :",
        missing_result.get("message")
    )

    # ---------------------------------------------------------
    # EMPTY INPUT TEST
    # ---------------------------------------------------------

    print("\n[3] EMPTY INPUT TEST")
    print("-" * 70)

    empty_result = engine.analyze_file(
        ""
    )

    print(
        "Status       :",
        empty_result.get("status")
    )

    print(
        "Message      :",
        empty_result.get("message")
    )

    # ---------------------------------------------------------
    # FINAL
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("FORENSIC METADATA TEST COMPLETED")
    print("=" * 70)