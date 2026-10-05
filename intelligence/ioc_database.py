"""
CYBERNEXUS Ω
IOC Database Layer

Compatible with the existing CyberNexus SQLite schema.

Existing iocs table:
    id
    incident_id
    ioc_type
    value
    confidence
    source
    created_at
"""

import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class IOCDatabase:
    """Persistent SQLite database layer for IOC records."""

    SUPPORTED_TYPES = {
        "URL",
        "DOMAIN",
        "IP",
        "EMAIL",
        "MD5",
        "SHA1",
        "SHA256",
    }

    def __init__(self, database_path: Optional[str] = None):

        project_root = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )

        default_database = os.path.join(
            project_root,
            "database",
            "cybernexus.db",
        )

        self.database_path = os.path.abspath(
            database_path or default_database
        )

        database_directory = os.path.dirname(
            self.database_path
        )

        os.makedirs(
            database_directory,
            exist_ok=True,
        )

    def _connect(self) -> sqlite3.Connection:
        """Create SQLite connection."""

        connection = sqlite3.connect(
            self.database_path,
            timeout=10,
        )

        connection.row_factory = sqlite3.Row

        return connection

    @staticmethod
    def _timestamp() -> str:
        """Return UTC timestamp."""

        return datetime.now(
            timezone.utc
        ).isoformat()

    @staticmethod
    def normalize_ioc_type(ioc_type: str) -> str:
        """Normalize IOC type."""

        if not ioc_type:
            raise ValueError(
                "IOC type is required."
            )

        normalized = str(
            ioc_type
        ).strip().upper()

        aliases = {
            "IPV4": "IP",
            "IPV4_ADDRESS": "IP",
            "DOMAIN_NAME": "DOMAIN",
            "MAIL": "EMAIL",
            "HASH_MD5": "MD5",
            "HASH_SHA1": "SHA1",
            "HASH_SHA256": "SHA256",
        }

        normalized = aliases.get(
            normalized,
            normalized,
        )

        if normalized not in IOCDatabase.SUPPORTED_TYPES:
            raise ValueError(
                f"Unsupported IOC type: {ioc_type}"
            )

        return normalized

    @staticmethod
    def normalize_ioc_value(
        ioc_type: str,
        value: str,
    ) -> str:
        """Normalize IOC value."""

        if value is None:
            raise ValueError(
                "IOC value is required."
            )

        normalized_type = (
            IOCDatabase.normalize_ioc_type(
                ioc_type
            )
        )

        normalized_value = str(
            value
        ).strip()

        if not normalized_value:
            raise ValueError(
                "IOC value cannot be empty."
            )

        if normalized_type in {
            "DOMAIN",
            "EMAIL",
        }:
            normalized_value = (
                normalized_value.lower()
            )

        if normalized_type in {
            "MD5",
            "SHA1",
            "SHA256",
        }:
            normalized_value = (
                normalized_value.lower()
            )

        return normalized_value

    def _ensure_table(self) -> None:
        """
        Verify that the existing iocs table exists.

        We do NOT replace or alter the existing schema.
        """

        with self._connect() as connection:

            table = connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                  AND name = 'iocs'
                """
            ).fetchone()

            if table is None:
                raise RuntimeError(
                    "Existing iocs table was not found."
                )

    def add_ioc(
        self,
        ioc_type: str,
        value: str,
        incident_id: Optional[int] = None,
        confidence: int = 0,
        source: str = "CYBERNEXUS",
    ) -> Dict[str, Any]:
        """
        Add IOC to the existing database.

        If the IOC already exists for the same type,
        the existing record is returned instead of
        creating a duplicate.
        """

        normalized_type = (
            self.normalize_ioc_type(
                ioc_type
            )
        )

        normalized_value = (
            self.normalize_ioc_value(
                normalized_type,
                value,
            )
        )

        try:
            confidence = int(
                confidence
            )
        except (
            TypeError,
            ValueError,
        ):
            confidence = 0

        confidence = max(
            0,
            min(100, confidence),
        )

        source = str(
            source or "CYBERNEXUS"
        ).strip()

        self._ensure_table()

        with self._connect() as connection:

            existing = connection.execute(
                """
                SELECT *
                FROM iocs
                WHERE ioc_type = ?
                  AND value = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (
                    normalized_type,
                    normalized_value,
                ),
            ).fetchone()

            if existing:

                return {
                    "success": True,
                    "created": False,
                    "duplicate": True,
                    "message": (
                        "IOC already exists."
                    ),
                    "ioc": dict(existing),
                }

            created_at = self._timestamp()

            cursor = connection.execute(
                """
                INSERT INTO iocs (
                    incident_id,
                    ioc_type,
                    value,
                    confidence,
                    source,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    normalized_type,
                    normalized_value,
                    confidence,
                    source,
                    created_at,
                ),
            )

            connection.commit()

            new_id = cursor.lastrowid

            row = connection.execute(
                """
                SELECT *
                FROM iocs
                WHERE id = ?
                """,
                (new_id,),
            ).fetchone()

        return {
            "success": True,
            "created": True,
            "duplicate": False,
            "message": (
                "IOC successfully added."
            ),
            "ioc": dict(row),
        }

    def get_ioc(
        self,
        ioc_type: str,
        value: str,
    ) -> Optional[Dict[str, Any]]:
        """Get one IOC."""

        normalized_type = (
            self.normalize_ioc_type(
                ioc_type
            )
        )

        normalized_value = (
            self.normalize_ioc_value(
                normalized_type,
                value,
            )
        )

        self._ensure_table()

        with self._connect() as connection:

            row = connection.execute(
                """
                SELECT *
                FROM iocs
                WHERE ioc_type = ?
                  AND value = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (
                    normalized_type,
                    normalized_value,
                ),
            ).fetchone()

        if row is None:
            return None

        return dict(row)

    def exists(
        self,
        ioc_type: str,
        value: str,
    ) -> bool:
        """Check whether IOC already exists."""

        return (
            self.get_ioc(
                ioc_type,
                value,
            )
            is not None
        )

    def search(
        self,
        value: str = "",
        ioc_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Search IOC database."""

        self._ensure_table()

        query = """
            SELECT *
            FROM iocs
            WHERE 1 = 1
        """

        parameters: List[Any] = []

        if value:

            query += """
                AND value LIKE ?
            """

            parameters.append(
                f"%{str(value).strip()}%"
            )

        if ioc_type:

            normalized_type = (
                self.normalize_ioc_type(
                    ioc_type
                )
            )

            query += """
                AND ioc_type = ?
            """

            parameters.append(
                normalized_type
            )

        query += """
            ORDER BY id DESC
        """

        with self._connect() as connection:

            rows = connection.execute(
                query,
                parameters,
            ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    def count(self) -> int:
        """Return total IOC count."""

        self._ensure_table()

        with self._connect() as connection:

            row = connection.execute(
                """
                SELECT COUNT(*) AS total
                FROM iocs
                """
            ).fetchone()

        return int(
            row["total"]
        )

    def delete_ioc(
        self,
        ioc_type: str,
        value: str,
    ) -> bool:
        """Delete an IOC."""

        normalized_type = (
            self.normalize_ioc_type(
                ioc_type
            )
        )

        normalized_value = (
            self.normalize_ioc_value(
                normalized_type,
                value,
            )
        )

        self._ensure_table()

        with self._connect() as connection:

            cursor = connection.execute(
                """
                DELETE FROM iocs
                WHERE ioc_type = ?
                  AND value = ?
                """,
                (
                    normalized_type,
                    normalized_value,
                ),
            )

            connection.commit()

        return cursor.rowcount > 0


def get_ioc_database(
    database_path: Optional[str] = None,
) -> IOCDatabase:
    """Create IOC database instance."""

    return IOCDatabase(
        database_path=database_path
    )


if __name__ == "__main__":

    print("=" * 60)
    print("CYBERNEXUS Ω IOC DATABASE TEST")
    print("=" * 60)

    database = IOCDatabase()

    print(
        f"Database : {database.database_path}"
    )

    # --------------------------------------------------
    # TEST 1 — Add DOMAIN
    # --------------------------------------------------

    result_1 = database.add_ioc(
        ioc_type="DOMAIN",
        incident_id=1,
        value="malicious-example.com",
        confidence=95,
        source="IOC Engine Test",
    )

    print("\n[1] Add DOMAIN")
    print(result_1)

    # --------------------------------------------------
    # TEST 2 — Duplicate DOMAIN
    # --------------------------------------------------

    result_2 = database.add_ioc(
        ioc_type="DOMAIN",
        incident_id=1,
        value="MALICIOUS-EXAMPLE.COM",
        confidence=98,
        source="IOC Database Test",
    )

    print(
        "\n[2] Duplicate DOMAIN"
    )
    print(result_2)

    # --------------------------------------------------
    # TEST 3 — Add IP
    # --------------------------------------------------

    result_3 = database.add_ioc(
        ioc_type="IP",
        incident_id=1,
        value="192.168.1.100",
        confidence=80,
        source="IOC Engine Test",
    )

    print("\n[3] Add IP")
    print(result_3)

    # --------------------------------------------------
    # TEST 4 — Add SHA256
    # --------------------------------------------------

    sha256_value = (
        "0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef"
    )

    result_4 = database.add_ioc(
        ioc_type="SHA256",
        incident_id=1,
        value=sha256_value,
        confidence=90,
        source="File Detector",
    )

    print("\n[4] Add SHA256")
    print(result_4)

    # --------------------------------------------------
    # TEST 5 — Lookup
    # --------------------------------------------------

    print(
        "\n[5] Lookup DOMAIN"
    )

    lookup = database.get_ioc(
        "DOMAIN",
        "malicious-example.com",
    )

    print(lookup)

    # --------------------------------------------------
    # TEST 6 — Exists
    # --------------------------------------------------

    print(
        "\n[6] Exists check"
    )

    print(
        database.exists(
            "DOMAIN",
            "malicious-example.com",
        )
    )

    # --------------------------------------------------
    # TEST 7 — Search
    # --------------------------------------------------

    print(
        "\n[7] Search"
    )

    results = database.search()

    for item in results:

        print(
            f"  ID={item['id']} | "
            f"TYPE={item['ioc_type']} | "
            f"VALUE={item['value']} | "
            f"CONFIDENCE={item['confidence']} | "
            f"SOURCE={item['source']}"
        )

    # --------------------------------------------------
    # TEST 8 — Count
    # --------------------------------------------------

    print(
        "\n[8] IOC Count"
    )

    print(
        f"Total IOC records: {database.count()}"
    )

    print("=" * 60)
    print(
        "IOC DATABASE TEST COMPLETE"
    )
    print("=" * 60)