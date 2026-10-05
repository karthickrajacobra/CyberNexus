"""
CYBERNEXUS Ω
IOC (Indicator of Compromise) Extraction Engine

Extracts and normalizes common security indicators:
- URLs
- Domains
- IPv4 addresses
- SHA-256 / SHA-1 / MD5 hashes
- Email addresses
"""

import re
from typing import Any, Dict, List


class IOCEngine:
    """Extract and normalize Indicators of Compromise."""

    # URL pattern
    URL_PATTERN = re.compile(
        r"https?://[^\s<>'\"`]+",
        re.IGNORECASE,
    )

    # IPv4 pattern
    IP_PATTERN = re.compile(
        r"\b(?:"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\."
        r"){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
        r"\b"
    )

    # Email pattern
    EMAIL_PATTERN = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )

    # Hash patterns
    MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
    SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
    SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")

    # Domain pattern
    DOMAIN_PATTERN = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}\b"
    )

    def __init__(self):
        self.engine_name = "CYBERNEXUS Ω IOC Engine"
        self.version = "1.0.0"

    @staticmethod
    def _clean(value: str) -> str:
        """Remove common punctuation around an IOC."""
        return value.strip().strip(
            ".,;:!?)]}>\"'`"
        )

    @staticmethod
    def _unique(values: List[str]) -> List[str]:
        """Return unique values while preserving order."""
        seen = set()
        result = []

        for value in values:
            if value not in seen:
                seen.add(value)
                result.append(value)

        return result

    def extract_urls(self, text: str) -> List[str]:
        """Extract HTTP/HTTPS URLs."""
        if not text:
            return []

        urls = [
            self._clean(match)
            for match in self.URL_PATTERN.findall(text)
        ]

        return self._unique(urls)

    def extract_emails(self, text: str) -> List[str]:
        """Extract email addresses."""
        if not text:
            return []

        emails = [
            self._clean(match)
            for match in self.EMAIL_PATTERN.findall(text)
        ]

        return self._unique(emails)

    def extract_ips(self, text: str) -> List[str]:
        """Extract IPv4 addresses."""
        if not text:
            return []

        ips = [
            self._clean(match)
            for match in self.IP_PATTERN.findall(text)
        ]

        return self._unique(ips)

    def extract_hashes(self, text: str) -> Dict[str, List[str]]:
        """Extract MD5, SHA-1 and SHA-256 hashes."""
        if not text:
            return {
                "md5": [],
                "sha1": [],
                "sha256": [],
            }

        md5 = self._unique(
            [self._clean(x) for x in self.MD5_PATTERN.findall(text)]
        )

        sha1 = self._unique(
            [self._clean(x) for x in self.SHA1_PATTERN.findall(text)]
        )

        sha256 = self._unique(
            [self._clean(x) for x in self.SHA256_PATTERN.findall(text)]
        )

        return {
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
        }

    def extract_domains(self, text: str) -> List[str]:
        """Extract domain names while avoiding email-local parts."""
        if not text:
            return []

        domains = []

        # Domains appearing inside URLs
        for url in self.extract_urls(text):
            match = re.search(
                r"https?://([^/:?#]+)",
                url,
                re.IGNORECASE,
            )

            if match:
                domains.append(match.group(1).lower())

        # Standalone domain-looking strings
        for match in self.DOMAIN_PATTERN.findall(text):
            domain = self._clean(match).lower()

            # Skip obvious email addresses
            if "@" not in domain:
                domains.append(domain)

        return self._unique(domains)

    def extract_all(self, text: str) -> Dict[str, Any]:
        """
        Extract all supported IOCs from text.
        """

        if text is None:
            text = ""

        text = str(text)

        hashes = self.extract_hashes(text)

        return {
            "engine": self.engine_name,
            "version": self.version,
            "success": True,
            "ioc_count": (
                len(self.extract_urls(text))
                + len(self.extract_domains(text))
                + len(self.extract_ips(text))
                + len(self.extract_emails(text))
                + len(hashes["md5"])
                + len(hashes["sha1"])
                + len(hashes["sha256"])
            ),
            "iocs": {
                "urls": self.extract_urls(text),
                "domains": self.extract_domains(text),
                "ips": self.extract_ips(text),
                "emails": self.extract_emails(text),
                "hashes": hashes,
            },
        }


def extract_iocs(text: str) -> Dict[str, Any]:
    """
    Convenience function for external modules.
    """
    engine = IOCEngine()
    return engine.extract_all(text)


if __name__ == "__main__":
    test_data = """
    Suspicious email received from attacker@example.com.

    Visit:
    https://malicious-example.com/login

    Another URL:
    http://192.168.1.100/update

    SHA256:
    0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

    MD5:
    d41d8cd98f00b204e9800998ecf8427e
    """

    engine = IOCEngine()
    result = engine.extract_all(test_data)

    print("=" * 60)
    print("CYBERNEXUS Ω IOC ENGINE TEST")
    print("=" * 60)
    print(f"Engine      : {result['engine']}")
    print(f"Version     : {result['version']}")
    print(f"IOC Count   : {result['ioc_count']}")
    print()

    print("URLs:")
    for item in result["iocs"]["urls"]:
        print(f"  - {item}")

    print("\nDomains:")
    for item in result["iocs"]["domains"]:
        print(f"  - {item}")

    print("\nIPs:")
    for item in result["iocs"]["ips"]:
        print(f"  - {item}")

    print("\nEmails:")
    for item in result["iocs"]["emails"]:
        print(f"  - {item}")

    print("\nHashes:")
    print("  MD5:")
    for item in result["iocs"]["hashes"]["md5"]:
        print(f"    - {item}")

    print("  SHA1:")
    for item in result["iocs"]["hashes"]["sha1"]:
        print(f"    - {item}")

    print("  SHA256:")
    for item in result["iocs"]["hashes"]["sha256"]:
        print(f"    - {item}")

    print("=" * 60)