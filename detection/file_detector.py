import hashlib
import math
import re
from pathlib import Path


# Files/extensions that deserve additional inspection.
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
}


SUSPICIOUS_PATTERNS = [
    rb"powershell",
    rb"cmd\.exe",
    rb"wscript",
    rb"cscript",
    rb"rundll32",
    rb"regsvr32",
    rb"mshta",
    rb"downloadstring",
    rb"invoke-expression",
    rb"base64",
    rb"createprocess",
]


def calculate_entropy(data):
    if not data:
        return 0.0

    frequency = {}

    for byte in data:
        frequency[byte] = frequency.get(byte, 0) + 1

    length = len(data)
    entropy = 0.0

    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 2)


def calculate_sha256(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        for block in iter(lambda: file.read(1024 * 1024), b""):
            sha256.update(block)

    return sha256.hexdigest()


def detect_patterns(data):

    findings = []

    for pattern in SUSPICIOUS_PATTERNS:

        if re.search(pattern, data, re.IGNORECASE):
            findings.append(
                pattern.decode("utf-8", errors="ignore")
            )

    return findings


def analyze_file(file_path):

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError("File not found")

    if not path.is_file():
        raise ValueError("Path is not a file")

    file_size = path.stat().st_size
    extension = path.suffix.lower()

    # Limit memory usage for the analysis sample.
    with open(path, "rb") as file:
        sample = file.read(5 * 1024 * 1024)

    sha256 = calculate_sha256(path)

    entropy = calculate_entropy(sample)

    suspicious_patterns = detect_patterns(sample)

    score = 0
    findings = []

    if extension in SUSPICIOUS_EXTENSIONS:

        score += 25

        findings.append(
            f"Executable or script extension detected: {extension}"
        )

    if entropy >= 7.2:

        score += 25

        findings.append(
            f"High entropy detected: {entropy}"
        )

    elif entropy >= 6.5:

        score += 10

        findings.append(
            f"Elevated entropy detected: {entropy}"
        )

    if suspicious_patterns:

        score += min(len(suspicious_patterns) * 10, 40)

        findings.append(
            "Suspicious execution-related patterns detected"
        )

    score = min(score, 100)

    if score >= 70:
        risk_level = "CRITICAL"

    elif score >= 45:
        risk_level = "HIGH"

    elif score >= 20:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return {

        "file_name": path.name,

        "extension": extension or "none",

        "size_bytes": file_size,

        "sha256": sha256,

        "entropy": entropy,

        "suspicious_patterns": suspicious_patterns,

        "findings": findings,

        "risk_score": score,

        "risk_level": risk_level,

    }