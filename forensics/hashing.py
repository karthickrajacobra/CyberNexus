import hashlib


def sha256_bytes(data: bytes) -> str:
    """
    Generate SHA-256 hash for raw bytes.
    """
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    """
    Generate SHA-256 hash for text.
    """
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(file_path: str) -> str:
    """
    Generate SHA-256 hash for a file.
    """
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            sha256.update(chunk)

    return sha256.hexdigest()