import hashlib
from typing import Dict

def get_file_hashes(file_content: bytes) -> Dict[str, str]:
    """Generates MD5, SHA1, and SHA256 hashes for the given file content."""
    return {
        "md5": hashlib.md5(file_content).hexdigest(),
        "sha1": hashlib.sha1(file_content).hexdigest(),
        "sha256": hashlib.sha256(file_content).hexdigest()
    }

def sha1_hash_string(target: str) -> str:
    """Returns the SHA1 hash of a string, uppercase (useful for HIBP API)."""
    return hashlib.sha1(target.encode('utf-8')).hexdigest().upper()
