"""Hashing and lightweight file-signature (magic byte) helpers.

We only ever hash bytes we actually pulled out of the capture — nothing
here invents a hash for a file that couldn't be reassembled.
"""

import hashlib
from typing import Dict, Optional

# A small set of well-known magic-byte signatures. Not exhaustive, but
# enough to label the file types the assignment calls out by name.
MAGIC_SIGNATURES = {
    b"MZ": "PE executable / DLL",
    b"PK\x03\x04": "ZIP archive (or Office/JAR container)",
    b"%PDF": "PDF document",
    b"\x7fELF": "ELF executable",
    b"\x1f\x8b": "GZIP archive",
    b"Rar!": "RAR archive",
    b"#!": "Script (shebang)",
}


def hashes_for(data: bytes) -> Dict[str, str]:
    """Compute MD5/SHA1/SHA256 for a blob of bytes actually recovered
    from the capture."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def identify_signature(data: bytes) -> Optional[str]:
    """Return a human-readable file type based on magic bytes, or None
    if nothing in our small signature table matches."""
    for magic, label in MAGIC_SIGNATURES.items():
        if data.startswith(magic):
            return label
    return None
