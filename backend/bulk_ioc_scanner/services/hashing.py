"""Stream-hash uploaded files locally; never retain the bytes."""
import hashlib
import os
import tempfile
from dataclasses import dataclass

from fastapi import UploadFile

CHUNK = 65536  # 64 KB read chunks


@dataclass
class FileHashes:
    filename: str
    size: int
    md5: str
    sha1: str
    sha256: str


async def hash_upload(upload: UploadFile, max_bytes: int) -> FileHashes:
    """
    Stream the uploaded file into a temp file, compute MD5/SHA1/SHA256,
    delete the temp file, and return the hash results.

    Raises ValueError if the file exceeds max_bytes.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    total = 0

    tmp_fd, tmp_path = tempfile.mkstemp(prefix="bulk_ioc_scanner_")
    try:
        with os.fdopen(tmp_fd, "wb") as tmp_file:
            while True:
                chunk = await upload.read(CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(
                        f"File '{upload.filename}' exceeds the {max_bytes // (1024*1024)} MB limit"
                    )
                tmp_file.write(chunk)
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
    finally:
        # Always remove the temp file — only hashes leave this function
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return FileHashes(
        filename=upload.filename or "unknown",
        size=total,
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
    )
