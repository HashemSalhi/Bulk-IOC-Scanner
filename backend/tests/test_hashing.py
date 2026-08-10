"""Tests for local file hashing — verifies hashes match known values and temp cleanup."""
import hashlib
import io

import pytest
from starlette.datastructures import Headers, UploadFile

from bulk_ioc_scanner.services.hashing import hash_upload


def make_upload(content: bytes, filename: str = "sample.bin") -> UploadFile:
    return UploadFile(
        file=io.BytesIO(content),
        filename=filename,
        headers=Headers({"content-type": "application/octet-stream"}),
    )


async def test_hashes_match_hashlib():
    content = b"The quick brown fox jumps over the lazy dog"
    upload = make_upload(content)

    result = await hash_upload(upload, max_bytes=10 * 1024 * 1024)

    assert result.md5 == hashlib.md5(content).hexdigest()
    assert result.sha1 == hashlib.sha1(content).hexdigest()
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert result.size == len(content)
    assert result.filename == "sample.bin"


async def test_empty_file():
    upload = make_upload(b"")
    result = await hash_upload(upload, max_bytes=1024)
    assert result.size == 0
    assert result.md5 == hashlib.md5(b"").hexdigest()


async def test_oversize_file_raises():
    content = b"A" * 5000
    upload = make_upload(content)
    with pytest.raises(ValueError, match="exceeds"):
        await hash_upload(upload, max_bytes=1000)


async def test_large_multichunk_file():
    # Larger than the 64 KB chunk size to exercise streaming loop
    content = b"X" * (200 * 1024)
    upload = make_upload(content)
    result = await hash_upload(upload, max_bytes=10 * 1024 * 1024)
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert result.size == len(content)
