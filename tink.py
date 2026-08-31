"""tink.py —— tink data-flow node frame protocol (universal, language-agnostic).

Frame = `[len u32 BE][payload][crc u32 BE]`; `crc` = CRC32-IEEE (0xEDB88320).
Mirrors `std/tink.tie` (tie standard library) and the Rust crate / C library;
pure functions over bytes, IO (stdin/stdout) left to the caller.

    import tink
    frame = tink.frame_encode(b"hi")
    payload, pos = tink.frame_next(frame, 0)
    assert payload == b"hi" and pos == len(frame)

Python 3 only, no dependencies beyond the standard library.
"""

import struct
import zlib


def crc32(data):
    """CRC32-IEEE over a bytes object (matches zlib.crc32 / the check vector
    `crc32(b"123456789") == 0xCBF43926`)."""
    return zlib.crc32(data) & 0xFFFFFFFF


def frame_encode(payload):
    """Encode a payload into a full frame: `[len u32 BE][payload][crc u32 BE]`.

    `payload` must be bytes (or bytes-like). Returns bytes."""
    payload = bytes(payload)
    return struct.pack(">I", len(payload)) + payload + struct.pack(">I", crc32(payload))


def frame_next(bytes_, pos):
    """Parse one frame at `pos` (verifies CRC). Returns `(payload, next_pos)`,
    or `None` on out-of-bounds or CRC mismatch.

    `bytes_` must be bytes; the returned payload is a view-like slice."""
    if pos < 0 or len(bytes_) < pos + 8:
        return None
    n = int.from_bytes(bytes_[pos:pos + 4], "big")
    end = pos + 8 + n
    if len(bytes_) < end:
        return None
    payload = bytes_[pos + 4:pos + 4 + n]
    want = int.from_bytes(bytes_[end - 4:end], "big")
    if crc32(payload) != want:
        return None
    return payload, end


def frame_skip(bytes_, pos):
    """Skip one frame at `pos` without copying or verifying (zero-copy).
    Returns `next_pos`, or `None` on out-of-bounds.

    Suitable for large payloads that only need to be located, or fast
    positioning across a batch of frames."""
    if pos < 0 or len(bytes_) < pos + 8:
        return None
    n = int.from_bytes(bytes_[pos:pos + 4], "big")
    end = pos + 8 + n
    if len(bytes_) < end:
        return None
    return end
