"""tink_v3.py —— tink v3 frame skeleton + message fragmentation.

Mirrors `tink_v3.c` and the tie reference implementation (`tlib/std/tink_v3.tie`);
KAT vectors are byte-exact across languages.

Frame (16-byte fixed header, big-endian; design doc §3):
  [magic 0x74 0x6B][ver=3][type][flags u16][stream_id u32][seq u32][len u16]
  [ext region: ext_len u16 + TLV bytes]?   (flags.EXT)
  [payload: len bytes]                     (flags.OFFSET: first 4 bytes = u32 BE offset)
  [tail: CRC32C 4B | AEAD tag 16B | none]
flags: 1=EXT 2=PROTECTED 4=CRC 8=FIN 16=OFFSET 32=URGENT.

Implemented subset: CRC32C tail, EXT region, single-frame up to 65535 bytes,
message fragmentation (> 65531 bytes split into OFFSET+FIN fragments, seq =
fragment index) with transparent reassembly on decode. PROTECTED frames are
rejected (crypto layer out of scope).

    frame = msg_encode(b"hi")            # single frame
    payload, pos = msg_decode(frame, 0)  # -> (b"hi", len(frame))

Python 3 only, standard library.
"""

import struct
from typing import Optional, Tuple

T_MESSAGE = 0x04
F_EXT = 1
F_PROTECTED = 2
F_CRC = 4
F_FIN = 8
F_OFFSET = 16
F_URGENT = 32

CHUNK_MAX = 65531  # max fragment data (65535 - 4-byte offset prefix)


def _crc_table():
    poly = 0x82F63B78
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = ((c >> 1) ^ poly) if (c & 1) else (c >> 1)
        t.append(c)
    return t


_CRC_TAB = _crc_table()


def crc32c(data: bytes) -> int:
    """CRC32C (Castagnoli, reflected poly 0x82F63B78; init/xorout 0xFFFFFFFF).

    Check vector: crc32c(b"123456789") == 0xE3069283."""
    c = 0xFFFFFFFF
    for b in data:
        c = (c >> 8) ^ _CRC_TAB[(c ^ b) & 0xFF]
    return c ^ 0xFFFFFFFF


def _frame_one(payload: bytes, flags: int, seq: int, ext: bytes = b"") -> bytes:
    out = bytearray()
    out += b"\x74\x6b\x03" + bytes([T_MESSAGE])
    out += struct.pack(">H", flags)
    out += struct.pack(">I", 0)  # stream_id
    out += struct.pack(">I", seq)
    out += struct.pack(">H", len(payload))
    if flags & F_EXT:
        out += struct.pack(">H", len(ext))
        out += ext
    out += payload
    out += struct.pack(">I", crc32c(bytes(out)))
    return bytes(out)


def frame_encode(payload: bytes) -> bytes:
    """Single frame without extension region (CRC|FIN; payload up to 65535)."""
    if len(payload) > 65535:
        raise ValueError("payload too large for a single frame")
    return _frame_one(payload, F_CRC | F_FIN, 0)


def frame_encode_ext(payload: bytes, ext: bytes) -> bytes:
    """Single frame carrying an extension region (raw TLV bytes)."""
    if len(payload) > 65535 or len(ext) > 65535:
        raise ValueError("payload or ext too large")
    flags = F_CRC | F_FIN | (F_EXT if ext else 0)
    return _frame_one(payload, flags, 0, ext)


def msg_encode(payload: bytes) -> bytes:
    """Message layer: single frame when <= 65531, else OFFSET fragments."""
    if len(payload) <= CHUNK_MAX:
        return _frame_one(payload, F_CRC | F_FIN, 0)
    out = bytearray()
    off = 0
    idx = 0
    while off < len(payload):
        chunk = payload[off:off + CHUNK_MAX]
        flags = F_CRC | F_OFFSET | (F_FIN if off + len(chunk) == len(payload) else 0)
        body = struct.pack(">I", off) + chunk
        out += _frame_one(body, flags, idx)
        off += len(chunk)
        idx += 1
    return bytes(out)


def _frame_read(b: bytes, pos: int):
    """Parse/verify one frame -> (flags, payload_offset, payload_len, next) or None."""
    if pos + 16 > len(b):
        return None
    if b[pos] != 0x74 or b[pos + 1] != 0x6B or b[pos + 2] != 3 or b[pos + 3] != T_MESSAGE:
        return None
    flags = int.from_bytes(b[pos + 4:pos + 6], "big")
    if flags & 0xFFC0:
        return None
    if flags & F_PROTECTED:
        return None
    eoff = pos + 16
    if flags & F_EXT:
        if pos + 18 > len(b):
            return None
        elen = int.from_bytes(b[pos + 16:pos + 18], "big")
        eoff = pos + 18 + elen
        if eoff > len(b):
            return None
    ln = int.from_bytes(b[pos + 14:pos + 16], "big")
    tlen = 4 if (flags & F_CRC) else 0
    if eoff + ln + tlen > len(b):
        return None
    if tlen == 4:
        want = int.from_bytes(b[eoff + ln:eoff + ln + 4], "big")
        if want != crc32c(b[pos:eoff + ln]):
            return None
    return flags, eoff, ln, eoff + ln + tlen


def msg_decode(b: bytes, pos: int) -> Optional[Tuple[bytes, int]]:
    """Decode one logical message at `pos`, reassembling fragments.
    Returns (payload, next_pos) or None on any malformed frame / CRC mismatch."""
    r = _frame_read(b, pos)
    if r is None:
        return None
    flags, po, pl, nx = r
    if not (flags & F_OFFSET):
        return b[po:po + pl], nx
    if pl < 4:
        return None
    if int.from_bytes(b[po:po + 4], "big") != 0:
        return None
    out = bytearray(b[po + 4:po + pl])
    cur = nx
    fin = bool(flags & F_FIN)
    while not fin:
        r2 = _frame_read(b, cur)
        if r2 is None:
            return None
        fl2, po2, pl2, nx2 = r2
        if not (fl2 & F_OFFSET) or pl2 < 4:
            return None
        off2 = int.from_bytes(b[po2:po2 + 4], "big")
        if off2 != len(out):
            return None
        out += b[po2 + 4:po2 + pl2]
        fin = bool(fl2 & F_FIN)
        cur = nx2
    return bytes(out), cur
