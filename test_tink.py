"""test_tink.py —— unit tests for the Python tink package (tink.py).
Run: python test_tink.py   (stdout: PASS/FAIL per group, non-zero exit on failure)
"""

import sys

import tink

failures = 0


def check(cond, msg):
    global failures
    if not cond:
        print("FAIL:", msg)
        failures += 1


def test_crc32_vector():
    check(tink.crc32(b"123456789") == 0xCBF43926, "crc32 vector")
    check(tink.crc32(b"") == 0, "crc32 empty")


def test_frame_roundtrip():
    payload = b"\x01\x02\x03"
    frame = tink.frame_encode(payload)
    check(frame == len(payload).to_bytes(4, "big") + payload + tink.crc32(payload).to_bytes(4, "big"),
          "frame bytes layout")
    res = tink.frame_next(frame, 0)
    check(res is not None, "frame_next ok")
    back, next_pos = res
    check(next_pos == len(frame), "next_pos == len(frame)")
    check(back == payload, "payload roundtrip")


def test_empty_frame_roundtrip():
    frame = tink.frame_encode(b"")
    res = tink.frame_next(frame, 0)
    check(res is not None and res[0] == b"" and res[1] == len(frame), "empty frame roundtrip")


def test_crc_tamper_rejected():
    frame = bytearray(tink.frame_encode(b"\x01\x02\x03"))
    frame[5] += 1  # tamper payload[1]
    check(tink.frame_next(bytes(frame), 0) is None, "tampered frame rejected")


def test_frame_skip_matches_len():
    frame = tink.frame_encode(b"\x01\x02\x03")
    check(tink.frame_skip(frame, 0) == len(frame), "frame_skip == len(frame)")


def test_out_of_bounds():
    frame = tink.frame_encode(b"\x01\x02\x03")
    check(tink.frame_next(frame, len(frame)) is None, "frame_next OOB")
    check(tink.frame_skip(frame, len(frame)) is None, "frame_skip OOB")
    check(tink.frame_next(frame, -1) is None, "frame_next neg pos")
    check(tink.frame_next(frame, len(frame) - 1) is None, "truncated header")


def test_multiple_frames():
    a = tink.frame_encode(b"\x0A\x0B")
    b = tink.frame_encode(b"\x63")
    buf = a + b
    res = tink.frame_next(buf, 0)
    check(res is not None and res[0] == b"\x0A\x0B", "first frame payload")
    res2 = tink.frame_next(buf, res[1])
    check(res2 is not None and res2[0] == b"\x63", "second frame payload")
    check(res2[1] == len(buf), "both frames consumed")


def main():
    test_crc32_vector()
    test_frame_roundtrip()
    test_empty_frame_roundtrip()
    test_crc_tamper_rejected()
    test_frame_skip_matches_len()
    test_out_of_bounds()
    test_multiple_frames()
    if failures:
        print("%d test(s) FAILED" % failures)
        sys.exit(1)
    print("all Python tink tests passed")


if __name__ == "__main__":
    main()
