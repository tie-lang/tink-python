# tink-python

tink data-flow node frame protocol — Python package (stdlib only, Python 3).
Universal and language-agnostic: any component that obeys the frame protocol
can join a tink pipeline.

```
帧 = [ len: u32 BE ][ payload: len 字节 ][ crc: u32 BE ]
len = payload 字节数
crc = CRC32-IEEE(payload)（多项式 0xEDB88320）
```

Mirrors `std/tink.tie` (tie standard library) and the Rust / C tink libraries;
pure functions over `bytes`, IO (stdin/stdout) left to the caller. `crc32`
reuses `zlib.crc32`.

## API

| function | description |
| --- | --- |
| `crc32(data: bytes) -> int` | CRC32-IEEE. Check vector: `crc32(b"123456789") == 0xCBF43926` |
| `frame_encode(payload: bytes) -> bytes` | encode a payload into a full frame `[len][payload][crc]` |
| `frame_next(bytes_: bytes, pos: int) -> (bytes, int) | None` | parse one frame at `pos`, verify CRC; `None` on out-of-bounds / mismatch |
| `frame_skip(bytes_: bytes, pos: int) -> int | None` | skip one frame at `pos` without copying or verifying (zero-copy) |

## Usage

```python
import tink

frame = tink.frame_encode(b"hi")
res = tink.frame_next(frame, 0)
payload, pos = res  # payload == b"hi", pos == len(frame)
```

## Test

```bash
python test_tink.py
```

## Cross-language

tink 帧协议各语言实现（API 语义与校验向量一致）：

| language | library |
| --- | --- |
| tie | `std/tink.tie` |
| Rust | `tink-rust`（tink crate） |
| C | `tink-c`（`tink.h` + `tink.c`） |
| Python | this package（`tink-python`） |

## License

本仓库使用 **TIE-LANG Open Source License v1.1**，完整文本见 [LICENSE](LICENSE)。
This repository is distributed under the **TIE-LANG Open Source License v1.1** — see [LICENSE](LICENSE) for the full text.
