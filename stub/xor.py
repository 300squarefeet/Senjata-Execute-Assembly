#!/usr/bin/env python3
"""XOR-encode a file with a 16-byte fixed key for embedding into the BOF."""
import sys
from pathlib import Path

# Fixed 16-byte key. Re-run build-stub.sh after changing this — the matching
# const in opsec-coreclr/src/host.rs must change too.
KEY = bytes.fromhex("a9 3f 17 c4 ee 0b 8d 51 22 6a 7f 04 9c b3 e7 56".replace(" ", ""))

def xor_bytes(buf: bytes) -> bytes:
    return bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(buf))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: xor.py <input.dll> <output.xor>", file=sys.stderr)
        sys.exit(1)
    src = Path(sys.argv[1]).read_bytes()
    Path(sys.argv[2]).write_bytes(xor_bytes(src))
    print(f"wrote {sys.argv[2]} ({len(src)} bytes XOR'd)")
