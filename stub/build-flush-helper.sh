#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/senjata-flush-helper"
echo "==> ilasm compile (MSIL, mscorlib 4.0.0.0)"
ilasm -exe -quiet -nologo -out:FlushHelper.exe FlushHelper.il
if [[ ! -f FlushHelper.exe ]]; then
    echo "ERROR: FlushHelper.exe not produced" >&2
    exit 1
fi
SIZE=$(stat -f%z FlushHelper.exe 2>/dev/null || stat -c%s FlushHelper.exe)
echo "==> Flush helper size: $SIZE bytes"
ASSETS=../../bofs/senjata-execute-assembly/assets
mkdir -p "$ASSETS"
python3 ../xor.py FlushHelper.exe "$ASSETS/flush.dll.xor"
echo "==> Asset: $ASSETS/flush.dll.xor"
echo "Next: cargo make build && git add $ASSETS/flush.dll.xor && commit"
