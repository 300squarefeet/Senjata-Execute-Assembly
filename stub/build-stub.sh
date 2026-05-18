#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/senjata-loader"
echo "==> dotnet publish (Release, no trim)"
dotnet publish -c Release -o ./out > /dev/null
DLL="./out/SenjataLoader.dll"
if [[ ! -f "$DLL" ]]; then
    echo "ERROR: $DLL not found after publish" >&2
    exit 1
fi
SIZE=$(stat -f%z "$DLL" 2>/dev/null || stat -c%s "$DLL")
echo "==> Stub size: $SIZE bytes"
ASSETS=../../bofs/senjata-execute-assembly/assets
mkdir -p "$ASSETS"
python3 ../xor.py "$DLL" "$ASSETS/stub.dll.xor"
echo "==> Committed asset path: $ASSETS/stub.dll.xor"
echo "Next: cargo make build && git add $ASSETS/stub.dll.xor && commit"
