#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v csc >/dev/null && ! command -v dotnet >/dev/null; then
    echo "ERROR: need csc or dotnet on PATH" >&2
    exit 1
fi

echo "==> Building NLogConfigHelper.exe"
if command -v csc >/dev/null; then
    csc /target:exe /out:NLogConfigHelper.exe /optimize+ /nostdlib- \
        /reference:mscorlib.dll /reference:System.dll NLogConfigHelper.cs
else
    dotnet build -c Release -nologo
    cp bin/Release/net472/NLogConfigHelper.exe ./NLogConfigHelper.exe
fi

if [[ ! -f NLogConfigHelper.exe ]]; then
    echo "ERROR: NLogConfigHelper.exe not produced" >&2
    exit 1
fi
SIZE=$(stat -f%z NLogConfigHelper.exe 2>/dev/null || stat -c%s NLogConfigHelper.exe)
echo "==> NLogConfigHelper size: $SIZE bytes"

ASSETS=../../bofs/senjata-execute-assembly/assets
mkdir -p "$ASSETS"
python3 ../xor.py NLogConfigHelper.exe "$ASSETS/nlog.dll.xor"
echo "==> Asset written: $ASSETS/nlog.dll.xor"
echo "Next: cargo make build && git add $ASSETS/nlog.dll.xor && commit"
