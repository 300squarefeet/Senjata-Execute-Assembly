#!/usr/bin/env python3
"""Recompute DJB2 hashes for NLog type FullNames. Run once per NLog version
bump; values are baked into NLogConfigHelper.cs as const uint literals."""

NAMES = [
    "NLog.LogManager",
    "NLog.Config.LoggingConfiguration",
    "NLog.Targets.ConsoleTarget",
    "NLog.LogLevel",
]

def djb2(s: str) -> int:
    h = 5381
    for ch in s:
        h = ((h << 5) + h + ord(ch)) & 0xFFFFFFFF
    return h

if __name__ == "__main__":
    for n in NAMES:
        print(f"{n:<40s} 0x{djb2(n):08X}")
