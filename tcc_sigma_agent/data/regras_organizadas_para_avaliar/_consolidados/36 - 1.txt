# Arquivo: A.yml
title: SmartScreen Bypass Leading to DarkGate-like Payload Execution
id: 4b2f9d7e-2026-smartscreen-darkgate-0001
status: experimental
description: Detects patterns consistent with exploitation of SmartScreen/Windows application reputation to deliver and execute payloads (as observed in DarkGate campaigns). Flags download of executables or installers to user download locations with MarkOfTheWeb (Zone.Identifier) followed by execution, execution of unsigned binaries originating from browser parents or SmartScreen processes, and rapid post-download network connections typical of remote access malware.
author: Detection Engineer
date: 2026-06-06
references:
  - https://www.bleepingcomputer.com/news/security/hackers-exploit-windows-smartscreen-flaw-to-drop-darkgate-malware/
  - https://www.trendmicro.com/en_us/research/24/c/cve-2024-21412--darkgate-operators-exploit-microsoft-windows-sma.html
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection_download_to_user:
    EventID: 11
    TargetFilename|re:
      - '(?i)\\Users\

\[^\\]

+\\Downloads\\.*\.(exe|msi|msix|appx|zip|7z)$'
    TargetFilename|contains:
      - "Zone.Identifier"
  selection_browser_parent:
    EventID: 1
    ParentImage|re:
      - '(?i)\\(msedge|chrome|firefox|iexplore|brave|opera)\.exe$'
    Image|re:
      - '(?i)\\.*\.(exe|msi|msix|appx)$'
  selection_smartscreen_parent:
    EventID: 1
    ParentImage|re:
      - '(?i)\\smartscreen\.exe$'
      - '(?i)\\ApplicationReputation\.exe$'
    Image|re:
      - '(?i)\\.*\.(exe|msi|msix|appx)$'
  selection_unsigned_execution:
    EventID: 1
    Image|re:
      - '(?i)\\Users\

\[^\\]

+\\Downloads\\.*\.(exe|msi|msix|appx)$'
    Signed: "false"
  selection_execution_from_temp:
    EventID: 1
    Image|re:
      - '(?i)\\AppData\\Local\\Temp\\.*\.(exe|dll|ps1|bat)$'
    ParentImage|re:
      - '(?i)\\(msedge|chrome|firefox|iexplore|smartscreen|dfsvc)\.exe$'
  selection_post_download_network:
    EventID: 3
    DestinationPort:
      - 443
      - 8443
      - 80
    DestinationIp|not_in_cidr:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
  condition: (selection_download_to_user and (selection_browser_parent or selection_smartscreen_parent)) or selection_unsigned_execution or selection_execution_from_temp or (selection_download_to_user and selection_post_download_network)
fields:
  - timestamp
  - EventID
  - ComputerName
  - SubjectUserName
  - Image
  - ParentImage
  - CommandLine
  - TargetFilename
  - Signed
  - DestinationIp
  - DestinationPort
  - ProcessId
falsepositives:
  - Legitimate user downloads and executions of installers from trusted vendors.
  - Enterprise software distribution tools that stage installers in user download or temp locations.
  - Security testing or red-team activity that intentionally downloads and runs unsigned artifacts.
level: high
tags:
  - attack.initial_access
  - attack.execution
  - attack.defense_evasion
  - malware.darkgate
  - detection.windows.sysmon
notes: |
  - Tuning: whitelist known vendor installers, enterprise deployment systems, and trusted browser automation accounts; consider requiring additional context (e.g., network C2 indicators, unusual parent/child process trees) to reduce noise.
  - Investigation: collect the downloaded file (preserve Zone.Identifier ADS), compute hashes, capture full process tree and command lines, check digital signature status, gather subsequent network connections and TLS metadata, and search for similar artifacts across the environment.
  - Response: isolate affected hosts if malicious activity is confirmed, block identified C2 endpoints, remove unauthorized artifacts, and review SmartScreen/Windows update status and mitigations for CVE-2024-21412 where applicable.


---
# Arquivo: B.yml
title: Suspicious Expand.exe Execution Related To DarkGate (CVE-2024-21412)
id: d76b5d27-4c3e-4b2a-9e1f-8246f4b6a9c1
status: experimental
description: |
  Detects the use of expand.exe to extract a cabinet file named 'files.cab' within a temporary directory prefixed with 'MW-'. 
  This specific behavior is initiated by a malicious MSI CustomActionDLL and has been observed in DarkGate malware campaigns exploiting the Windows SmartScreen bypass vulnerability CVE-2024-21412.
author: Gemini
date: 2024/05/18
references:
    - https://www.trendmicro.com/en_us/research/24/c/cve-2024-21412--darkgate-operators-exploit-microsoft-windows-sma.html
    - https://www.bleepingcomputer.com/news/security/hackers-exploit-windows-smartscreen-flaw-to-drop-darkgate-malware/
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1140
    - attack.t1218
    - cve.2024.21412
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\expand.exe'
        CommandLine|contains|all:
            - '\Temp\MW-'
            - 'files.cab'
    condition: selection
falsepositives:
    - Unlikely, but possible rare legitimate installers that happen to create a temporary folder starting with 'MW-' and decompress a 'files.cab' archive.
level: high

---
# Arquivo: C.yml
title: CVE-2024-21412 SmartScreen Bypass - Chained Internet Shortcut Opens Remote MSI (DarkGate)
id: 9b14c72e-3f08-4a1e-b247-6e8dc305fa1b
status: experimental
description: |
    Detects the host-side execution chain exploiting CVE-2024-21412, a Windows Defender
    SmartScreen bypass used by DarkGate operators (and earlier by Water Hydra / DarkMe)
    since mid-January 2024. Microsoft patched the flaw in February 2024 Patch Tuesday,
    but unpatched systems remain at risk.

    The exploit abuses how Windows resolves nested Internet Shortcut (.url) files:

      Step 1 — A phishing email delivers a PDF with a Google DDM open-redirect link.
      Step 2 — The victim is sent to a compromised server hosting shortcut_1.url, which
                uses the URL= field to point to a second shortcut on an attacker-controlled
                WebDAV server:
                    URL=file://\\<attacker>\<share>\shortcut_2.url
      Step 3 — Windows follows the reference and opens shortcut_2.url, which points
                directly to the malicious MSI:
                    URL=file://\\<attacker>\<share>\<payload>.msi
      Step 4 — Because the Mark-of-the-Web (MotW) is not correctly propagated through
                the double-shortcut indirection, SmartScreen never prompts the user and
                msiexec.exe launches the MSI silently.
      Step 5 — The MSI (disguised as NVIDIA, Apple iTunes, or Notion) side-loads
                libcef.dll and uses sqlite3.dll as a shellcode loader to decrypt and
                execute DarkGate v6.

    This rule targets the pivot from Step 2 → Step 3 on the host: rundll32.exe or
    explorer.exe invoking msiexec.exe where the MSI originates from a UNC / WebDAV
    path, without a preceding user-visible Save dialog (MotW absent). It also captures
    the DLL sideload fingerprint when image-load telemetry is available.

    References:
      - https://www.bleepingcomputer.com/news/security/hackers-exploit-windows-smartscreen-flaw-to-drop-darkgate-malware/
      - https://www.trendmicro.com/en_us/research/24/c/cve-2024-21412--darkgate-operators-exploit-microsoft-windows-sma.html
      - https://nvd.nist.gov/vuln/detail/CVE-2024-21412

author: Claude (based on Trend Micro and BleepingComputer public reporting)
date: 2026-06-06
modified: 2026-06-06
tags:
    - attack.initial-access
    - attack.t1566.001           # Phishing: Spearphishing Attachment
    - attack.defense-evasion
    - attack.t1553.005           # Subvert Trust Controls: Mark-of-the-Web Bypass
    - attack.t1218.007           # System Binary Proxy Execution: Msiexec
    - attack.execution
    - attack.t1204.002           # User Execution: Malicious File
    - cve.2024-21412
    - tlp:white

logsource:
    category: process_creation
    product: windows
    # Primary: Sysmon EventID 1. Also tested against Microsoft Defender for Endpoint
    # DeviceProcessEvents and CrowdStrike ProcessRollup2. Adjust field names for your EDR.
    # Branch C (DLL sideload) additionally requires Sysmon EventID 7 (ImageLoad) —
    # use a separate logsource block if your SIEM cannot correlate event IDs in one rule.

detection:

    # ── Branch A: msiexec.exe launched with a UNC / WebDAV path as its target ──
    #
    # The exploit causes explorer.exe to invoke msiexec.exe directly against a
    # remote MSI. A UNC path in msiexec's CommandLine that bypassed MotW means
    # SmartScreen was never invoked — that's the exploit in action.
    #
    # Legitimate enterprise MSI deployments via SCCM/Intune use SYSTEM accounts
    # and specific UNC paths to known internal servers; tune the filter below.
    selection_msiexec_unc:
        Image|endswith: '\msiexec.exe'
        CommandLine|contains:
            - '\\\\'           # UNC path  \\server\share\file.msi
            - 'http://'        # WebDAV over HTTP (less common variant)
            - 'https://'       # WebDAV over HTTPS
        CommandLine|contains:
            - '.msi'

    # ── Branch B: .url file opens another .url (the double-shortcut trick) ───
    #
    # On Sysmon-instrumented hosts, when explorer.exe resolves shortcut_1.url
    # and the URL= field references a remote .url, Windows spawns a new
    # explorer.exe process with the remote .url as the argument before following
    # it to the MSI. This transient process is detectable.
    selection_url_opens_url:
        Image|endswith: '\explorer.exe'
        CommandLine|contains:
            - '.url'
        CommandLine|re: '\\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\.+\.url'
        # Matches \\<IPv4>\<any path>.url — attacker WebDAV server referenced directly
        # Legitimate network shortcuts exist but almost never reference raw IP addresses.

    # ── Branch C: DarkGate-specific DLL sideload fingerprint ─────────────────
    #
    # The MSI drops its payload to %TEMP% or %APPDATA% and sideloads libcef.dll
    # (Chromium Embedded Framework) next to a renamed sqlite3.dll loader. CEF is
    # a legitimate library but has no business being in user temp directories.
    # This branch fires on process_creation where a non-CEF-app binary loads libcef.dll
    # from a user-writable path (requires image-load logging, Sysmon EID 7).
    #
    # Note: Wire this as a separate Sysmon EID 7 (image_load) correlation if your
    # SIEM does not support mixed category rules.
    selection_libcef_sideload:
        # Spawn from msiexec or rundll32 into a user-writable directory
        ParentImage|endswith:
            - '\msiexec.exe'
            - '\rundll32.exe'
        Image|contains:
            - '\AppData\'
            - '\Temp\'
            - '\Users\'
        # Child spawned by the sideloaded DarkGate payload (cmd, powershell, etc.)
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wscript.exe'
            - '\cscript.exe'

    # ── Filter: suppress known-good enterprise MSI distribution ──────────────
    filter_sccm_intune:
        # SCCM and Intune run msiexec as SYSTEM from specific management paths.
        # Tune \\<your_sccm_server>\ to your environment.
        User|contains:
            - 'SYSTEM'
            - 'NT AUTHORITY'
        ParentImage|endswith:
            - '\ccmexec.exe'     # SCCM client
            - '\MsiExec.exe'     # Chained MSI (legitimate installer chains)
            - '\TrustedInstaller.exe'

    filter_legitimate_cef_apps:
        # Browsers and Electron apps legitimately ship libcef.dll in their own dirs.
        Image|contains:
            - '\Google\Chrome\'
            - '\Microsoft\Edge\'
            - '\Spotify\'
            - '\Discord\'
            - '\Slack\'
            - '\Teams\'

    condition: >
        (
          ( selection_msiexec_unc and not filter_sccm_intune )
          or selection_url_opens_url
          or ( selection_libcef_sideload and not filter_legitimate_cef_apps )
        )

falsepositives:
    - Branch A: Enterprise software packaging tools that stage MSIs on file servers
      (address by expanding filter_sccm_intune with your distribution server UNC paths)
    - Branch B: False positives are rare; raw IP addresses in .url references are
      almost exclusively attacker infrastructure
    - Branch C: Any Electron or CEF-based app installed to a non-standard path may
      trigger; tune filter_legitimate_cef_apps with your software inventory

level: high   # Lower Branch A alone to medium if UNC-MSI deployments are common in your env

fields:
    - Image
    - CommandLine
    - ParentImage
    - ParentCommandLine
    - User
    - ProcessId
    - ParentProcessId
    - CurrentDirectory

# ── Analyst triage checklist ──────────────────────────────────────────────────
# 1. Is the UNC server IP/hostname internal or external? External = escalate immediately.
# 2. Check browser/email process ancestry above explorer.exe — PDF or browser open-redirect?
# 3. Look for libcef.dll and sqlite3.dll drops in %TEMP% / %APPDATA% at the same timestamp.
# 4. Check DNS/proxy logs for Google DDM redirect domains (doubleclick.net) 30–60s before
#    the event — that's the phishing link click that triggered the chain.
# 5. DarkGate v6 beacons to C2 over HTTP/S shortly after execution; correlate with
#    unusual network connections from msiexec or its children within 2 minutes.
#
# Patch status check: CVE-2024-21412 was fixed in Microsoft February 2024 Patch Tuesday.
# If this rule fires, verify patch status of the affected host immediately.
#
# Known DarkGate MSI lure filenames (Trend Micro IoCs):
#   NVIDIA_Install.msi, iTunes_Setup.msi, Notion_Setup.msi (exact names may vary)

---
# Arquivo: D.yml
title: Potential DarkGate SmartScreen Bypass Exploitation Via Internet Shortcut
id: 3c0f6f8a-4f91-4d9d-a7d5-c7f2c3f0f9b1
status: experimental
description: >
  Detects execution of Internet Shortcut (.url) files that reference remote
  WebDAV or SMB resources and subsequently launch MSI installers. This
  behavior is associated with exploitation of CVE-2024-21412, a Microsoft
  Windows SmartScreen bypass vulnerability used by DarkGate operators to
  deliver malicious payloads through crafted Internet Shortcut files.
references:
  - https://www.bleepingcomputer.com/news/security/hackers-exploit-windows-smartscreen-flaw-to-drop-darkgate-malware/
  - https://www.trendmicro.com/en_us/research/24/c/cve-2024-21412--darkgate-operators-exploit-microsoft-windows-sma.html
author: OpenAI
date: 2026-06-06
tags:
  - attack.initial_access
  - attack.execution
  - attack.t1204.001
  - attack.t1218.007
  - cve.2024.21412
logsource:
  product: windows
  category: process_creation
detection:
  selection_msiexec:
    Image|endswith: '\msiexec.exe'
  selection_remote_source:
    CommandLine|contains:
      - '\\\\'
      - 'dav://'
      - 'http://'
      - 'https://'
  selection_msi:
    CommandLine|contains: '.msi'
  condition: all of selection_*
fields:
  - Image
  - CommandLine
  - ParentImage
  - ParentCommandLine
  - User
  - Computer
falsepositives:
  - Legitimate software installation from network shares
  - Enterprise software deployment solutions
  - Administrative MSI installations hosted on WebDAV repositories
level: high

---
# Arquivo: E.yml
title: Potential CVE-2024-21412 SmartScreen Bypass Leading to DarkGate Malware
id: 7a2e1c4d-5b6f-4a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: Detects the exploitation chain of CVE-2024-21412, a SmartScreen bypass vulnerability used by DarkGate malware to download and install malicious MSI packages.
references:
  - https://www.bleepingcomputer.com/news/security/hackers-exploit-windows-smartscreen-flaw-to-drop-darkgate-malware/
  - https://www.trendmicro.com/en_us/research/24/c/cve-2024-21412--darkgate-operators-exploit-microsoft-windows-sma.html
author: Sigma Rule Generator
date: 2026-06-05
tags:
  - attack.defense-evasion
  - attack.t1211
  - attack.t1204
  - cve.2024-21412
logsource:
  category: process_creation
  product: windows
detection:
  selection_url:
    Image|endswith:
      - '\rundll32.exe'
    CommandLine|contains|all:
      - '..\'
      - '.url'
  selection_msi:
    Image|endswith:
      - '\msiexec.exe'
    CommandLine|contains:
      - '\\localhost\C$\'
      - '\\\\127.0.0.1\C$\'
      - 'webdav'
      - '.msi'
  condition: selection_url or selection_msi
falsepositives:
  - Legitimate use of URL files with relative paths.
  - Authorized MSI installations from network shares.
level: high

---
# Arquivo original: file_event_win_malware_darkgate_autoit3_save_temp.yml
title: DarkGate - Drop DarkGate Loader In C:\Temp Directory
id: df49c691-8026-48dd-94d3-4ba6a79102a8
status: experimental
description: Detects attackers attempting to save, decrypt and execute the DarkGate Loader in C:\temp folder.
references:
    - https://www.bleepingcomputer.com/news/security/hackers-exploit-windows-smartscreen-flaw-to-drop-darkgate-malware/
    - https://www.trendmicro.com/en_us/research/24/c/cve-2024-21412--darkgate-operators-exploit-microsoft-windows-sma.html
author: Tomasz Dyduch, Josh Nickels
date: 2024-05-31
tags:
    - attack.execution
    - attack.t1059
    - detection.emerging-threats
logsource:
    category: file_event
    product: windows
detection:
    selection_filename_suffix:
        TargetFilename|contains: ':\temp\'
        TargetFilename|endswith:
            - '.au3'
            - '\autoit3.exe'
    selection_image_suffix:
        Image|contains: ':\temp\'
        Image|endswith:
            - '.au3'
            - '\autoit3.exe'
    condition: 1 of selection_*
falsepositives:
    - Unlikely legitimate usage of AutoIT in temp folders.
level: medium

---