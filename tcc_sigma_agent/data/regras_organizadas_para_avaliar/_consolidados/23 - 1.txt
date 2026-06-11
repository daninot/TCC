# Arquivo: A.yml
title: Suspicious Child Process from Windows App Package
id: 9f2a1c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d
status: experimental
description: Detects when an application launched from the WindowsApps directory spawns a suspicious child process, which may indicate a malicious AppX package attempting to execute arbitrary commands for malware deployment or persistence, as seen in BazarLoader campaigns.
references:
  - https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/
  - https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting
  - https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/
author: Senior Threat Detection Engineer
date: 2026-06-04
tags:
  - attack.defense-evasion
  - attack.execution
  - attack.t1059
  - attack.t1218
  - attack.t1047
logsource:
  product: windows
  category: process_creation
detection:
  selection_parent:
    ParentImage|contains: 'C:\Program Files\WindowsApps\'
  selection_susp_child:
    Image|endswith:
      - '\cmd.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\powershell.exe'
      - '\powershell_ise.exe'
      - '\pwsh.exe'
      - '\regsvr32.exe'
      - '\rundll32.exe'
      - '\wscript.exe'
  condition: selection_parent and selection_susp_child
falsepositives:
  - Legitimate Windows App packages that require external binaries (e.g., Windows Terminal, Sysinternals Suite). Administrative tools or developer environments may also trigger this rule.
level: medium

---
# Arquivo: B.yml
title: Potentially Suspicious Windows App Activity
id: f91ed517-a6ba-471d-9910-b3b4a398c0f3
status: test
description: Detects potentially suspicious child process activity spawned from applications launched inside the WindowsApps directory. This can indicate a rogue APPX/MSIX package execution chain used to deploy malware.
references:
  - https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/
  - https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting
  - https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/
author: OpenAI
date: 2026-06-04
tags:
  - attack.execution
  - attack.t1204
logsource:
  product: windows
  category: process_creation
detection:
  selection_parent:
    ParentImage|contains: 'C:\Program Files\WindowsApps\'
  selection_susp_img:
    Image|endswith:
      - '\cmd.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\powershell.exe'
      - '\powershell_ise.exe'
      - '\pwsh.exe'
      - '\regsvr32.exe'
      - '\rundll32.exe'
      - '\wscript.exe'
  selection_susp_cli:
    CommandLine|contains:
      - 'cmd /c'
      - 'Invoke-'
      - 'Base64'
  filter_optional_terminal:
    ParentImage|contains: ':\Program Files\WindowsApps\Microsoft.WindowsTerminal'
    ParentImage|endswith: '\WindowsTerminal.exe'
    Image|endswith:
      - '\powershell.exe'
      - '\cmd.exe'
      - '\pwsh.exe'
  filter_optional_sysinternals:
    ParentImage|startswith: 'C:\Program Files\WindowsApps\Microsoft.SysinternalsSuite'
    Image|endswith: '\cmd.exe'
  condition: selection_parent and 1 of selection_susp_* and not 1 of filter_optional_*
fields:
  - ParentImage
  - Image
  - CommandLine
  - User
  - Computer
falsepositives:
  - Legitimate packages that intentionally launch external binaries
  - Windows Terminal integrations
  - Authorized enterprise software using packaged app launchers
level: medium

---
# Arquivo: C.yml
title: Suspicious AppX / AppInstaller Activity Indicative of Malicious App Deployment
id: 5d3a9f2e-2026-06-04-0001
status: experimental
description: Detects suspicious AppX/AppInstaller activity and AppX package deployment patterns abused by malware (e.g., BazarLoader) to deliver payloads via Windows app packaging and installer mechanisms. Matches PowerShell AppX cmdlets, AppInstaller protocol usage, AppxPackagingTool/AppInstaller binaries, and execution from AppX package directories combined with unusual parent processes or rapid repeated installs.
author: Security Analyst
date: 2026-06-04
references:
  - https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/
  - https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting
  - https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection_powershell_appx:
    CommandLine|contains:
      - "Add-AppxPackage"
      - "Add-AppxProvisionedPackage"
      - "Remove-AppxPackage"
      - "Register-AppxPackage"
      - "Get-AppxPackage"
  selection_appinstaller_protocol:
    CommandLine|contains:
      - "ms-appinstaller:"
      - "ms-appinstaller:?source="
  selection_appinstaller_binaries:
    Image|endswith:
      - "\\AppInstaller.exe"
      - "\\AppxPackagingTool.exe"
      - "\\AppxDeploymentServer.exe"
      - "\\AppxInstaller.exe"
  selection_exec_from_appx_dir:
    Image|contains:
      - "\\WindowsApps\\"
      - "\\Packages\\"
      - "\\LocalState\\"
  selection_suspicious_parents:
    ParentImage|contains:
      - "\\powershell.exe"
      - "\\cmd.exe"
      - "\\wscript.exe"
      - "\\cscript.exe"
      - "\\rundll32.exe"
  selection_encoded_command:
    CommandLine|contains:
      - "-EncodedCommand"
      - "-enc"
      - "FromBase64String"
  selection_rapid_installs:
    CountByHost: ">2"
    Timeframe: "10m"
  condition: (selection_powershell_appx or selection_appinstaller_protocol or selection_appinstaller_binaries or selection_exec_from_appx_dir) and (selection_suspicious_parents or selection_encoded_command or selection_rapid_installs)
fields:
  - timestamp
  - EventID
  - ComputerName
  - SubjectUserName
  - Image
  - ParentImage
  - CommandLine
  - ProcessId
  - CountByHost
falsepositives:
  - Legitimate Microsoft Store installs or enterprise AppX deployments and updates
  - IT automation or software distribution systems using AppX packaging (whitelist known management accounts and servers)
level: high
tags:
  - attack.execution
  - attack.persistence
  - malware.bazarloader
  - detection.windows.sysmon
  - technique.T1218.011


---
# Arquivo: D.yml
title: Remote MSIX/Appx Package Installation Via AppInstaller
id: 9b8f0412-1f48-4e8c-85f2-9bc50f612015
status: experimental
description: Detects the execution of the Windows App Installer utility (AppInstaller.exe or DesktopAppInstaller.exe) processing a remote URL or utilizing the 'ms-appinstaller' protocol handler. Threat actors (such as BazarLoader and Emotet) abuse this mechanism to distribute malicious AppX or MSIX packages via phishing links, allowing them to bypass browser security warnings and deploy malware.
references:
    - https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/
    - https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting
    - https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/
author: Security Operations Center
date: 2026/06/04
tags:
    - attack.initial_access
    - attack.execution
    - attack.t1566.002 # Phishing: Malicious Link
    - attack.t1204.002 # User Execution: Malicious File
logsource:
    product: windows
    category: process_creation
detection:
    selection_image:
        Image|endswith:
            - '\AppInstaller.exe'
            - '\DesktopAppInstaller.exe'
    selection_indicators:
        CommandLine|contains:
            - 'http://'
            - 'https://'
            - 'ms-appinstaller'
            - 'source='
    condition: selection_image and selection_indicators
falsepositives:
    - Enterprise deployment of internal line-of-business applications hosted on corporate web servers or deep-linked cloud repositories (e.g., Azure Blob storage).
level: high

---
# Arquivo: E.yml
title: Windows - Malicious APPX/MSIX Package Deployment via AppInstaller Abuse (BazarLoader/Emotet)
id: 8d4c7f21-3e95-4b57-a093-6b8e2d5c9f47
status: test
description: |
    Detects abuse of the Windows AppInstaller (AppInstaller.exe) process as a
    malware delivery vehicle via APPX/MSIX packages, covering techniques documented
    by SentinelOne Labs (July 2022) and Sophos (November 2021) for multiple malware
    families including BazarBackdoor, Emotet, Magniber ransomware, and ElectronBot.

    The attack exploits the Windows ms-appinstaller: URI protocol handler.
    When a user clicks a phishing link that redirects to ms-appinstaller:?source=URL,
    the browser (Edge, Chrome, Firefox) spawns AppInstaller.exe to process the request.
    AppInstaller.exe then downloads and installs the APPX package from the attacker's
    URL, bypassing Mark-of-the-Web controls. Malicious packages typically declare the
    "runFullTrust" capability, bypassing the UWP application sandbox.

    Three detection tiers:
      1. selection_browser_parent (HIGH) — browser spawns AppInstaller.exe via
         ms-appinstaller: URI. Legitimate AppInstaller launches come from Explorer,
         winget, or direct double-click — never from a browser process.
      2. selection_office_parent (HIGH) — Office application spawns AppInstaller.exe.
         Malicious documents can invoke the ms-appinstaller: handler directly.
      3. selection_appinstaller_child (HIGH) — AppInstaller.exe spawns a command
         interpreter or shell. Indicates post-install malicious payload execution.

    Note: Microsoft temporarily disabled the ms-appinstaller handler after CVE-2021-43890
    and again in late 2022, but the direct APPX sideloading vector via AppInstaller.exe
    remains abusable when AppInstaller is invoked directly.
references:
    - https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/
    - https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting
    - https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-43890
    - https://attack.mitre.org/techniques/T1566/002/
    - https://attack.mitre.org/techniques/T1218/
author: Security Team
date: 2026-05-25
tags:
    - attack.initial_access
    - attack.t1566.002  # Phishing: Spearphishing Link (malicious ms-appinstaller: URL)
    - attack.execution
    - attack.t1204.002  # User Execution: Malicious File (APPX package)
    - attack.defense_evasion
    - attack.t1218      # System Binary Proxy Execution (AppInstaller as LOLBin)
logsource:
    category: process_creation
    product: windows
detection:
    selection_browser_parent:
        # Browser spawning AppInstaller.exe — primary ms-appinstaller: URI abuse vector
        # (BazarLoader and Emotet technique per Sophos and SentinelOne)
        ParentImage|endswith:
            - '\msedge.exe'
            - '\chrome.exe'
            - '\firefox.exe'
            - '\iexplore.exe'
            - '\opera.exe'
            - '\brave.exe'
        Image|endswith: '\AppInstaller.exe'
    selection_office_parent:
        # Office application spawning AppInstaller.exe — malicious document variant
        ParentImage|endswith:
            - '\winword.exe'
            - '\excel.exe'
            - '\powerpnt.exe'
            - '\outlook.exe'
            - '\mshta.exe'
        Image|endswith: '\AppInstaller.exe'
    selection_appinstaller_child:
        # AppInstaller.exe spawning interpreters — post-install malicious code execution
        # Legitimate AppInstaller does not spawn command shells or script engines
        ParentImage|end

---
# Arquivo original: win_appxdeployment_server_appx_downloaded_from_file_sharing_domains.yml
title: Remote AppX Package Downloaded from File Sharing or CDN Domain
id: 8b48ad89-10d8-4382-a546-50588c410f0d
status: test
description: |
    Detects an appx package that was added to the pipeline of the "to be processed" packages which was downloaded from a file sharing or CDN domain.
references:
    - https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/
    - https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting
    - https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-11
modified: 2025-12-10
tags:
    - attack.stealth
logsource:
    product: windows
    service: appxdeployment-server
detection:
    selection:
        EventID: 854
        Path|contains:
            - '.githubusercontent.com'       # Includes both gists and github repositories / Michael Haag (idea)
            - 'anonfiles.com'
            - 'cdn.discordapp.com'
            - 'ddns.net'
            - 'dl.dropboxusercontent.com'
            - 'ghostbin.co'
            - 'github.com'
            - 'glitch.me'
            - 'gofile.io'
            - 'hastebin.com'
            - 'mediafire.com'
            - 'mega.nz'
            - 'onrender.com'
            - 'pages.dev'
            - 'paste.ee'
            - 'pastebin.com'
            - 'pastebin.pl'
            - 'pastetext.net'
            - 'privatlab.com'
            - 'privatlab.net'
            - 'send.exploit.in'
            - 'sendspace.com'
            - 'storage.googleapis.com'
            - 'storjshare.io'
            - 'supabase.co'
            - 'temp.sh'
            - 'transfer.sh'
            - 'trycloudflare.com'
            - 'ufile.io'
            - 'w3spaces.com'
            - 'workers.dev'
    condition: selection
falsepositives:
    - Unlikely, unless the organization uses file sharing or CDN services to distribute internal applications.
level: high

---