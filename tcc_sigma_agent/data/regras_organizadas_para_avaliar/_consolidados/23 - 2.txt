# Arquivo: A.yml
title: AppX Package Queued for Installation from Suspicious File Sharing Domain
id: b4d1f9e3-2c7a-4b8f-a6e4-9c3d5b1f7a28
status: experimental
description: >
  Detects an AppX or MSIX package queued for installation on Windows where
  the package source path contains a domain associated with file sharing,
  paste, or CDN services commonly abused for malware staging. Adversaries
  — including BazarLoader and Emotet operators — abuse the Windows App
  Installer (ms-appinstaller URI scheme) to deliver malicious APPX packages
  from attacker-controlled files hosted on legitimate CDN and file sharing
  infrastructure. This technique bypasses Mark-of-the-Web controls because
  the App Installer process downloads and installs the package directly,
  and it exploits user trust in recognisable brand domains such as Discord
  and GitHub. EventID 821 in the Microsoft-Windows-AppXDeploymentServer
  Operational log records the source URI of every package queued for
  installation, making it the authoritative telemetry source for detecting
  this delivery vector. The domain list covers the platforms most frequently
  observed in malware campaigns: GitHub raw content, Discord CDN, Dropbox,
  Mega, Pastebin, and general-purpose file transfer services.
references:
  - https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/
  - https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting
  - https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/
author: Senior Threat Detection Engineer
date: 2026-05-25
tags:
  - attack.initial_access
  - attack.defense_evasion
  - attack.t1566.002
  - attack.t1218
logsource:
  product: windows
  service: appxdeployment-server
detection:
  selection:
    EventID: 821
    Path|contains:
      - 'raw.githubusercontent.com'
      - 'cdn.discordapp.com'
      - 'media.discordapp.net'
      - 'dropbox.com/s/'
      - 'mega.nz'
      - 'pastebin.com'
      - 'transfer.sh'
      - 'wetransfer.com'
      - 'mediafire.com'
      - 'anonfiles.com'
      - 'gofile.io'
      - 'onedrive.live.com'
      - '4shared.com'
      - 'storjshare.io'
  condition: selection
falsepositives:
  - Developers or IT administrators who intentionally sideload APPX or
    MSIX packages hosted on GitHub raw content or a personal file sharing
    account as part of an approved internal distribution workflow where
    the Microsoft Store or an enterprise package repository is not used.
  - Automated software deployment pipelines that fetch APPX packages from
    cloud storage during a CI/CD release process and install them via the
    App Installer, where the CDN URL for the artefact happens to match
    one of the listed domains.
level: high

---
# Arquivo: B.yml
title: Remote AppX Package Downloaded from File Sharing or CDN Domain
id: 8b48ad89-10d8-4382-a546-50588c410f0d
status: test
description: Detects an AppX package added to the AppXDeployment-Server processing pipeline that was downloaded from a file sharing, paste, or CDN domain commonly abused for malware staging.
references:

* [https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/](https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/)
* [https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting](https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting)
* [https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/](https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/)
  author: OpenAI
  date: 2026-06-04
  tags:
* attack.stealth
  logsource:
  product: windows
  service: appxdeployment-server
  detection:
  selection:
  EventID: 854
  Path|contains:

  * '.githubusercontent.com'
  * 'anonfiles.com'
  * 'cdn.discordapp.com'
  * 'ddns.net'
  * 'dl.dropboxusercontent.com'
  * 'dropbox.com'
  * 'ghostbin.co'
  * 'github.com'
  * 'gist.github.com'
  * 'glitch.me'
  * 'gofile.io'
  * 'hastebin.com'
  * 'mega.nz'
  * 'mediafire.com'
  * 'onedrive.live.com'
  * 'paste.ee'
  * 'pastebin.com'
  * 'pastebin.pl'
  * 'pastetext.net'
  * 'privatlab.com'
  * 'privatlab.net'
  * 'send.exploit.in'
  * 'sendspace.com'
  * 'storage.googleapis.com'
  * 'storjshare.io'
  * 'supabase.co'
  * 'temp.sh'
  * 'transfer.sh'
  * 'trycloudflare.com'
  * 'ufile.io'
  * 'w3spaces.com'
  * 'workers.dev'
    condition: selection
    falsepositives:
* Unlikely, unless the organization intentionally distributes AppX packages through public file sharing or CDN services.
  level: high


---
# Arquivo: C.yml
title: AppX Package Downloaded From File Sharing or CDN Domain
id: c3f9a7d2-4b6e-4a1f-9c2d-7e5b8a0c1d2f
status: experimental
description: Detects AppX packages queued for installation where the package source URI or file path contains domains commonly used for file sharing, paste services, or CDNs (e.g., GitHub, Discord CDN, Dropbox, Mega, Pastebin). This behavior is used by malware campaigns to deliver malicious AppX packages via trusted delivery mechanisms. Requires AppX deployment server logging to be enabled and forwarded to the SIEM.
author: Senior Threat Detection Engineer
date: 2026/06/05
references:
  - [https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/](https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/)
  - [https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting](https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting)
  - [https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/](https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/)
tags:
  - attack.initial_access
  - attack.delivery
  - malware
logsource:
  product: windows
  service: appxdeployment-server
  category: application
  description: AppX Deployment Server operational logs must be enabled and collected (AppXDeployment-Server/Operational).
detection:
  selection:
    EventID: 307
    SourceUri|contains:
      - 'github.com'
      - 'raw.githubusercontent.com'
      - 'gist.githubusercontent.com'
      - 'cdn.jsdelivr.net'
      - 'cdnjs.cloudflare.com'
      - 'cdn.discordapp.com'
      - 'media.discordapp.net'
      - 'dropbox.com'
      - 'dl.dropboxusercontent.com'
      - 'mega.nz'
      - 'pastebin.com'
      - 'hastebin.com'
      - 'transfer.sh'
      - 'anonfiles.com'
      - 'file.io'
      - 'bit.ly'
      - 'tinyurl.com'
      - 's3.amazonaws.com'
      - 'cloudfront.net'
    FilePath|contains:
      - 'github.com'
      - 'raw.githubusercontent.com'
      - 'cdn.jsdelivr.net'
      - 'cdn.discordapp.com'
      - 'dropbox.com'
      - 'mega.nz'
      - 'pastebin.com'
  keywords:
    Signature|contains:
      - 'Symantec Pending Analysis'
      - 'Symantec: Pending Analysis'
      - 'PSP Pending Analysis'
      - 'Symantec PSP Pending'
  condition: selection and not keywords
falsepositives:
  - Legitimate enterprise deployments or internal automation that stage AppX packages from GitHub, CDN, or file-sharing services.
  - Software distribution workflows that temporarily host packages on public CDNs or file-sharing services.
level: high

---
# Arquivo: D.yml
title: AppX Package Installation From File Sharing or CDN Domain
id: 8f2d5a10-23b4-4b5f-a492-c11f7c5e2195
status: stable
description: Detects an AppX package queued for installation that was downloaded directly from a file sharing, paste, or CDN domain. This technique is commonly abused by malware campaigns (such as BazarLoader) to deliver malicious Windows applications via trusted app installers.
references:

* [https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/](https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/)
* [https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting](https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting)
* [https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/](https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/)
author: Senior Threat Detection Engineer
date: 2026/06/04
tags:
* attack.defense_evasion
* attack.execution
* attack.t1218
logsource:
product: windows
service: appxdeployment-server
detection:
selection:
EventID: 10
Path|contains:
* 'raw.githubusercontent.com'
* 'cdn.discordapp.com'
* 'mediafire.com'
* 'mega.nz'
* 'dropbox.com'
* 'pastebin.com'
* 'drive.google.com'
condition: selection
falsepositives:


* Legitimate enterprise or developer AppX/MSIX packages hosted on public code repositories or corporate cloud storage.
level: high

---
# Arquivo: E.yml
title: Malicious AppX Package Downloaded from File Sharing or CDN Domain
id: d1e2f3a4-b5c6-47d8-9e0f-1a2b3c4d5e6f
status: experimental
description: Detects an AppX package queued for installation downloaded from a file sharing, paste, or CDN domain, as abused by malware campaigns like BazarLoader to deliver malicious Windows apps.
references:
    - https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/
    - https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting
    - https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/
author: Senior Threat Detection Engineer
date: 2026-06-04
logsource:
    product: windows
    service: appxdeployment-server
detection:
    selection_eventid:
        EventID: 7008  # AppX package queued for installation
    selection_domain:
        Path|contains:
            - 'github.com'
            - 'githubusercontent.com'
            - 'discord.com'
            - 'discordapp.com'
            - 'cdn.discordapp.com'
            - 'dropbox.com'
            - 'dropboxusercontent.com'
            - 'mega.nz'
            - 'pastebin.com'
            - 'paste.ee'
            - 'bitbucket.org'
            - 'gitlab.com'
            - 'cloudfront.net'
            - 'azureedge.net'
            - 'storage.googleapis.com'
            - 'transfer.sh'
            - 'sendspace.com'
            - 'mediafire.com'
    condition: selection_eventid and selection_domain
falsepositives:
    - Legitimate AppX packages downloaded from these domains for testing or development
level: high
tags:
    - attack.defense_evasion
    - attack.t1218
    - attack.t1105
    - attack.execution

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