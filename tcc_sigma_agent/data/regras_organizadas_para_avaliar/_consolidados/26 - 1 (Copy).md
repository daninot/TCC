# Arquivo: A.yml
title: RomCom Campaign - Office-Delivered Loader Activity
id: 8f3b2d1a-2023-romcom-0001
status: experimental
description: Detects post-exploitation activity consistent with the RomCom campaign: Office applications spawning script interpreters or downloaders, encoded PowerShell stagers, use of mshta/rundll32/wscript/cscript, DLLs loaded from Temp/AppData, and follow-on outbound connections to internet hosts. Correlate with email/attachment telemetry for phishing indicators.
author: Detection Engineer
date: 2026-06-05
references:
  - https://blogs.blackberry.com/en/2023/07/romcom-targets-ukraine-nato-membership-talks-at-nato-summit
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection_office_spawn_shell:
    EventID: 1
    ParentImage|endswith:
      - "\\WINWORD.EXE"
      - "\\EXCEL.EXE"
      - "\\POWERPNT.EXE"
      - "\\OUTLOOK.EXE"
    Image|in:
      - "*\\cmd.exe"
      - "*\\powershell.exe"
      - "*\\pwsh.exe"
      - "*\\mshta.exe"
      - "*\\rundll32.exe"
      - "*\\wscript.exe"
      - "*\\cscript.exe"
      - "*\\regsvr32.exe"
  selection_encoded_powershell:
    EventID: 1
    Image|endswith:
      - "\\powershell.exe"
      - "\\pwsh.exe"
    CommandLine|contains:
      - "-EncodedCommand"
      - "-enc"
      - "FromBase64String"
      - "Invoke-Expression"
      - "IEX"
  selection_download_tools:
    EventID: 1
    CommandLine|re:
      - '(?i)\b(bitsadmin|certutil|curl|wget|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|bitsadmin\.exe)\b'
  selection_temp_dll_load:
    EventID: 7
    ImageLoaded|contains:
      - "\\AppData\\Local\\Temp\\"
      - "\\AppData\\Roaming\\"
      - "\\Temp\\"
  selection_network_followup:
    EventID: 3
    DestinationPort:
      - 80
      - 443
      - 8080
      - 8443
      - 53
    DestinationIp|not_in_cidr:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
      - "127.0.0.0/8"
  condition: selection_office_spawn_shell and (selection_encoded_powershell or selection_download_tools or selection_temp_dll_load or selection_network_followup)
fields:
  - timestamp
  - EventID
  - ComputerName
  - SubjectUserName
  - Image
  - ParentImage
  - CommandLine
  - ImageLoaded
  - DestinationIp
  - DestinationPort
  - ProcessId
falsepositives:
  - Legitimate macros or automation that invoke scripts from Office documents (whitelist known business processes)
  - IT troubleshooting or software distribution activities that use certutil, bitsadmin, or PowerShell from Office-hosted automation
level: high
tags:
  - attack.initial_access
  - attack.execution
  - attack.command_and_control
  - malware.romcom
  - detection.windows.sysmon
notes: |
  - Tune by whitelisting known automation/service accounts and trusted document-processing workflows.
  - Investigate matched events by collecting the originating document, email metadata, full command lines, parent/child process trees, dropped files under Temp/AppData, and related network traffic.
  - Correlate with mailbox and gateway telemetry for spearphishing indicators (subjects or attachments referencing Ukraine, NATO, summit, membership) to raise confidence.


---
# Arquivo: B.yml
title: Potential RomCom RAT Exploitation Share Access Pattern (CVE-2023-36884)
id: 3df95076-9e78-4e63-accb-16699c3b74f8
status: test
description: Detects network file share connections matching a specific folder nomenclature utilized by RomCom RAT operators during campaigns targeting the NATO summit. This activity occurs when an endpoint opens a weaponized Microsoft Office document that exploits CVE-2023-36884 to query external shares for remote payloads.
references:
    - https://blogs.blackberry.com/en/2023/07/romcom-targets-ukraine-nato-membership-talks-at-nato-summit
author: Security Operations Center
date: 2023/07/13
modified: 2026/06/05
tags:
    - attack.initial_access
    - attack.execution
    - attack.t1566.001 # Phishing: Malicious Attachment
    - attack.t1203     # Exploitation for Client Execution
    - cve.2023.36884
logsource:
    product: windows
    service: security
definition: 'Requires Windows Security Advanced Auditing policy "Object Access > Audit File Share" enabled for Success/Failure.'
detection:
    selection_eid:
        EventID: 5140 # Network Share Object Access
    selection_indicators:
        - ShareName|contains: '\MSHTML_C7\'
        - ShareLocalPath|contains: '\MSHTML_C7\'
    condition: selection_eid and selection_indicators
falsepositives:
    - Intentional red team exercises, internal vulnerability scanning simulation routines, or sandboxed malware analysis tools mimicking the RomCom campaign indicators.
level: critical

---
# Arquivo: C.yml
title: RomCom NATO Summit Lure HTTP Path Pattern
id: 8f7b6e2c-7fd5-4e28-8c0f-8f5f7d1c2a11
status: experimental
description: Detects HTTP requests to the MSHTML_C7 lure and stage paths observed in the RomCom campaign targeting Ukraine and NATO summit attendees.
references:
  - https://blogs.blackberry.com/en/2023/07/romcom-targets-ukraine-nato-membership-talks-at-nato-summit
author: OpenAI
date: 2026-06-05
tags:
  - attack.initial_access
  - attack.execution
  - attack.t1566
  - attack.t1204
logsource:
  category: webserver
detection:
  selection_path:
    url|contains:
      - '/MSHTML_C7/zip_k.asp'
      - '/MSHTML_C7/zip_k2.asp'
      - '/MSHTML_C7/zip_k3.asp'
      - '/MSHTML_C7/start.xml'
      - '/MSHTML_C7/RFile.asp'
      - '/MSHTML_C7/file001.url'
      - '/MSHTML_C7/search-ms'
      - '/MSHTML_C7/redir_obj.html'
  selection_path_alt:
    cs_uri_path|contains:
      - '/MSHTML_C7/zip_k.asp'
      - '/MSHTML_C7/zip_k2.asp'
      - '/MSHTML_C7/zip_k3.asp'
      - '/MSHTML_C7/start.xml'
      - '/MSHTML_C7/RFile.asp'
      - '/MSHTML_C7/file001.url'
      - '/MSHTML_C7/search-ms'
      - '/MSHTML_C7/redir_obj.html'
  selection_host:
    url|contains:
      - '74.50.94.156'
      - '104.234.239.26'
      - 'ukrainianworldcongress.info'
  condition: 1 of selection_path* and 1 of selection_host
fields:
  - src_ip
  - method
  - url
  - cs_host
  - cs_uri_path
  - cs_uri_query
  - user_agent
falsepositives:
  - Security research and sandbox analysis
  - Threat intelligence collection
  - Controlled testing of known samples
level: high

---
# Arquivo: D.yml
title: RomCom RAT Svchost Service Creation with Hardcoded CLSID
id: b83c2f17-d041-4ea8-bc93-5a71e6f04d38
status: experimental
description: |
    Detects the RomCom downloader registering a rogue Windows service that launches
    svchost.exe with the "-k DcomLaunch" parameter and installs a payload DLL under
    a CLSID key masquerading as a legitimate COM server. This behaviour was observed
    in the July 2023 RomCom campaign that used NATO Summit-themed lure documents to
    target Ukraine supporters. The downloader (disguised as Calc.exe) creates a service
    named "OneDriveSrv" whose ImagePath is "C:\Windows\System32\svchost.exe -k DcomLaunch"
    and registers the payload DLL as an in-process COM server under the hardcoded CLSID
    {2781761E-28E0-4109-99FE-B9D127C57AFE}.
references:
    - https://blogs.blackberry.com/en/2023/07/romcom-targets-ukraine-nato-membership-talks-at-nato-summit
author: Generated from BlackBerry Threat Research blog (RomCom NATO Summit campaign)
date: 2023-07-04
modified: 2023-07-10
tags:
    - attack.persistence
    - attack.t1543.003   # Create or Modify System Process: Windows Service
    - attack.defense_evasion
    - attack.t1218.011   # System Binary Proxy Execution: Rundll32 (svchost abuse)
    - attack.t1036.004   # Masquerading: Masquerade Task or Service
    - tlp:white
logsource:
    category: registry_set
    product: windows
detection:
    # Arm 1 – rogue COM InProcServer32 registration under the hardcoded CLSID
    selection_clsid_inproc:
        EventType: SetValue
        TargetObject|contains:
            - '\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\InProcServer32'

    # Arm 2 – service ImagePath pointing to svchost -k DcomLaunch written outside
    #          HKLM\SYSTEM\CurrentControlSet\Services\DcomLaunch (the legitimate key)
    #          and whose service name contains "OneDriveSrv"
    selection_service_imagepath:
        EventType: SetValue
        TargetObject|contains:
            - '\Services\OneDriveSrv\'
        Details|contains:
            - 'svchost.exe -k DcomLaunch'

    condition: selection_clsid_inproc or selection_service_imagepath
falsepositives:
    - Legitimate software registering a COM server under this exact CLSID is
      extraordinarily unlikely; the CLSID is hardcoded in the RomCom sample.
    - A service legitimately named "OneDriveSrv" hosting svchost under DcomLaunch
      does not exist in stock Windows or any known benign software package.
level: critical

---
# Arquivo: E.yml
title: Potential CVE-2023-36884 Exploitation Pattern
id: 0066d244-c277-4c3e-88ec-9e7b777cc8bc
status: test
description: Detects a unique pattern seen being used by RomCom while potentially exploiting CVE-2023-36884.
references:
  - https://blogs.blackberry.com/en/2023/07/romcom-targets-ukraine-nato-membership-talks-at-nato-summit
author: X__Junior (Original)
date: 2023-07-12
tags:
  - attack.command-and-control
  - cve.2023-36884
  - detection.emerging-threats
logsource:
  category: proxy
detection:
  selection:
    cs-method: 'GET'
    c-uri|contains: '/MSHTML_C7/'
    c-uri|re: '\?d=[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
  condition: selection
falsepositives:
  - Unknown
level: critical

---
# Arquivo original: win_security_exploit_cve_2023_36884_office_windows_html_rce_share_access_pattern.yml
title: Potential CVE-2023-36884 Exploitation - Share Access
id: 3df95076-9e78-4e63-accb-16699c3b74f8
status: test
description: Detects access to a file share with a naming schema seen being used during exploitation of CVE-2023-36884
references:
    - https://blogs.blackberry.com/en/2023/07/romcom-targets-ukraine-nato-membership-talks-at-nato-summit
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-07-13
tags:
    - attack.command-and-control
    - cve.2023-36884
    - detection.emerging-threats
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit File Share" must be configured for Success/Failure'
detection:
    selection_eid:
        EventID: 5140
    selection_share_name:
        ShareName|contains: '\MSHTML_C7\'
        ShareName|re: '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
    selection_share_path:
        ShareLocalPath|contains: '\MSHTML_C7\'
        ShareLocalPath|re: '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
    condition: selection_eid and 1 of selection_share_*
falsepositives:
    - Unknown
level: high

---