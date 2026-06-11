# Arquivo: A.yml
title: Potential PrintNightmare Malicious Printer Driver DLL Creation
id: 6fe1719e-ecdf-4caf-bffe-4f501cb0a561
status: stable
description: >
  Detects creation of DLL files within the Windows Print Spooler driver
  directory, a behavior associated with exploitation of PrintNightmare
  vulnerabilities CVE-2021-1675 and CVE-2021-34527 via malicious printer
  driver installation.
references:
  - https://twitter.com/mvelazco/status/1410291741241102338
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527
author: OpenAI
date: 2026-06-04
tags:
  - attack.execution
  - attack.privilege_escalation
  - attack.t1574.001
  - cve.2021.1675
  - cve.2021.34527
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|startswith: 'C:\Windows\System32\spool\drivers\x64\'
    TargetFilename|endswith: '.dll'
  filter_legitimate:
    Image:
      - 'C:\Windows\System32\spoolsv.exe'
  condition: selection and not filter_legitimate
fields:
  - TargetFilename
  - Image
  - User
  - Computer
falsepositives:
  - Legitimate printer driver installation
  - Printer server maintenance activities
  - Authorized driver updates
level: high

---
# Arquivo: B.yml
title: Antivirus PrinterNightmare CVE-2021-34527 Exploit Detection
id: 6fe1719e-ecdf-4caf-bffe-4f501cb0a561
status: stable
description: Detects the suspicious file that is created from PoC code against Windows Print Spooler Remote Code Execution Vulnerability CVE-2021-34527 (PrinterNightmare), CVE-2021-1675 .
references:
    - https://twitter.com/mvelazco/status/1410291741241102338
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527
author: Sittikorn S, Nuttakorn T, Tim Shelton
date: 2021-07-01
modified: 2023-10-23
tags:
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1055
    - detection.emerging-threats
    - cve.2021-34527
    - cve.2021-1675
logsource:
    category: antivirus
detection:
    selection:
        Filename|contains: ':\Windows\System32\spool\drivers\x64\'
    keywords:
        - 'File submitted to Symantec' # symantec fp, pending analysis, more generic
    condition: selection and not keywords
falsepositives:
    - Unlikely, or pending PSP analysis
level: critical

---
# Arquivo: C.yml
title: Windows Print Spooler - Suspicious Child Process Spawned by spoolsv.exe (PrintNightmare)
id: f2d8a51e-7c93-4b46-a081-3e6d94b27f58
status: test
description: |
    Detects a suspicious child process spawned by spoolsv.exe (Windows Print Spooler),
    the process-level Indicator of Compromise identified by Mauricio Velazco (Splunk
    Threat Research) in "I Pity the Spool: Detecting PrintNightmare CVE-2021-34527"
    (published July 1, 2021, day of CVE-2021-34527 assignment by Microsoft).

    PrintNightmare exploits two distinct but related vulnerabilities in spoolsv.exe:
      CVE-2021-1675: Local privilege escalation — attacker uses AddPrinterDriverEx
        locally to install a malicious DLL and escalate to SYSTEM. Requires prior
        local authenticated access; patched June 2021 but not fully remediated.
      CVE-2021-34527: Remote Code Execution — attacker uses RpcAddPrinterDriverEx
        (MS-RPRN) from any authenticated host on the network to install the DLL
        remotely. CVSS 8.8. Emergency patch released July 6-7, 2021.

    Both CVEs result in the same host-level artifact: spoolsv.exe loading a malicious
    DLL from C:\Windows\System32\spool\drivers\ and spawning a child process as SYSTEM.
    Velazco's primary detection focuses on spoolsv.exe → rundll32.exe (the DLL loader
    spawned to execute the attacker's payload), but any unexpected child process from
    spoolsv.exe is suspicious: the print spooler service does not normally spawn
    interactive processes or command interpreters.

    Complementary detection layer to RPC Firewall rule (MS-RPRN opnum 89 / MS-PAR):
      RPC Firewall rule fires BEFORE code execution (catches the API call).
      This rule fires AFTER code execution begins (catches the process spawn).
    Requires Sysmon with process creation events (EventID 1) or Windows Security
    EventID 4688 with command-line auditing enabled.
references:
    - https://twitter.com/mvelazco/status/1410291741241102338
    - https://www.splunk.com/en_us/blog/security/i-pity-the-spool-detecting-printnightmare-cve-2021-34527.html
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527
    - https://attack.mitre.org/techniques/T1210/
    - https://attack.mitre.org/techniques/T1574/001/
author: Security Team
date: 2026-05-25
tags:
    - attack.execution
    - attack.privilege_escalation
    - attack.t1068      # Exploitation for Privilege Escalation (CVE-2021-1675 local)
    - attack.t1210      # Exploitation of Remote Services (CVE-2021-34527 remote)
    - attack.t1574.001  # Hijack Execution Flow: DLL Search Order Hijacking
    - cve.2021-1675
    - cve.2021-34527
logsource:
    category: process_creation
    product: windows
detection:
    selection_spoolsv_parent:
        # Any child process of spoolsv.exe — the print spooler should never
        # spawn interactive shells, loaders, or arbitrary executables
        ParentImage|endswith: '\spoolsv.exe'
    selection_rundll32:
        # Velazco/Splunk primary detection: spoolsv.exe → rundll32.exe
        # rundll32.exe is used to load and execute the attacker's malicious DLL
        ParentImage|endswith: '\spoolsv.exe'
        Image|endswith: '\rundll32.exe'
    filter_legitimate_children:
        # Known legitimate child processes of spoolsv.exe
        Image|endswith:
            - '\splwow64.exe'         # 64-bit print driver host (WOW64 redirection)
            - '\PrintIsolationHost.exe' # print isolation for 3rd-party drivers
    filter_system_path:
        # Suppress rundll32.exe invocations loading signed Windows print components
        # from the official Windows system directory (not attacker staging areas)
        Image|endswith: '\rundll32.exe'
        CommandLine|contains:
            - 'printui.dll'           # legitimate: Windows Printer UI library
            - 'ntprint.dll'           # legitimate: print subsystem component
    condition: (1 of selection_*) and not 1 of filter_*
fields:
    - Image
    - CommandLine
    - ParentImage
    - ParentCommandLine
    - User
    - IntegrityLevel
    - ProcessId
    - ParentProcessId
falsepositives:
    - Third-party print driver installers that use rundll32.exe for driver setup
    - Legacy print management software spawning sub-processes from spoolsv
    - Authorized printer driver testing in isolated lab environments
level: high

---
# Arquivo: D.yml
title: Suspicious Print Spooler Activity Indicative of PrintNightmare Exploitation
id: 8d2f4b1e-2026-0001-0000-0000000000a1
status: experimental
description: Detects suspicious activity related to Print Spooler exploitation (CVE-2021-1675 / CVE-2021-34527) such as spoolsv.exe spawning interactive shells or script interpreters, unexpected driver/print-related file drops to spool directories, and service installations pointing to print driver binaries. Correlate with network, authentication, and other host telemetry for triage.
author: Security Analyst
date: 2026-06-04
references:
  - https://twitter.com/mvelazco/status/1410291741241102338
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection_spoolsv_child_process:
    EventID: 1
    ParentImage|endswith:
      - "\\spoolsv.exe"
    Image|matches:
      - "*\\cmd.exe"
      - "*\\powershell.exe"
      - "*\\pwsh.exe"
      - "*\\cscript.exe"
      - "*\\wscript.exe"
      - "*\\rundll32.exe"
      - "*\\mshta.exe"
  selection_spool_driver_file_create:
    EventID: 11
    TargetFilename|contains:
      - "\\Windows\\System32\\spool\\drivers\\"
      - "\\Windows\\System32\\spool\\PRINTERS\\"
      - "\\Windows\\System32\\spool\\drivers\\x64\\"
  selection_service_install_print:
    EventID: 7045
    TargetImage|contains:
      - "spool"
      - "print"
    TargetImage|not_contains:
      - "\\system32\\spoolsv.exe"
  selection_registry_driver_install:
    EventID: 13
    TargetObject|contains:
      - "\\SYSTEM\\CurrentControlSet\\Control\\Print\\Environments"
  condition: selection_spoolsv_child_process or selection_spool_driver_file_create or selection_service_install_print or selection_registry_driver_install
fields:
  - timestamp
  - EventID
  - ComputerName
  - SubjectUserName
  - Image
  - ParentImage
  - CommandLine
  - TargetFilename
  - TargetImage
  - TargetObject
falsepositives:
  - Legitimate administrative print driver installations or troubleshooting where admins intentionally install drivers or run debugging shells from spooler context.
  - Managed print services or vendor tools that interact with spool directories or install print drivers.
level: high
tags:
  - attack.privilege_escalation
  - attack.execution
  - attack.persistence
  - cve.CVE-2021-1675
  - cve.CVE-2021-34527
  - detection.windows.sysmon
notes: |
  - Tuning: whitelist known print management servers, vendor driver installers, and scheduled maintenance accounts.
  - Investigation: collect process command lines, parent/child process trees, full file paths for created files, and any network connections from the host; check for newly created services, unexpected DLLs under spool driver paths, and evidence of lateral movement.
  - Mitigation: ensure Microsoft updates addressing CVE-2021-1675 and CVE-2021-34527 are applied, and consider disabling the Print Spooler service on hosts that do not require printing.


---
# Arquivo: E.yml
title: Spoolsv Suspicious Loaded Modules (PrintNightmare)
id: a5e451f8-da81-11eb-b245-acde48001122
status: production
description: Detects the loading of a DLL by spoolsv.exe from the print drivers directory tree, which is highly characteristic of the PrintNightmare vulnerability exploitation (CVE-2021-1675 and CVE-2021-34527). Adversaries abuse the RpcAddPrinterDriverEx API to upload and register a malicious payload DLL within these driver paths to gain SYSTEM execution.
references:
    - https://twitter.com/mvelazco/status/1410291741241102338
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527
    - https://medium.com/@mvelazco/i-pity-the-spool-detecting-printnightmare-cve-2021-34527-8f7032cc40b9
author: Mauricio Velazco, Michael Haag, Teoderick Contreras, Splunk
date: 2021/07/01
modified: 2026/06/04
tags:
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1547.012 # Boot or Logon Autostart Execution: Print Processors
    - attack.t1068     # Exploitation for Privilege Escalation
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\spoolsv.exe'
        ImageLoaded|contains:
            - '\Windows\System32\spool\drivers\x64\3\'
            - '\Windows\System32\spool\drivers\x64\4\'
        ImageLoaded|endswith: '.dll'
    condition: selection
falsepositives:
    - Legitimate print driver upgrades, deployments, or printer hardware updates initiated by domain administrators installing approved vendor drivers (e.g., HP, Xerox, Canon).
level: critical

---
# Arquivo original: av_exploit_cve_2021_34527_print_nightmare.yml
title: Antivirus PrinterNightmare CVE-2021-34527 Exploit Detection
id: 6fe1719e-ecdf-4caf-bffe-4f501cb0a561
status: stable
description: Detects the suspicious file that is created from PoC code against Windows Print Spooler Remote Code Execution Vulnerability CVE-2021-34527 (PrinterNightmare), CVE-2021-1675 .
references:
    - https://twitter.com/mvelazco/status/1410291741241102338
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527
author: Sittikorn S, Nuttakorn T, Tim Shelton
date: 2021-07-01
modified: 2023-10-23
tags:
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1055
    - detection.emerging-threats
    - cve.2021-34527
    - cve.2021-1675
logsource:
    category: antivirus
detection:
    selection:
        Filename|contains: ':\Windows\System32\spool\drivers\x64\'
    keywords:
        - 'File submitted to Symantec' # symantec fp, pending analysis, more generic
    condition: selection and not keywords
falsepositives:
    - Unlikely, or pending PSP analysis
level: critical

---