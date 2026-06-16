# Arquivo: A.yml
title: Persistence Indicators Related to BZAR Tooling and Generic Persistence Techniques
id: 2026-000-bzar-persistence
status: experimental
description: Detects persistence techniques and artifacts associated with the BZAR toolkit and common attacker persistence methods: service installs with non-standard image paths, scheduled task creation, Run/RunOnce registry entries pointing to user-writable locations, DLL sideloading via regsvr32/rundll32, startup folder placements, and creation of files or processes containing "bzar" or known BZAR component names. Correlate across file, process, registry and service/task events to raise confidence.
author: Detection Engineer
date: 2026-06-08
references:
  - https://github.com/mitre-attack/bzar#indicators-for-attck-persistence
logsource:
  product: windows
  service: sysmon,security
  category: process_creation,file_event,registry,service_installation
detection:
  selection_service_install_unusual_path:
    EventID: 7045
    ServiceFileName|re:
      - '(?i)\\Users\

\[^\\]

+\\'
      - '(?i)\\AppData\\Local\\Temp\\'
      - '(?i)\\AppData\\Roaming\\'
      - '(?i)\\.*\\Downloads\\'
      - '(?i)\\ProgramData\\'
  selection_schtask_create:
    EventID: 4698
    TaskName|re:
      - '(?i).*bzar.*'
      - '(?i).*persist.*'
      - '(?i).*update.*'
  selection_registry_run_keys:
    EventID: 13
    RegistryKey|re:
      - '(?i)HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
      - '(?i)HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
      - '(?i)HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
      - '(?i)HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
      - '(?i)HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices'
      - '(?i)HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'
    RegistryValueData|re:
      - '(?i)\\Users\

\[^\\]

+\\'
      - '(?i)\\AppData\\Local\\Temp\\'
      - '(?i)\\AppData\\Roaming\\'
      - '(?i)\\.*\\Downloads\\'
      - '(?i)\\ProgramData\\'
  selection_startup_folder_file:
    EventID: 11
    TargetFilename|re:
      - '(?i)\\Users\

\[^\\]

+\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\'
      - '(?i)\\Users\

\[^\\]

+\\Start Menu\\Programs\\Startup\\'
  selection_dll_sideloading:
    EventID: 1
    Image|re:
      - '(?i)\\regsvr32\.exe$'
      - '(?i)\\rundll32\.exe$'
    CommandLine|re:
      - '(?i)\.dll'
      - '(?i)\\.*\

\[^\\]

{1,100}\.dll'
  selection_bzar_filenames_written:
    EventID: 11
    TargetFilename|re:
      - '(?i)\\bzar(\.exe|\.dll|\.ps1|\.py|_agent\.exe|_service\.exe)?$'
      - '(?i)\\.*\\bzar[-_a-z0-9]{0,40}\.(exe|dll|ps1|py)$'
  selection_bzar_process:
    EventID: 1
    Image|re:
      - '(?i)\\bzar(\.exe|\.py|\.ps1)$'
    CommandLine|re:
      - '(?i)bzar'
  selection_unusual_parent_for_service_install:
    EventID: 1
    ParentImage|re:
      - '(?i)\\(msedge|chrome|firefox|iexplore|outlook|winword|excel|powerpnt)\.exe$'
  correlation_file_then_service:
    - when: selection_bzar_filenames_written
      then: selection_service_install_unusual_path
      within: "2m"
  correlation_registry_then_exec:
    - when: selection_registry_run_keys
      then: selection_bzar_process
      within: "2m"
  condition: >
    selection_service_install_unusual_path
    or selection_schtask_create
    or selection_registry_run_keys
    or selection_startup_folder_file
    or selection_dll_sideloading
    or selection_bzar_filenames_written
    or selection_bzar_process
    or selection_unusual_parent_for_service_install
    or correlation_file_then_service
    or correlation_registry_then_exec
fields:
  - timestamp
  - EventID
  - ComputerName
  - SubjectUserName
  - ServiceName
  - ServiceFileName
  - TaskName
  - RegistryKey
  - RegistryValueName
  - RegistryValueData
  - TargetFilename
  - Image
  - ParentImage
  - CommandLine
  - ProcessId
falsepositives:
  - Legitimate software installers, developer tools, or packaging processes that stage or install services/tasks from non-standard locations (whitelist known deployment and build hosts).
  - User-installed portable applications placed intentionally in user directories or Startup folders.
  - Administrative automation that creates scheduled tasks or registry run keys as part of legitimate management workflows.
level: high
tags:
  - persistence
  - attack.t1547
  - attack.t1053
  - attack.t1543
  - bzar
  - detection.windows
notes: |
  - Tuning: whitelist known deployment/CI hosts, signed installers, and authorized admin/service accounts; require correlation across multiple signals (e.g., file write + service install or registry entry + process execution) to reduce noise.
  - Investigation: collect the service binary, scheduled task XML, registry value data, full process trees, command lines, and file hashes; check digital signatures and search for identical artifacts across the environment.
  - Response: if malicious, stop and disable services/tasks, remove persistence artifacts, isolate affected hosts, rotate credentials if exposed, and perform a broader hunt for additional BZAR components or related persistence mechanisms.


---
# Arquivo: B.yml
title: BZAR - ATT&CK Persistence via Remote DCE-RPC Winlogon Helper or Port Monitor Registration
id: a4f3c9e1-7d2b-4e6a-b8f0-1c5d9a2e4b7f
status: experimental
description: >
    Detects ATT&CK-like persistence techniques (T1547.004 and T1547.010) by
    identifying DCE-RPC calls to functions used to remotely register Winlogon
    Helper DLLs or Port Monitors on a target Windows host. These calls are
    observed in network traffic logs (Zeek/Bro dce_rpc.log) and indicate an
    adversary attempting to establish persistence by loading a malicious DLL
    through the Windows Logon subsystem or the Print Spooler service.
    Based on MITRE BZAR analytics (section 4.6 - Indicators for ATT&CK Persistence).
references:
    - https://github.com/mitre-attack/bzar#indicators-for-attck-persistence
    - https://attack.mitre.org/techniques/T1547/004/
    - https://attack.mitre.org/techniques/T1547/010/
author: Generated for educational purposes
date: 2026-06-08
tags:
    - attack.persistence
    - attack.t1547.004    # Boot or Logon Autostart Execution: Winlogon Helper DLL
    - attack.t1547.010    # Boot or Logon Autostart Execution: Port Monitors
logsource:
    product: zeek
    service: dce_rpc
    definition: >
        Requires Zeek (Bro) network security monitor with DCE-RPC protocol
        analysis enabled, generating dce_rpc.log entries. Fields used are
        'endpoint' and 'operation' from the Zeek DCE-RPC log. These logs
        must be forwarded to a SIEM and parsed accordingly. The Zeek log
        fields map as: endpoint -> dce_rpc.endpoint, operation -> dce_rpc.operation.
detection:
    selection_winlogon_helper:
        # T1547.004 - Winlogon Helper DLL
        # The ISecLogon interface is used to create processes under alternate
        # credentials. Remotely calling these operations is a strong signal
        # of an adversary abusing Winlogon for persistence or lateral movement.
        endpoint: 'ISecLogon'
        operation:
            - 'SeclCreateProcessWithLogonW'
            - 'SeclCreateProcessWithLogonExW'

    selection_port_monitor:
        # T1547.010 - Port Monitors / Print Processors
        # Legitimate remote printer management rarely calls AddMonitor or
        # AddPrintProcessor from outside the organization's print management
        # infrastructure. These calls from unexpected sources are highly
        # suspicious and indicate DLL registration for persistence.
        endpoint:
            - 'IRemoteWinspool'
            - 'spoolss'
        operation:
            - 'RpcAsyncAddMonitor'
            - 'RpcAsyncAddPrintProcessor'
            - 'RpcAddMonitor'
            - 'RpcAddPrintProcessor'

    condition: selection_winlogon_helper or selection_port_monitor
falsepositives:
    - Legitimate remote printer infrastructure management by authorized
      print server administrators using RpcAddMonitor or RpcAddPrintProcessor
    - Enterprise print management software that programmatically registers
      port monitors across a fleet of workstations
    - Authorized IT automation scripts that configure Winlogon helpers
      during system provisioning or domain join operations
level: high

---
# Arquivo: C.yml
title: Remote Persistence via Winspool or ISecLogon RPC
id: 9d1a6c77-7b1a-4f7b-9f5e-7bd3d3c0c2ac
status: experimental
description: Detects remote DCE-RPC operations associated with ATT&CK persistence techniques, including Winlogon/helper logon and remote print monitor or print processor additions.
references:
  - https://github.com/mitre-attack/bzar#indicators-for-attck-persistence
author: OpenAI
date: 2026-06-08
logsource:
  product: zeek
  service: dce_rpc
detection:
  selection:
    dce_rpc.operation|contains:
      - 'ISecLogon::SeclCreateProcessWithLogonW'
      - 'ISecLogon::SeclCreateProcessWithLogonExW'
      - 'IRemoteWinspool::RpcAsyncAddMonitor'
      - 'IRemoteWinspool::RpcAsyncAddPrintProcessor'
      - 'spoolss::RpcAddMonitor'
      - 'spoolss::RpcAddPrintProcessor'
  condition: selection
falsepositives:
  - Legitimate remote administration
  - Printer management and deployment tools
  - Authorized logon-session creation by enterprise software
level: high
tags:
  - attack.persistence
  - attack.t1547.004
  - attack.t1547.010

---
# Arquivo: D.yml
title: Potential DCE-RPC Persistence Technique
id: 4f5e3a2b-1c0d-4e8f-9a7b-6c5d4e3f2a1b
status: experimental
description: Detects DCE-RPC operations associated with ATT&CK persistence techniques, such as Winlogon Helper DLL (T1547.004) and Port Monitors (T1547.010), as identified by MITRE's BZAR project.
references:
  - https://sigmahq.io/docs/basics/rules.html
  - https://github.com/mitre-attack/bzar#indicators-for-attck-persistence
author: Senior Threat Detection Engineer
date: 2026-06-08
tags:
  - attack.persistence
  - attack.t1547.004
  - attack.t1547.010
logsource:
  product: zeek
  service: dce_rpc
detection:
  selection:
    operation|contains:
      - 'ISecLogon::SeclCreateProcessWithLogonW'
      - 'ISecLogon::SeclCreateProcessWithLogonExW'
      - 'IRemoteWinspool::RpcAsyncAddMonitor'
      - 'IRemoteWinspool::RpcAsyncAddPrintProcessor'
      - 'spoolss::RpcAddMonitor'
      - 'spoolss::RpcAddPrintProcessor'
  condition: selection
falsepositives:
  - Legitimate administrative actions using the same RPC calls (e.g., printer or print processor installation, certain software deployments).
level: high

---
# Arquivo: E.yml
title: Zeek DCE-RPC Remote Scheduled Task Creation (BZAR Persistence)
id: 8d302a9e-5e7c-4811-9a99-b14e6727d819
status: experimental
description: |
  Detects network traffic associated with the remote creation or modification of Windows Scheduled Tasks via DCE-RPC.
  As outlined by the MITRE BZAR project, adversaries frequently leverage the 'atsvc' or 'ITaskSchedulerService' RPC interfaces to establish persistence or execute payloads laterally across a network without requiring an interactive logon session.
author: Gemini
date: 2026/06/08
references:
    - https://github.com/mitre-attack/bzar#indicators-for-attck-persistence
    - https://attack.mitre.org/techniques/T1053/005/
tags:
    - attack.persistence
    - attack.lateral_movement
    - attack.t1053.005
logsource:
    product: zeek
    service: dcerpc
detection:
    selection:
        endpoint: 
            - 'ITaskSchedulerService'
            - 'atsvc'
        operation: 
            - 'SchRpcRegisterTask'
            - 'JobAdd'
    condition: selection
falsepositives:
    - System administrators legitimately managing remote endpoints using the Task Scheduler MMC snap-in or PowerShell cmdlets.
    - Automated endpoint management solutions (e.g., SCCM, Tanium) deploying periodic maintenance scripts.
level: high

---
# Arquivo original: zeek_dce_rpc_mitre_bzar_persistence.yml
title: MITRE BZAR Indicators for Persistence
id: 53389db6-ba46-48e3-a94c-e0f2cefe1583
status: test
description: 'Windows DCE-RPC functions which indicate a persistence techniques on the remote system. All credit for the Zeek mapping of the suspicious endpoint/operation field goes to MITRE.'
references:
    - https://github.com/mitre-attack/bzar#indicators-for-attck-persistence
author: '@neu5ron, SOC Prime'
date: 2020-03-19
modified: 2021-11-27
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1547.004
logsource:
    product: zeek
    service: dce_rpc
detection:
    op1:
        endpoint: 'spoolss'
        operation: 'RpcAddMonitor'
    op2:
        endpoint: 'spoolss'
        operation: 'RpcAddPrintProcessor'
    op3:
        endpoint: 'IRemoteWinspool'
        operation: 'RpcAsyncAddMonitor'
    op4:
        endpoint: 'IRemoteWinspool'
        operation: 'RpcAsyncAddPrintProcessor'
    op5:
        endpoint: 'ISecLogon'
        operation: 'SeclCreateProcessWithLogonW'
    op6:
        endpoint: 'ISecLogon'
        operation: 'SeclCreateProcessWithLogonExW'
    condition: 1 of op*
falsepositives:
    - Windows administrator tasks or troubleshooting
    - Windows management scripts or software
level: medium

---