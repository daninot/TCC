# Arquivo: A.yml
title: DCE-RPC Calls Indicative of Remote Persistence via Print/Logon RPCs
id: 8f2b1c3d-4a5e-4b6c-9d0e-1f2a3b4c5d6e
status: experimental
description: Detects DCE-RPC calls to RPC endpoints and operations commonly abused to install print monitors/print processors or create processes under another user's logon session on remote hosts. These RPC endpoint/operation pairs have been observed in adversary persistence techniques. Requires Zeek DCE-RPC logging that captures endpoint/interface and operation names.
author: Senior Threat Detection Engineer
date: 2026/06/15
references:
  - [https://github.com/mitre-attack/bzar#indicators-for-attck-persistence](https://github.com/mitre-attack/bzar#indicators-for-attck-persistence)
  - `https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/` [(learn.microsoft.com in Bing)](https://www.bing.com/search?q="https%3A%2F%2Flearn.microsoft.com%2Fen-us%2Fopenspecs%2Fwindows_protocols%2Fms-rprn%2F") (print spooler RPC)
tags:
  - attack.persistence
  - attack.lateral_movement
  - windows
  - rpc
logsource:
  product: zeek
  service: dce_rpc
  category: network_traffic
  description: Zeek DCE-RPC logs containing fields such as endpoint, interface, operation, opnum, src_ip, dst_ip, and uid. Ensure DCE/RPC parsing is enabled.
detection:
  op1:
    endpoint|contains:
      - 'spoolss'
    operation|contains:
      - 'RpcAddMonitor'
  op2:
    endpoint|contains:
      - 'spoolss'
    operation|contains:
      - 'RpcAddPrintProcessor'
  op3:
    endpoint|contains:
      - 'IRemoteWinspool'
    operation|contains:
      - 'RpcAddMonitor'
      - 'RpcAddMonitorAsync'
  op4:
    endpoint|contains:
      - 'IRemoteWinspool'
    operation|contains:
      - 'RpcAddPrintProcessor'
      - 'RpcAddPrintProcessorAsync'
  op5:
    endpoint|contains:
      - 'ISecLogon'
    operation|contains:
      - 'SeclCreateProcessWithLogonW'
  op6:
    endpoint|contains:
      - 'ISecLogon'
    operation|contains:
      - 'SeclCreateProcessWithLogonWEx'
  condition: 1 of op1 op2 op3 op4 op5 op6
fields:
  - endpoint
  - interface
  - operation
  - opnum
  - src_ip
  - dst_ip
  - uid
falsepositives:
  - Legitimate administrative or print server management activity that installs print monitors or processors.
  - Remote management tooling or enterprise orchestration that invokes print or logon RPCs for valid operational reasons.
level: high

---
# Arquivo: B.yml
title: BZAR Remote Persistence Indicators via DCE-RPC
id: c71b67f1-79b9-43c3-b0c6-930fcbba2fb6
status: experimental
description: Detects Windows DCE-RPC calls indicating remote persistence techniques. Adversaries invoke specific RPC endpoint/operation pairs to install print monitors, print processors, or create processes under another user's logon session on a remote host. Pattern catalog from MITRE BZAR project.
references:
- [https://github.com/mitre-attack/bzar#indicators-for-attck-persistence](https://github.com/mitre-attack/bzar#indicators-for-attck-persistence)
author: Senior Threat Detection Engineer
date: 2026/06/08
tags:
- attack.persistence
- attack.t1547.010
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
operation: 'AsyncAddMonitor'
op4:
endpoint: 'IRemoteWinspool'
operation: 'AsyncAddPrintProcessor'
op5:
endpoint: 'ISecLogon'
operation: 'SeclCreateProcessWithLogonW'
op6:
endpoint: 'ISecLogon'
operation: 'SeclCreateProcessWithLogonExW'
condition: 1 of op*
falsepositives:
- Legitimate remote administration and print server configuration
level: medium

---
# Arquivo: C.yml
title: Remote Persistence via DCE-RPC Calls
id: f6a7b8c9-d0e1-42f3-84a5-6b7c8d9e0f1a
status: experimental
description: Detects DCE-RPC calls indicating remote persistence techniques, such as installing print monitors/processors or creating processes under another user's logon session on a remote host (MITRE BZAR).
references:
    - https://github.com/mitre-attack/bzar#indicators-for-attck-persistence
author: Senior Threat Detection Engineer
date: 2026-06-08
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
    - Legitimate administrative actions installing printers or using runas on remote systems
level: high
tags:
    - attack.persistence
    - attack.t1547
    - attack.t1136
    - attack.t1547.010

---
# Arquivo: D.yml
title: Remote DCE-RPC Persistence via Print Monitor Print Processor or Logon Session Process
id: 4f2b8e3d-1c7a-4f9b-b5e2-8d3c1f7a4b29
status: experimental
description: >
  Detects Windows DCE-RPC calls over the network that invoke specific endpoint
  and operation pairs associated with remote persistence techniques, as
  documented by the MITRE BZAR analytics project. The six endpoint-operation
  pairs covered fall into three categories. First, the spoolss and
  IRemoteWinspool endpoints expose RpcAddMonitor and RpcAddPrintProcessor
  (and their async variants) which allow a caller to register a print monitor
  or print processor DLL on the target host; when invoked remotely with an
  attacker-supplied DLL path, these calls cause the Print Spooler service to
  load the DLL with SYSTEM privileges, providing both persistent code execution
  and privilege escalation. Second, the ISecLogon endpoint exposes
  SeclCreateProcessWithLogonW and its Ex variant, which create a new process
  in the context of a different user's logon session on the remote host,
  enabling an adversary to spawn processes as an arbitrary user without
  interactive logon. All six operations are network-observable from Zeek
  DCE-RPC log telemetry, making them detectable without host-based sensors
  on the targeted system.
references:
  - https://github.com/mitre-attack/bzar#indicators-for-attck-persistence
author: Senior Threat Detection Engineer
date: 2026-05-25
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.lateral_movement
  - attack.t1547.010
  - attack.t1134.002
logsource:
  product: zeek
  service: dce_rpc
detection:
  op1:
    endpoint: spoolss
    operation: RpcAddMonitor
  op2:
    endpoint: spoolss
    operation: RpcAddPrintProcessor
  op3:
    endpoint: IRemoteWinspool
    operation: RpcAsyncAddMonitor
  op4:
    endpoint: IRemoteWinspool
    operation: RpcAsyncAddPrintProcessor
  op5:
    endpoint: ISecLogon
    operation: SeclCreateProcessWithLogonW
  op6:
    endpoint: ISecLogon
    operation: SeclCreateProcessWithLogonExW
  condition: 1 of op*
falsepositives:
  - Legitimate print server administration workflows where an authorised
    administrator remotely registers a vendor-supplied print monitor or
    print processor DLL on a managed print server as part of a driver
    deployment or hardware provisioning process.
  - Enterprise management software that creates processes in alternate
    user contexts via ISecLogon as part of an approved privilege-separated
    execution design.
level: high

---
# Arquivo: E.yml
title: Windows DCE-RPC Persistence via Remote Print Monitor and Logon Session Operations
id: 9f2f3d7b-6e2c-4d0a-8f0a-2d9c7ab8f4a1
status: experimental
description: Detects Windows DCE-RPC calls associated with remote persistence techniques, including adding print monitors or print processors and creating processes under another user's logon session.
references:

* [https://github.com/mitre-attack/bzar#indicators-for-attck-persistence](https://github.com/mitre-attack/bzar#indicators-for-attck-persistence)
  author: OpenAI
  date: 2026-06-06
  tags:
* attack.persistence
* attack.t1547.004
* attack.t1547.010
  logsource:
  product: zeek
  service: dce_rpc
  detection:
  op1:
  endpoint|contains: 'spoolss'
  operation|contains: 'RpcAddMonitor'
  op2:
  endpoint|contains: 'spoolss'
  operation|contains: 'RpcAddPrintProcessor'
  op3:
  endpoint|contains: 'IRemoteWinspool'
  operation|contains: 'RpcAsyncAddMonitor'
  op4:
  endpoint|contains: 'IRemoteWinspool'
  operation|contains: 'RpcAsyncAddPrintProcessor'
  op5:
  endpoint|contains: 'ISecLogon'
  operation|contains: 'SeclCreateProcessWithLogonW'
  op6:
  endpoint|contains: 'ISecLogon'
  operation|contains: 'SeclCreateProcessWithLogonExW'
  condition: 1 of op*
  falsepositives:
* Legitimate remote printer administration
* Authorized administrative use of logon-session creation tooling
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