# Arquivo: A.yml
title: Telegram Bot API Abuse Indicators (C2 / Ransomware / Data Exfiltration)
id: 2026-000-telegram-bot-api-abuse
status: experimental
description: Detects abuse of the Telegram Bot API by malware for command-and-control, data exfiltration, or ransomware callbacks. Flags HTTP requests to Telegram API endpoints, discovery of Telegram bot tokens in files or command lines, processes invoking Telegram endpoints, and creation of ransom notes or encrypted artifacts correlated with Telegram network activity.
author: Detection Engineer
date: 2026-06-09
references:
  - https://core.telegram.org/bots/faq
  - https://researchcenter.paloaltonetworks.com/2018/03/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/
  - https://blog.malwarebytes.com/threat-analysis/2016/11/telecrypt-the-ransomware-abusing-telegram-api-defeated/
  - https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/
logsource:
  product: firewall,proxy,webserver,endpoint
  service: http,network,sysmon,file
  category: network_traffic,web_access,process_creation,file_event
detection:
  selection_telegram_api_http:
    EventID: 3
    Host|contains:
      - "api.telegram.org"
    RequestUri|re:
      - '(?i)/bot[0-9]{6,12}:[A-Za-z0-9_\-]{30,}/'
    HttpMethod|in:
      - "POST"
      - "GET"
  selection_telegram_api_host:
    EventID: 3
    DestinationHost|re:
      - '(?i)api\.telegram\.org'
      - '(?i)telegram\.org'
  selection_telegram_token_in_file:
    EventID: 11
    TargetFilename|re:
      - '(?i).*\.txt$'
      - '(?i).*\.config$'
      - '(?i).*\.json$'
      - '(?i).*\.env$'
    FileContent|re:
      - '(?i)[0-9]{6,12}:[A-Za-z0-9_\-]{30,}'
  selection_token_in_commandline:
    EventID: 1
    Image|re:
      - '(?i)\\(curl|wget|python|powershell|pwsh)\.exe$'
    CommandLine|re:
      - '(?i)api\.telegram\.org'
      - '(?i)[0-9]{6,12}:[A-Za-z0-9_\-]{30,}'
  selection_process_sending_files:
    EventID: 1
    Image|re:
      - '(?i)\\python(\d?\.exe)?$'
      - '(?i)\\powershell(\.exe)?$'
      - '(?i)\\curl\.exe$'
    CommandLine|re:
      - '(?i)(sendDocument|sendPhoto|sendMessage|sendAudio|sendVideo|sendMediaGroup)'
  selection_ransomnote_or_encrypted_artifact:
    EventID: 11
    TargetFilename|re:
      - '(?i).*\\(README_FOR_DECRYPT|README\.txt|HOW_TO_DECRYPT|_DECRYPT|_README).*'
      - '(?i).*\.locked$'
      - '(?i).*\.enc$'
  selection_long_lived_https:
    EventID: 3
    Protocol|contains:
      - "https"
    Duration|gt: "00:05:00"
    DestinationHost|re:
      - '(?i)api\.telegram\.org'
  correlation_token_then_network:
    - when: selection_telegram_token_in_file
      then: selection_telegram_api_http
      within: "5m"
  correlation_process_then_ransom:
    - when: selection_process_sending_files
      then: selection_ransomnote_or_encrypted_artifact
      within: "10m"
  condition: >
    (selection_telegram_api_http or selection_telegram_api_host or selection_long_lived_https)
    and (selection_telegram_token_in_file or selection_token_in_commandline or selection_process_sending_files or selection_ransomnote_or_encrypted_artifact)
    or correlation_token_then_network
    or correlation_process_then_ransom
fields:
  - timestamp
  - EventID
  - ComputerName
  - SourceIp
  - DestinationIp
  - DestinationHost
  - DestinationPort
  - Protocol
  - HttpMethod
  - RequestUri
  - Image
  - ParentImage
  - CommandLine
  - TargetFilename
  - FileContentSnippet
  - ProcessId
falsepositives:
  - Legitimate automation, monitoring, or admin scripts that use Telegram bots for notifications (whitelist known bot tokens, service accounts, and management hosts).
  - Developers or CI systems that store bot tokens in configuration files in non-production environments.
  - Long-lived integrations to Telegram used by business applications.
level: high
tags:
  - attack.command_and_control
  - attack.exfiltration
  - attack.ransomware
  - telegram
  - detection.network
  - detection.endpoint
notes: |
  - Tuning: whitelist approved bot tokens, known management IPs, and internal automation; restrict detection to production-facing hosts and external IP ranges to reduce noise.
  - Investigation: collect full HTTP request/response pairs, TLS metadata (SNI, certs), the file containing the token (preserve and hash), full process tree and command lines, and any created ransom notes or encrypted files.
  - Response: revoke exposed bot tokens, block outbound access to api.telegram.org from compromised hosts, isolate affected systems, recover from backups if ransomware is confirmed, and hunt for other hosts using the same token or contacting the same Telegram endpoints.


---
# Arquivo: B.yml
title: Suspicious Telegram Bot API Command and Control Communication
id: 6f0db574-8b1e-4cb8-871d-5b5cfae64177
status: experimental
description: Detects network proxy requests or connection attempts to the Telegram Bot API endpoint. Threat actors across various platforms (such as the operators behind TeleRAT, TeleCrypt, and TeleBots) frequently abuse Telegram's legitimate bot infrastructure as an encrypted, resilient Command and Control (C2) channel or data exfiltration medium.
references:
    - https://core.telegram.org/bots/faq
    - https://researchcenter.paloaltonetworks.com/2018/03/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/
    - https://blog.malwarebytes.com/threat-analysis/2016/11/telecrypt-the-ransomware-abusing-telegram-api-defeated/
    - https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/
author: Security Operations Center
date: 2026/06/08
tags:
    - attack.command_and_control
    - attack.exfiltration
    - attack.t1102.002 # Web Service: Bidirectional Communication
logsource:
    category: proxy
detection:
    selection:
        url|contains:
            - 'api.telegram.org/bot'
    condition: selection
falsepositives:
    - Authorized corporate DevOps notifications, chat-ops automation playbooks, or security alerts configured by internal engineering teams to broadcast status updates to dedicated Telegram channels.
level: medium

---
# Arquivo: C.yml
title: Telegram Bot API Used as C2 Channel by Suspicious Process
id: 9c2e5f1a-3b7d-4a8e-c6f2-0d4b1e9a5c8f
status: experimental
description: >
    Detects outbound HTTP/HTTPS connections to the Telegram Bot API endpoint
    (api.telegram.org/bot<token>/) initiated by processes that are not
    expected to communicate with Telegram in a corporate environment.
    This pattern is consistent with multiple malware families that abuse
    the Telegram Bot API as a covert Command & Control (C2) and data
    exfiltration channel, including TeleRAT (Android RAT targeting Iranian
    users), TeleCrypt (ransomware exfiltrating encryption keys), and the
    TeleBots/KillDisk APT group (linked to Sandworm/NotPetya precursor activity).
    The Telegram Bot API is attractive to attackers because it rides on
    legitimate HTTPS traffic to a trusted domain, bypassing URL-based
    blocklists and firewall rules that permit social media traffic.
references:
    - https://core.telegram.org/bots/faq
    - https://unit42.paloaltonetworks.com/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/
    - https://blog.malwarebytes.com/threat-analysis/2016/11/telecrypt-the-ransomware-abusing-telegram-api-defeated/
    - https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/
author: Generated for educational purposes
date: 2026-06-08
tags:
    - attack.command_and_control
    - attack.t1102              # Web Service (using legitimate external service as C2)
    - attack.t1102.002          # Bidirectional Communication via Web Service
    - attack.exfiltration
    - attack.t1567              # Exfiltration Over Web Service
    - attack.t1567.002          # Exfiltration to Cloud Storage / messaging platform
logsource:
    category: proxy
    definition: >
        Requires HTTP/HTTPS proxy logs (e.g. Squid, Zscaler, Blue Coat, Palo
        Alto NGFW URL Filtering) with fields for the requesting host, the
        initiating process name (if available via endpoint agent integration),
        and the full request URL or at minimum the hostname and URI path.
        Alternatively, this rule can be adapted for Sysmon Event ID 3
        (NetworkConnect) or Windows Firewall logs by matching the destination
        hostname. The key field is cs-uri-stem or similar, containing the
        path '/bot' as part of the Telegram Bot API token pattern.
detection:
    selection_telegram_bot_api:
        # Every Telegram Bot API call follows the pattern:
        # https://api.telegram.org/bot<TOKEN>/<METHOD>
        # The presence of '/bot' immediately after the hostname is the
        # canonical indicator — no legitimate Telegram client app uses
        # this path structure; only bots (and malware impersonating bots) do.
        cs-host: 'api.telegram.org'
        cs-uri-stem|startswith: '/bot'

    selection_suspicious_methods:
        # These are the specific Bot API methods observed in malware:
        # - sendMessage / sendDocument: exfiltrating data or alerting the operator
        # - getUpdates: polling for new C2 commands (TeleRAT beaconing every 4.6s)
        # - getFile / forwardMessage: retrieving payloads or relaying stolen data
        cs-uri-stem|contains:
            - '/sendMessage'
            - '/sendDocument'
            - '/getUpdates'
            - '/getFile'
            - '/forwardMessage'
            - '/sendPhoto'

    filter_legitimate_processes:
        # Exclude known-good processes that legitimately use Telegram
        # in a desktop/enterprise context. Adapt this list to your environment.
        cs-username|contains:
            - 'Telegram Desktop'
        # If your proxy logs include the initiating process (via endpoint
        # agent like CrowdStrike, Carbon Black, or Sysmon+proxy integration),
        # add process name filters here, e.g.:
        # process_name|endswith:
        #     - '\Telegram.exe'
        #     - '\chrome.exe'
        #     - '\firefox.exe'
        #     - '\msedge.exe'

    condition: (selection_telegram_bot_api and selection_suspicious_methods) and not filter_legitimate_processes

falsepositives:
    - Internal developer bots or ChatOps integrations (e.g. CI/CD pipelines
      posting build results to a Telegram channel) running on workstations
      rather than dedicated servers
    - Telegram Desktop application performing background polling — however,
      the official client does NOT use the /bot API path; it uses MTProto
    - Automated monitoring or alerting scripts legitimately using a Telegram
      bot to notify on-call engineers; these should be inventoried and their
      source IPs/processes added to an allowlist

level: high

---
# Arquivo: D.yml
title: Telegram Bot API C2 Traffic
id: 2bf3d4ab-3f0a-4c7a-8f9d-3c4f1c55b9d1
status: experimental
description: Detects outbound HTTP(S) requests to the Telegram Bot API, which may indicate malware abusing Telegram bots for command-and-control, tasking, or exfiltration.
references:

* [https://core.telegram.org/bots/faq](https://core.telegram.org/bots/faq)
* [https://researchcenter.paloaltonetworks.com/2018/03/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/](https://researchcenter.paloaltonetworks.com/2018/03/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/)
* [https://blog.malwarebytes.com/threat-analysis/2016/11/telecrypt-the-ransomware-abusing-telegram-api-defeated/](https://blog.malwarebytes.com/threat-analysis/2016/11/telecrypt-the-ransomware-abusing-telegram-api-defeated/)
* [https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/](https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/)
  author: OpenAI
  date: 2026-06-08
  tags:
* attack.command_and_control
* attack.t1071.001
* attack.t1102
  logsource:
  category: proxy
  detection:
  selection_host_1:
  cs-host|contains: 'api.telegram.org'
  selection_host_2:
  url|contains: 'api.telegram.org'
  selection_host_3:
  dst_domain: 'api.telegram.org'
  selection_bot_prefix_1:
  cs-uri-stem|contains: '/bot'
  selection_bot_prefix_2:
  url|contains: '/bot'
  selection_method_1:
  cs-uri-stem|contains:

  * '/getUpdates'
  * '/sendMessage'
  * '/sendDocument'
  * '/sendPhoto'
  * '/sendFile'
  * '/getFile'
  * '/answerCallbackQuery'
    selection_method_2:
    url|contains:
  * '/getUpdates'
  * '/sendMessage'
  * '/sendDocument'
  * '/sendPhoto'
  * '/sendFile'
  * '/getFile'
  * '/answerCallbackQuery'
    condition: (1 of selection_host_*) and (1 of selection_bot_prefix_*) and (1 of selection_method_*)
    fields:
* cs-host
* cs-uri-stem
* cs-uri-query
* url
* dst_domain
* src_ip
* user_agent
* process_name
  falsepositives:
* Legitimate Telegram bot integrations
* Developer testing of Telegram bots
* User-driven applications that intentionally access the Telegram Bot API
  level: medium


---
# Arquivo: E.yml
title: Telegram Bot API Request
id: c64c5175-5189-431b-a55e-6d9882158251
status: test
description: Detects suspicious DNS queries to api.telegram.org used by Telegram Bots of any kind
references:
    - https://core.telegram.org/bots/faq
    - https://researchcenter.paloaltonetworks.com/2018/03/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/
    - https://blog.malwarebytes.com/threat-analysis/2016/11/telecrypt-the-ransomware-abusing-telegram-api-defeated/
    - https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/
author: Florian Roth (Nextron Systems)
date: 2018-06-05
modified: 2022-10-09
tags:
    - attack.command-and-control
    - attack.t1102.002
logsource:
    category: dns
detection:
    selection:
        query: 'api.telegram.org'  # Telegram Bot API Request
    condition: selection
falsepositives:
    - Legitimate use of Telegram bots in the company
level: medium

---
# Arquivo original: net_dns_susp_telegram_api.yml
title: Telegram Bot API Request
id: c64c5175-5189-431b-a55e-6d9882158251
status: test
description: Detects suspicious DNS queries to api.telegram.org used by Telegram Bots of any kind
references:
    - https://core.telegram.org/bots/faq
    - https://researchcenter.paloaltonetworks.com/2018/03/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/
    - https://blog.malwarebytes.com/threat-analysis/2016/11/telecrypt-the-ransomware-abusing-telegram-api-defeated/
    - https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/
author: Florian Roth (Nextron Systems)
date: 2018-06-05
modified: 2022-10-09
tags:
    - attack.command-and-control
    - attack.t1102.002
logsource:
    category: dns
detection:
    selection:
        query: 'api.telegram.org'   # Telegram Bot API Request https://core.telegram.org/bots/faq
    condition: selection
falsepositives:
    - Legitimate use of Telegram bots in the company
level: medium

---