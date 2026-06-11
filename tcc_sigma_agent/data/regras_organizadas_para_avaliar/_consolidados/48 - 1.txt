# Arquivo: A.yml
title: Velocity SSTI Probe via Application Runtime Exception
id: 7f3c1e2a-9b4d-4f8e-a1c5-2d6b8e0f3a7c
status: experimental
description: >
    Detects Server-Side Template Injection (SSTI) attempts targeting the Apache
    Velocity template engine by identifying parse/evaluation exceptions in
    application server logs. Attackers probe for SSTI by injecting Velocity
    syntax (e.g. #set, $class, #evaluate) into user-controlled inputs, which
    causes the engine to throw characteristic runtime exceptions when the
    payload disrupts normal template parsing. Based on the Wix Engineering
    approach of using application-level IOCs (Indicators of Compromise) from
    error logs for real-time vulnerability hunting.
references:
    - https://antgarsil.github.io/posts/velocity/
    - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
    - https://velocity.apache.org/engine/1.7/user-guide.html
author: Generated for educational purposes
date: 2026-06-08
tags:
    - attack.initial_access
    - attack.t1190          # Exploit Public-Facing Application
    - attack.t1059          # Command and Scripting Interpreter
logsource:
    category: application
    product: java
    definition: >
        Requires application server logs (e.g. Logback, Log4j, stdout) to be
        collected and forwarded to a SIEM. The log entry must contain the full
        stack trace or at minimum the exception class name and message.
detection:
    selection_exception:
        # These are the canonical Velocity runtime exceptions thrown when
        # template parsing fails — a strong signal of malformed/injected syntax
        message|contains:
            - 'org.apache.velocity.exception.ParseErrorException'
            - 'org.apache.velocity.runtime.parser.ParseException'
            - 'org.apache.velocity.exception.MethodInvocationException'
            - 'VelocityException'
    selection_ssti_keywords:
        # Common Velocity SSTI payload fragments that appear in exception
        # messages when the engine tries to parse injected input
        message|contains:
            - '#set('
            - '#{set}'
            - '$class.inspect'
            - '#evaluate('
            - '$response.sendRedirect'
            - '$session.setAttribute'
            - 'java.lang.Runtime'
            - 'getRuntime().exec'
    condition: selection_exception or selection_ssti_keywords
falsepositives:
    - Legitimate template syntax errors introduced by developers during
      testing or deployment of new templates
    - Automated integration tests that intentionally exercise error paths
    - Misconfigured templates in staging environments forwarding logs to
      the same SIEM index as production
level: high

---
# Arquivo: B.yml
title: Potential Velocity SSTI Exploitation Attempt
id: b3a7e1c5-4d2f-4a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: Detects attempts to exploit Server-Side Template Injection (SSTI) in Apache Velocity, indicated by common payload patterns in HTTP requests. These patterns may lead to remote code execution, privilege escalation, or open redirection.
references:
  - https://antgarsil.github.io/posts/velocity/
  - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
author: Senior Threat Detection Engineer
date: 2026-06-08
tags:
  - attack.initial-access
  - attack.t1190
  - attack.t1059
logsource:
  category: webserver
definition: HTTP request logs (e.g., access log, WAF log) with URI, query string, or request body parameters.
detection:
  selection_keywords:
    cs-uri|contains|all:
      - '#set('
      - '$'
  selection_redirect:
    cs-uri|contains|all:
      - '$response.sendRedirect'
      - 'http://'
  selection_rce:
    cs-uri|contains|all:
      - '$class.inspect'
      - 'getRuntime().exec'
  selection_session:
    cs-uri|contains:
      - '$session.getAttributeNames'
      - '$session.setAttribute'
  selection_foreach:
    cs-uri|contains|all:
      - '#foreach'
      - '$key'
  selection_import:
    cs-uri|contains:
      - '$import.read'
  condition: 1 of selection_*
falsepositives:
  - Legitimate Velocity template usage in development or staging environments.
  - Automated security scanners or vulnerability tests.
level: high

---
# Arquivo: C.yml
title: Apache Velocity Template Injection Attempts and Application Error Indicators
id: 2026-000-velocity-vti-app-error
status: experimental
description: Detects attempts to exploit Apache Velocity Template Injection (VTI) and related malicious template payloads combined with application server error responses or stack traces. Flags HTTP requests containing Velocity template syntax or attempts to access Java internals (e.g., java.lang.Runtime, Class.forName, getRuntime().exec) and correlates with 5xx responses, stack traces, or repeated error responses from the same client to identify exploitation or probing activity.
author: Detection Engineer
date: 2026-06-08
references:
  - https://antgarsil.github.io/posts/velocity/
  - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
logsource:
  product: webserver
  service: http
  category: web_access
detection:
  selection_velocity_payload:
    RequestBody|re:
      - '(?i)\$\{.*\}'
      - '(?i)#set\s*\('
      - '(?i)#foreach\s*\('
      - '(?i)\$!\{.*\}'
      - '(?i)\$\{.*\|.*\}'
  selection_java_runtime_exec:
    RequestBody|re:
      - '(?i)Runtime\.getRuntime\(\)\.exec\('
      - '(?i)java\.lang\.Runtime'
      - '(?i)Class\.forName\('
      - '(?i)new\s+java\.lang'
      - '(?i)getRuntime\(\)\.exec'
  selection_template_class_access:
    RequestBody|re:
      - '(?i)org\.apache\.velocity'
      - '(?i)VelocityContext'
      - '(?i)Template\.merge\('
  selection_stacktrace_response:
    ResponseBody|re:
      - '(?i)(exception|stacktrace|traceback|at\s+[A-Za-z0-9_\.]+:\d+|java\.lang\.|org\.springframework|org\.apache\.velocity)'
  selection_http_error_status:
    Status:
      - 500
      - 502
      - 503
      - 504
  selection_suspicious_useragent:
    UserAgent|re:
      - '(?i)(curl|wget|python-requests|libwww-perl|sqlmap|acunetix|nikto|fuzz|scanner)'
  selection_long_uri_or_params:
    RequestUri|re:
      - '.{200,}'
  selection_repeated_errors_from_ip:
    CountByClientIP: ">5"
    Timeframe: "5m"
    Status:
      - 500
      - 502
      - 503
      - 504
  condition: >
    (selection_velocity_payload or selection_java_runtime_exec or selection_template_class_access)
    and (selection_stacktrace_response or selection_http_error_status or selection_repeated_errors_from_ip)
    or (selection_velocity_payload and selection_suspicious_useragent)
fields:
  - timestamp
  - ClientIP
  - HttpMethod
  - Uri
  - RequestBody
  - ResponseBody
  - Status
  - UserAgent
  - Referer
  - Host
falsepositives:
  - Legitimate use of Velocity templates in application requests (internal template rendering APIs) where template fragments are submitted intentionally.
  - Security scanners or automated testing tools that intentionally submit template-like payloads to test template engines.
  - Large or complex legitimate requests that include characters matching the regex (tune by whitelisting known clients and internal services).
level: high
tags:
  - web.application
  - attack.injection
  - attack.template_injection
  - apache.velocity
  - detection.logging
notes: |
  - Tuning: whitelist known internal services, CI/CD scanners, and trusted testing tools; restrict detection to production-facing endpoints and to external/untrusted client IP ranges.
  - Investigation: capture full request and response pairs, request parameters and bodies, server-side stack traces, recent deployments, and correlate with WAF/IDS alerts. If exploitation is suspected, preserve affected logs and collect the rendered template context from the application if possible.
  - Remediation: apply input validation and output encoding, disable direct template evaluation of user-controlled input, patch vulnerable template engine versions, add WAF rules to block template syntax patterns, and review recent code changes that touch template rendering paths.


---
# Arquivo: D.yml
title: Apache Velocity Server-Side Template Injection Indicators
id: 2b8c2c3b-5f7f-4d0f-9f2a-7d7a7f1a7d6d
status: experimental
description: Detects Apache Velocity SSTI payload fragments or Velocity-related runtime exceptions in application logs.
references:
  - https://antgarsil.github.io/posts/velocity/
  - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
author: OpenAI
date: 2026-06-08
logsource:
  category: application
detection:
  selection_payload:
    Message|contains:
      - '#set('
      - '#{set}'
      - '#evaluate('
      - '$class.inspect('
      - 'java.lang.Runtime'
      - 'Runtime.getRuntime().exec'
      - '$session.setAttribute('
      - '$response.sendRedirect('
  selection_exception:
    Message|contains:
      - 'MethodInvocationException'
      - 'ParseErrorException'
      - 'ResourceNotFoundException'
      - 'Velocity'
      - 'server-side template injection'
  condition: selection_payload or selection_exception
falsepositives:
  - Legitimate Velocity template debugging
  - Development and testing environments
  - Error logs from benign malformed templates
level: medium
tags:
  - attack.initial_access
  - attack.execution
  - attack.t1059
  - attack.t1059.004

---
# Arquivo: E.yml
title: Apache Velocity Template Exception (Potential SSTI)
id: 5b8d2b90-1c4f-4a31-9a75-2d8e4f1b5a91
status: experimental
description: |
  Detects exceptions generated by the Apache Velocity template engine within application logs. 
  Unexpected parsing or method invocation exceptions from the Velocity engine often indicate an attacker is actively fuzzing or attempting Server-Side Template Injection (SSTI). Because attackers must often use trial-and-error to find the correct Java class reflection chain to achieve RCE, they frequently trigger ParseErrorExceptions or MethodInvocationExceptions before succeeding.
author: Gemini
date: 2026/06/08
references:
    - https://antgarsil.github.io/posts/velocity/
    - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
tags:
    - attack.initial_access
    - attack.t1190
logsource:
    category: application
detection:
    keywords:
        - 'org.apache.velocity.exception.ParseErrorException'
        - 'org.apache.velocity.exception.MethodInvocationException'
        - 'org.apache.velocity.exception.MathException'
        - 'Encountered " <IDENTIFIER> "java.lang.Runtime""'
        - 'Velocity engine evaluation exception'
    condition: keywords
falsepositives:
    - Application developers deploying broken or malformed templates to a development or staging environment.
    - Rare edge cases where user-provided input is inadvertently parsed as a template but lacks malicious intent (e.g., a user submitting an email containing raw `$variable` syntax that breaks the lexer).
level: medium

---
# Arquivo original: velocity_ssti_injection.yml
title: Potential Server Side Template Injection In Velocity
id: 16c86189-b556-4ee8-b4c7-7e350a195a4f
status: test
description: Detects exceptions in velocity template renderer, this most likely happens due to dynamic rendering of user input and may lead to RCE.
references:
    - https://antgarsil.github.io/posts/velocity/
    - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
author: Moti Harmats
date: 2023-02-11
tags:
    - attack.initial-access
    - attack.t1190
logsource:
    category: application
    product: velocity
    definition: 'Requirements: application error logs must be collected (with LOG_LEVEL=ERROR and above)'
detection:
    keywords:
        - 'ParseErrorException'
        - 'VelocityException'
        - 'TemplateInitException'
    condition: keywords
falsepositives:
    - Application bugs
    - Missing .vm files
level: high

---