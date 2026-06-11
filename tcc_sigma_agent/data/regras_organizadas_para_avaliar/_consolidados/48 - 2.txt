# Arquivo: A.yml
title: Velocity Template Engine Exceptions in Application Logs
id: 9d4f2b6a-3c1e-4f7b-8a2d-0e1f2b3c4d5e
status: experimental
description: Detects Velocity template engine exceptions in application error logs. When triggered by user-controlled input, Velocity parsing and template initialization exceptions often indicate Server-Side Template Injection (SSTI) attempts that may lead to remote code execution. Requires application logging at LOG_LEVEL ERROR or above and collection of full log messages and stack traces.
author: Senior Threat Detection Engineer
date: 2026/06/15
references:
  - [https://antgarsil.github.io/posts/velocity/](https://antgarsil.github.io/posts/velocity/)
  - [https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs](https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs)
tags:
  - attack.execution
  - attack.injection
  - web
  - velocity
logsource:
  product: velocity
  category: application
  description: Velocity application logs at LOG_LEVEL ERROR or above. Logs must include timestamp, LogLevel, and Message/StackTrace fields so exception class names and stack traces are visible.
detection:
  selection_level:
    LogLevel|in:
      - 'ERROR'
      - 'Error'
      - 'error'
      - 'CRITICAL'
      - 'FATAL'
  selection_exception:
    Message|contains:
      - 'org.apache.velocity.exception.ParseErrorException'
      - 'ParseErrorException'
      - 'org.apache.velocity.exception.MethodInvocationException'
      - 'MethodInvocationException'
      - 'org.apache.velocity.exception.ResourceNotFoundException'
      - 'ResourceNotFoundException'
      - 'org.apache.velocity.exception.VelocityException'
      - 'VelocityException'
      - 'org.apache.velocity.exception.TemplateInitException'
      - 'TemplateInitException'
      - 'org.apache.velocity.exception.VelocityRuntimeException'
      - 'VelocityRuntimeException'
      - 'org.apache.velocity.exception.ParseException'
      - 'ParseException'
      - 'VelocityEngineException'
      - 'VelocityException:'
  condition: selection_level and selection_exception
falsepositives:
  - Legitimate template errors caused by developer mistakes, malformed templates in staging, or expected runtime failures during template updates.
  - Automated testing, CI pipelines, or template compilation tasks that intentionally trigger parsing or initialization errors.
level: high

---
# Arquivo: B.yml
title: Velocity Template Engine Exception Indicating SSTI Attempt
id: 5e8f3b1c-2d7a-4e9f-b4c1-7a3e2d5f8b16
status: experimental
description: >
  Detects Apache Velocity template engine exception class names in application
  error logs that are emitted when user-controlled input causes the Velocity
  engine to fail during template parsing, resource loading, or method
  invocation. Velocity is a Java-based server-side template engine; if
  attacker-supplied input reaches the Velocity evaluation context without
  sanitisation, the attacker can inject Velocity directives and syntax to
  enumerate server-side objects, perform open redirects via HttpServletResponse,
  read remote files via the #evaluate and #import directives, and ultimately
  execute arbitrary OS commands by obtaining a reference to java.lang.Runtime
  through the class inspection interface. Malformed or boundary-testing
  injection payloads frequently trigger ParseErrorException when the injected
  syntax is structurally invalid, VelocityException for generic engine
  failures, or MethodInvocationException when an injected method call resolves
  but fails at runtime. The presence of any of these exception class names at
  ERROR level is a strong indicator of active SSTI probing or exploitation.
  Requires Velocity application error logging to be enabled at LOG_LEVEL ERROR
  or above and the log stream forwarded to the SIEM; applications that suppress
  exception output or redirect ERROR logs to an un-ingested sink will not
  surface these events.
references:
  - https://antgarsil.github.io/posts/velocity/
  - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
author: Senior Threat Detection Engineer
date: 2026-05-25
tags:
  - attack.initial_access
  - attack.execution
  - attack.t1190
  - attack.t1059
logsource:
  product: velocity
  category: application
  definition: >
    Requirements: application error logging must be enabled at LOG_LEVEL
    ERROR or above and the Velocity engine exception output must be included
    in the log stream forwarded to the SIEM. Applications that suppress
    stack traces in production logs or route ERROR output to a sink not
    ingested by the pipeline will not surface these events.
detection:
  keywords:
    - 'ParseErrorException'
    - 'VelocityException'
    - 'MethodInvocationException'
    - 'ResourceNotFoundException'
    - 'org.apache.velocity.exception'
  condition: keywords
falsepositives:
  - Legitimate template authoring errors introduced by developers who
    submit syntactically invalid Velocity templates during development,
    staging, or testing workflows where user-editable template content
    is a designed application feature.
  - CMS or email-template platforms that expose Velocity syntax to
    end users for personalisation, where a benign user makes a syntax
    error in a template expression, producing a ParseErrorException
    without any malicious intent.
level: medium

---
# Arquivo: C.yml
title: Velocity Template Engine Exceptions
id: a7d38e91-62c4-4b82-8df1-3e4b7a1e2f1d
status: experimental
description: Detects Velocity template engine exceptions in application logs. When triggered by user-controlled input, these typically indicate Server-Side Template Injection (SSTI) attempts that can lead to remote code execution. Note that this detection requires application logs to be ingested at LOG_LEVEL ERROR or above.
references:
- [https://antgarsil.github.io/posts/velocity/](https://antgarsil.github.io/posts/velocity/)
- [https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs](https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs)
author: Senior Threat Detection Engineer
date: 2026/06/08
tags:
- attack.initial_access
- attack.t1190
logsource:
product: velocity
category: application
detection:
selection:
- 'VelocityException'
- 'ParseErrorException'
- 'TemplateInitException'
- 'MethodInvocationException'
- 'ResourceNotFoundException'
condition: selection
falsepositives:
- Legitimate syntax errors in newly deployed templates or application misconfigurations
level: medium

---
# Arquivo: D.yml
title: Velocity Template Engine Exceptions in Application Error Logs
id: 5bbd9d03-5d24-4a3e-9d31-5bb6f0e6d2e1
status: experimental
description: Detects Velocity template engine exception class names in application logs, which may indicate server-side template injection attempts. This rule assumes logs are emitted at LOG_LEVEL ERROR or higher.
references:

* [https://antgarsil.github.io/posts/velocity/](https://antgarsil.github.io/posts/velocity/)
* [https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs](https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs)
  logsource:
  product: velocity
  category: application
  definition: Requires application error logging at LOG_LEVEL ERROR or above.
  detection:
  selection:
  message|re: '(?i)\b(?:org.apache.velocity.exception.)?(?:ParseErrorException|VelocityException|TemplateInitException)\b'
  condition: selection
  falsepositives:
* Legitimate template parsing or initialization failures during development or testing
* Benign rendering errors caused by malformed templates or configuration issues
  level: medium
  tags:
* attack.execution
* attack.t1059.007


---
# Arquivo: E.yml
title: Velocity Template Engine Exception Indicating SSTI
id: e5f6a7b8-c9d0-41e2-83f4-5a6b7c8d9e0f
status: experimental
description: Detects Velocity template engine exceptions in application logs, which may indicate Server-Side Template Injection (SSTI) attempts leading to remote code execution.
references:
    - https://antgarsil.github.io/posts/velocity/
    - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
author: Senior Threat Detection Engineer
date: 2026-06-08
logsource:
    product: velocity
    category: application
    definition: 'Requires error logs at LOG_LEVEL ERROR or above'
detection:
    selection:
        exception_class|contains:
            - 'ParseErrorException'
            - 'VelocityException'
            - 'ResourceNotFoundException'
            - 'MethodInvocationException'
            - 'TemplateInitException'
    condition: selection
falsepositives:
    - Legitimate template syntax errors during development or deployment
level: high
tags:
    - attack.initial_access
    - attack.t1190
    - attack.t1059

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