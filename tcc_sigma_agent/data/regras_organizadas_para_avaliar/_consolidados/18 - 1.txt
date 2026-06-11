# Arquivo: A.yml
title: Suspicious Application-Level Error Indicators
id: a6c5b9f3-2d91-4e1a-9c3e-5b8d7e6f2a0b
status: experimental
description: Detects suspicious application-level error indicators (e.g., SQL syntax exceptions, deserialization failures) that may indicate exploitation attempts of vulnerabilities such as SQL injection, XXE, SSTI, or insecure deserialization.
references:
  - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
author: Sigma Rule Generator
date: 2026-06-03
tags:
  - attack.initial-access
  - attack.t1190
logsource:
  category: application
  definition: 'Requires application error logs (e.g., stack traces, exception messages) with log level ERROR or higher.'
detection:
  keywords:
    - 'You have an error in your SQL syntax'
    - 'Unclosed quotation mark'
    - 'quoted string not properly terminated'
    - 'ORA-'
    - 'SQL syntax'
    - 'Unexpected token'
    - 'Invalid argument'
    - 'Deserialization'
    - 'SAXParseException'  # XXE
    - 'External DTD'
    - 'Template parsing error'
  condition: keywords
falsepositives:
  - Legitimate application errors resulting from malformed input or edge cases (e.g., empty IN() clause causing SQL syntax errors).
level: high

---
# Arquivo: B.yml
title: Application Server Error Log Anomalies Indicative of Attacks
id: 7c9f1a2b-6d4e-4f8a-9b3c-0d1e2f3a4b5c
status: experimental
description: Detects anomalous or suspicious application server error log entries (stack traces, unhandled exceptions, database error strings, directory traversal indicators, and repeated 5xx errors) that may indicate probing, exploitation attempts, or successful attacks. Based on hunting guidance for application server error logs.
author: Daniela
date: 2026-06-03
references:
  - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
logsource:
  product: webserver
  service: application
  category: web_access
detection:
  selection_error_strings:
    Message|contains:
      - "Unhandled Exception"
      - "StackTrace"
      - "Traceback (most recent call last)"
      - "NullReferenceException"
      - "TypeError"
      - "ReferenceError"
      - "Fatal error"
      - "Segmentation fault"
      - "ORA-"
      - "SQL syntax"
      - "You have an error in your SQL syntax"
      - "mysql_fetch_array"
      - "PDOException"
      - "Permission denied"
      - "Access denied"
      - "FileNotFoundError"
  selection_stacktrace:
    Message|contains:
      - "at "
      - "in <module>"
      - "line "
  selection_traversal:
    Uri|contains:
      - "../"
      - "..\\"
      - "%2e%2e%2f"
      - "%2e%2e\\"
      - "/etc/passwd"
      - "boot.ini"
  selection_rce_indicators:
    Message|contains:
      - "eval("
      - "exec("
      - "system("
      - "popen("
      - "cmd.exe"
  selection_suspicious_useragent:
    UserAgent|contains:
      - "sqlmap"
      - "curl/"
      - "wget/"
      - "fuzz"
  selection_repeated_errors:
    CountByClientIP: ">5"
    Timeframe: "5m"
  condition: (selection_error_strings and (selection_stacktrace or selection_traversal or selection_rce_indicators or selection_suspicious_useragent)) or selection_repeated_errors
fields:
  - timestamp
  - ClientIP
  - Uri
  - HttpMethod
  - Status
  - Message
  - UserAgent
  - ServerName
falsepositives:
  - Development or staging environments with verbose error logging
  - Legitimate debugging sessions or automated health checks that trigger errors
  - Load or stress testing that produces repeated 5xx responses
level: high
tags:
  - attack.initial_access
  - attack.exploitation
  - detection.logging
  - web.application


---
# Arquivo: C.yml
title: Application Server - Runtime Exception as Application-Level Vulnerability IOC
id: 3b9e7f14-2a56-4c88-d031-5c7e8a4b2f19
status: experimental
description: |
    Detects runtime exceptions in application server logs that serve as
    application-level Indicators of Compromise (IOCs), per the Wix AppSec
    methodology: exceptions that should NEVER appear in securely-written
    production applications are proxies for exploitable vulnerabilities.

    Core inversion: instead of waiting for an attacker to exploit a flaw,
    hunt the runtime evidence that a flaw EXISTS. SQL syntax errors only occur
    with dynamic SQL; if user input "breaks" the query syntax, the application
    is vulnerable to SQL injection. The same logic applies to XXE, SSTI,
    and Java deserialization.

    Triaging an alert: in the stack trace, find the first non-generic class
    (not com.mysql.*, not java.sql.*, not org.springframework.*) — this is
    the custom application class containing the vulnerable code.

    Wix-measured false positive rates (production, 3000+ services):
      SQLi selections: ~74% FP (legitimate empty IN() / ORM edge cases)
      XXE + SSTI selections: 0% FP (100% detection accuracy)
      Deserialization: low FP (class version mismatch after deploys)
references:
    - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
    - https://attack.mitre.org/techniques/T1190/
    - https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
author: Security Team
date: 2026-05-25
tags:
    - attack.initial_access
    - attack.t1190       # Exploit Public-Facing Application
    - attack.execution
    - attack.t1059.007   # Command and Scripting Interpreter (SSTI → RCE)
    - attack.discovery
    - attack.t1083       # File and Directory Discovery (XXE → LFI)
logsource:
    category: application
    product: java
    definition: |
        Ingest application server error/exception logs (Tomcat, Spring Boot,
        WildFly, Jetty, etc.). The 'message' field must contain the full exception
        class name and stack trace. Ensure multiline log entries are aggregated
        into a single event before indexing.
detection:
    selection_sqli:
        # SQL syntax errors from JDBC drivers — only appear with dynamic SQL
        # "broken" by user input, indicating exploitable SQL injection
        message|contains:
            - 'SQLSyntaxErrorException'
            - 'MySQLSyntaxErrorException'
            - 'JdbcSQLSyntaxErrorException'    # H2
            - 'SQLGrammarException'             # Hibernate / Spring Data
            - 'BadSqlGrammarException'          # Spring JDBC Template
    selection_xxe:
        # XML parsing exception combined with DOCTYPE — attacker-supplied XML
        # containing external entity declaration reached the parser
        # contains|all ensures both: parser exception + DOCTYPE payload signal
        message|contains|all:
            - 'SAXParseException'
            - 'DOCTYPE'
    selection_ssti:
        # Template engine exceptions — should NEVER fire if user input is escaped
        # Wix observed 0% FP rate for these: any match is a real vulnerability
        message|contains:
            - 'freemarker.core.InvalidReferenceException'
            - 'freemarker.template.TemplateException'
            - 'org.thymeleaf.exceptions.TemplateProcessingException'
            - 'velocity.exception.ParseErrorException'
    selection_deserial:
        # Java deserialization failure — InvalidClassException means object graph
        # from untrusted input was deserialized; may be a failed gadget chain attempt
        message|contains:
            - 'java.io.InvalidClassException'
            - 'InvalidClassException: serialVersionUID'
    filter_deployment:
        # Suppress class version mismatches during rolling deployments
        # that fire InvalidClassException for non-deserialization reasons
        # Customize per your deployment tooling:
        # logger|contains: 'DeploymentManager'
        logger: null   # placeholder — tune with your deployment logger names
    condition: (1 of selection_*) and not filter_deployment
fields:
    - message
    - logger
    - level
    - thread
    - timestamp
falsepositives:
    - SQLGrammarException from legitimate ORM edge cases (empty IN() clause,
      missing nullable field, typo in named query) — 74% FP rate per Wix
    - SAXParseException+DOCTYPE from developer-submitted test XML payloads
      during authorized security assessments
    - InvalidClassException from class serialVersionUID mismatch after hot deploy
      (use filter_deployment to suppress known deployment logger contexts)
level: medium

---
# Arquivo: D.yml
title: Application Error Log SQL Syntax Exception
id: 6a8a0a6d-2e63-4d3f-a8d4-0f5f2d3c7e91
status: experimental
description: >
  Detects SQL syntax exceptions in application server error logs. These
  exceptions may indicate dynamically constructed SQL statements and can
  be an indicator of SQL injection vulnerabilities or active probing
  attempts against the application.
references:
  - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
author: OpenAI
date: 2026-06-03
tags:
  - attack.initial_access
  - attack.t1190
  - attack.credential_access
logsource:
  category: application
detection:
  selection:
    message|contains:
      - 'SQLSyntaxErrorException'
      - 'SQL syntax error'
      - 'You have an error in your SQL syntax'
      - 'syntax error at or near'
      - 'Incorrect syntax near'
      - 'quoted string not properly terminated'
      - 'Unclosed quotation mark after the character string'
  condition: selection
fields:
  - message
  - exception
  - stacktrace
  - service
  - application
  - source
falsepositives:
  - Application bugs
  - Database migration failures
  - Developer testing activities
level: high

---
# Arquivo: E.yml
title: Apache Velocity Server-Side Template Injection (SSTI) Indicators
id: 5792949f-cb1c-4b68-80f4-52d3080c326d
status: test
description: Detects specific Apache Velocity template engine exceptions within web or application server logs. These exceptions frequently surface when an adversary attempts Server-Side Template Injection (SSTI) by feeding malformed input fields parsed by an unvalidated template engine.
references:
    - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
    - https://antgarsil.github.io/posts/velocity/
author: Moti Harmats, Security Operations Center
date: 2023/02/11
modified: 2026/06/03
tags:
    - attack.initial_access
    - attack.t1190 # Exploit Public-Facing Application
logsource:
    category: application
    product: velocity
detection:
    keywords:
        - 'ParseErrorException'
        - 'VelocityException'
        - 'TemplateInitException'
    condition: keywords
falsepositives:
    - Legitimate application runtime bugs where dynamic code mistyped key variables or loaded broken template path syntax.
    - Missing or misconfigured internal `.vm` reference files.
level: high

---
# Arquivo original: java_local_file_read.yml
title: Potential Local File Read Vulnerability In JVM Based Application
id: e032f5bc-4563-4096-ae3b-064bab588685
status: test
description: |
    Detects potential local file read vulnerability in JVM based apps.
    If the exceptions are caused due to user input and contain path traversal payloads then it's a red flag.
references:
    - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
author: Moti Harmats
date: 2023-02-11
tags:
    - attack.initial-access
    - attack.t1190
logsource:
    category: application
    product: jvm
    definition: 'Requirements: application error logs must be collected (with LOG_LEVEL=ERROR and above)'
detection:
    keywords_local_file_read:
        '|all':
            - 'FileNotFoundException'
            - '/../../..'
    condition: keywords_local_file_read
falsepositives:
    - Application bugs
level: high

---