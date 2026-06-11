# Arquivo: A.yml
title: Application-Level Vulnerability Exploitation Attempt
id: 11111111-1111-1111-1111-111111111111
status: test
description: Detects application-level error patterns (SQL syntax errors, deserialization exceptions, XXE parsing errors, template injection errors) in application server logs, which may indicate exploitation attempts against known vulnerability classes such as SQL Injection, Insecure Deserialization, XXE, or SSTI.
references:
    - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
author: Moti Harmats (Wix Engineering), Detection Engineering Team
date: 2022-12-07
modified: 2023-09-11
tags:
    - attack.initial-access
    - attack.t1190
    - attack.t1134
    - attack.t1059
logsource:
    category: application
    definition: 'Application error logs must be collected with LOG_LEVEL=ERROR and above for each service (e.g., Java, Node.js, Python, .NET, Ruby, PHP).'
detection:
    selection_sqli:
        message|contains:
            - 'SQL syntax'
            - 'You have an error in your SQL syntax'
            - 'Unclosed quotation mark'
            - 'quoted string not properly terminated'
            - 'ORA-'
            - 'com.mysql.jdbc.exceptions.jdbc4.MySQLSyntaxErrorException'
            - 'SQLException'
    selection_deserialization:
        message|contains:
            - 'Deserialization'
            - 'SerializationException'
            - 'InvalidClassException'
            - 'StreamCorruptedException'
            - 'JsonParseException'
            - 'JsonMappingException'
    selection_xxe:
        message|contains:
            - 'SAXParseException'
            - 'External DTD'
            - 'DOCTYPE'
            - 'XXE'
            - 'XMLStreamException'
            - 'ParserConfigurationException'
    selection_ssti:
        message|contains:
            - 'Template parsing error'
            - 'TemplateSyntaxError'
            - 'Freemarker template error'
            - 'VelocityException'
            - 'Jinja2.exceptions.TemplateSyntaxError'
            - 'Thymeleaf Template Processing Error'
    condition: 1 of selection_*
falsepositives:
    - Legitimate application errors due to edge cases (e.g., empty IN() clause causing SQL syntax error).
    - Typos or bugs in dynamic query construction.
    - User-supplied input that inadvertently triggers parsing errors without exploitation.
level: high

---
# Arquivo: B.yml
title: Application Error Logs Indicating Potential Exploitable Vulnerabilities
id: 8d2e5a94-0d0a-4f6e-9b3e-c6d6a0f4b8f1
status: experimental
description: >
  Detects application server error log entries that may indicate active exploitation
  attempts or the presence of exploitable vulnerabilities. Based on the approach
  described by Wix Engineering, which monitors application runtime exceptions such
  as SQL syntax errors, deserialization failures, XXE parser exceptions, and
  server-side template injection errors as application-level indicators of
  compromise (IOCs). :contentReference[oaicite:0]{index=0}
references:
  - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
author: OpenAI
date: 2026-06-06
tags:
  - attack.initial_access
  - attack.discovery
  - attack.t1190
  - attack.t1059
  - detection.application
logsource:
  product: application
  category: application
detection:
  selection_sqli:
    Message|contains:
      - 'SQL syntax'
      - 'SQLException'
      - 'You have an error in your SQL syntax'
      - 'ORA-'
      - 'PostgreSQL'
      - 'mysql syntax error'
  selection_xxe:
    Message|contains:
      - 'DOCTYPE is disallowed'
      - 'External Entity'
      - 'SAXParseException'
      - 'XML parser exception'
  selection_ssti:
    Message|contains:
      - 'TemplateSyntaxError'
      - 'TemplateParsingException'
      - 'Freemarker template error'
      - 'Jinja2'
      - 'VelocityException'
  selection_deserialization:
    Message|contains:
      - 'InvalidClassException'
      - 'StreamCorruptedException'
      - 'SerializationException'
      - 'deserialization error'
  condition: 1 of selection_*
falsepositives:
  - Application bugs and coding errors
  - Misconfigured database queries
  - Invalid XML or template input from legitimate users
  - Development or testing activity
level: medium

---
# Arquivo: C.yml
title: Application Server - Python Web Framework Runtime Exception as Vulnerability IOC
id: 9c1e4a27-7f53-4b80-a061-2d8e3c6b5f14
status: experimental
description: |
    Companion rule to the Java application server exception IOC rule, extending
    the Wix AppSec methodology to Python web frameworks (Django, Flask, FastAPI,
    SQLAlchemy). Detects runtime exceptions that should never appear in securely
    written production applications, indicating active vulnerability probing or
    existing exploitable code paths.

    Core methodology (Wix Engineering):
    SQL syntax errors only occur with dynamic SQL; if user input "breaks" the
    query, the application is vulnerable. The same logic applies to XML parsing
    (XXE) and template engine errors (SSTI).

    Three vulnerability classes covered for Python stacks:

    1. selection_sqli — SQL syntax errors from Python database adapters and ORMs:
       Django ORM (django.db.utils.ProgrammingError), SQLAlchemy (sqlalchemy.exc.
       ProgrammingError), psycopg2 (psycopg2.errors.SyntaxError), PyMySQL/MySQLdb.
       These exceptions indicate user input reached a dynamically-built SQL query.

    2. selection_xxe — Python XML parsing exception combined with DOCTYPE keyword.
       xml.etree.ElementTree.ParseError and lxml.etree.XMLSyntaxError raised when
       a parser processes attacker-supplied XML with external entity declarations.
       Wix AppSec observed 0% false positive rate for XXE-class detections.

    3. selection_ssti — Jinja2 / Django template engine exceptions triggered by
       user-controlled input that reached template rendering. jinja2.exceptions.
       TemplateSyntaxError and UndefinedError should never fire from user data
       if templates are built correctly. Near-zero FP rate per Wix methodology.
references:
    - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
    - https://attack.mitre.org/techniques/T1190/
    - https://owasp.org/www-community/attacks/Server_Side_Template_Injection
author: Security Team
date: 2026-05-25
tags:
    - attack.initial_access
    - attack.t1190       # Exploit Public-Facing Application
    - attack.execution
    - attack.t1059.006   # Command and Scripting Interpreter: Python (SSTI → RCE)
    - attack.discovery
    - attack.t1083       # File and Directory Discovery (XXE → LFI)
logsource:
    category: application
    product: python
    definition: |
        Python WSGI/ASGI application server logs (Gunicorn, uWSGI, uvicorn,
        Waitress). The 'message' field must include the exception class name and
        traceback. Ensure multiline log entries are aggregated before indexing.
        Compatible with Django, Flask, FastAPI, and any SQLAlchemy-backed app.
detection:
    selection_sqli:
        # SQL syntax errors from Python ORMs and database adapters —
        # only occur with dynamic SQL; user input breaking query = exploitable
        message|contains:
            - 'django.db.utils.ProgrammingError'
            - 'sqlalchemy.exc.ProgrammingError'
            - 'sqlalchemy.exc.OperationalError'
            - 'psycopg2.errors.SyntaxError'
            - 'MySQLdb.ProgrammingError'
            - 'pymysql.err.ProgrammingError'
    selection_xxe:
        # XML parsing exception with DOCTYPE — attacker-supplied XML reached parser
        # contains|all ensures both the parser exception AND DOCTYPE signal are present
        message|contains|all:
            - 'xml.etree.ElementTree.ParseError'
            - 'DOCTYPE'
    selection_xxe_lxml:
        message|contains|all:
            - 'lxml.etree.XMLSyntaxError'
            - 'DOCTYPE'
    selection_ssti:
        # Jinja2 / Django template exceptions from user-controlled input —
        # should NEVER fire in production if templates are correctly parameterised
        message|contains:
            - 'jinja2.exceptions.TemplateSyntaxError'
            - 'jinja2.exceptions.UndefinedError'
            - 'django.template.exceptions.TemplateSyntaxError'
            - 'jinja2.exceptions.TemplateNotFound'
    filter_dev_reload:
        # Suppress Jinja2 errors triggered by live-reload during development
        # Populate with known dev/staging hostnames or logger names:
        # logger|contains:
        #     - 'werkzeug'
        #     - 'django.request'   # only in DEBUG=True environments
        logger: null   # placeholder — tune for dev environments
    condition: (1 of selection_*) and not filter_dev_reload
fields:
    - message
    - logger
    - level
    - pathname
    - funcName
    - lineno
falsepositives:
    - SQLAlchemy OperationalError from legitimate connection pool timeouts
      or schema migration edge cases (triage via traceback pathname field)
    - Jinja2 TemplateNotFound from misrouted requests to non-existent views
    - Development environments with DEBUG=True exposing all framework errors
    - CI pipeline test runs that intentionally trigger exception paths
level: medium

---
# Arquivo: D.yml
title: Application Server Error Log Indicators for Hunting
id: 6f4d2b8e-2026-app-server-error-hunting
status: experimental
description: Detects anomalous application server error log entries and HTTP responses that often indicate probing, exploitation attempts, or application faults useful for threat and vulnerability hunting. Flags stack traces, framework exceptions, SQL/database error messages, file inclusion or directory traversal payloads, and repeated 5xx responses from the same client.
author: Daniela
date: 2026-06-06
references:
  - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
logsource:
  product: webserver
  service: http
  category: web_access
detection:
  selection_http_error:
    Status:
      - 500
      - 502
      - 503
      - 504
      - 400
  selection_stacktrace_response:
    ResponseBody|re:
      - '(?i)(exception|stacktrace|traceback|at\s+[A-Za-z0-9_\.]+:\d+|java\.lang\.|org\.springframework|System\.NullReferenceException|Unhandled Exception)'
  selection_db_error_response:
    ResponseBody|re:
      - '(?i)(SQL syntax.*MySQL|You have an error in your SQL syntax|mysql_fetch_|Warning: pg_|PG::SyntaxError|ORA-|SQLSTATE

\[|ODBC SQL Server Driver|Unclosed quotation mark after the character string)'
  selection_lfi_rfi_traversal:
    RequestUri|re:
      - '(\.\./|\%2e\%2e|/etc/passwd|/proc/self/environ|/windows/win.ini)'
      - '(?i)(\binclude\b.*\bhttp:|file:\/\/|php://input|expect://)'
  selection_sqli_payloads:
    RequestUri|re:
      - '(?i)(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|\bor\s+\'1\'=\'1\b|--\s|/\*.*\*/|sleep\(|benchmark\()'
  selection_suspicious_useragent:
    UserAgent|re:
      - '(?i)(sqlmap|nikto|acunetix|nessus|curl|wget|python-requests|libwww-perl|fuzz|scanner)'
  selection_long_uri_or_params:
    RequestUri|re:
      - '.{200,}'
  selection_repeated_errors_from_ip:
    CountByClientIP: ">5"
    Timeframe: "5m"
  condition: (selection_http_error and (selection_stacktrace_response or selection_db_error_response or selection_lfi_rfi_traversal or selection_sqli_payloads or selection_long_uri_or_params)) or (selection_suspicious_useragent and selection_repeated_errors_from_ip)
fields:
  - timestamp
  - ClientIP
  - HttpMethod
  - Uri
  - Status
  - UserAgent
  - ResponseBody
  - Referer
  - Host
falsepositives:
  - Development or staging environments with verbose error pages enabled.
  - Legitimate scanners and vulnerability assessments run by authorized teams.
  - Large legitimate requests (file uploads, long query strings) from trusted clients.
level: medium
tags:
  - web.application
  - detection.logging
  - attack.discovery
  - attack.injection
  - hunting
notes: |
  - Tune: suppress alerts from known internal scanners, developer hosts, and non-production environments; adjust repetition thresholds and URI length to match baseline traffic.
  - Investigate: capture full request/response pairs, stack traces, parameter values, and correlate with authentication context, recent deployments, and WAF/IDS alerts.
  - Remediation: ensure production apps do not expose stack traces, sanitize error messages, fix vulnerable endpoints, and apply WAF rules for matched payloads.


---
# Arquivo: E.yml
title: Application Server SQL Syntax Error Exception
id: a87dbf0a-6f5e-4c74-8b63-d14a1e9447e1
status: experimental
description: |
  Detects common SQL syntax exceptions within application error logs. As detailed by Wix Engineering, properly written and parameterized queries should not throw syntax errors in production. The presence of these errors often indicates dynamic query manipulation, highlighting either a direct SQL Injection attempt or a newly exposed application vulnerability.
author: Gemini
date: 2026/06/06
references:
    - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
tags:
    - attack.initial_access
    - attack.t1190
logsource:
    category: application
detection:
    keywords:
        - 'SQLSyntaxErrorException'
        - 'MySQLSyntaxErrorException'
        - 'You have an error in your SQL syntax'
        - 'System.Data.SqlClient.SqlException'
        - 'SQL syntax error'
        - 'syntax error at or near'
        - 'ORA-00900: invalid SQL statement'
    condition: keywords
falsepositives:
    - Badly formatted dynamic queries (e.g., unhandled empty IN() clauses).
    - Typographical errors or plain bugs in newly deployed application code.
    - Edge cases in ORM library generation causing malformed queries.
level: medium

---
# Arquivo original: nodejs_rce_exploitation_attempt.yml
title: Potential RCE Exploitation Attempt In NodeJS
id: 97661d9d-2beb-4630-b423-68985291a8af
status: test
description: Detects process execution related errors in NodeJS. If the exceptions are caused due to user input then they may suggest an RCE vulnerability.
references:
    - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
author: Moti Harmats
date: 2023-02-11
tags:
    - attack.initial-access
    - attack.t1190
logsource:
    category: application
    product: nodejs
    definition: 'Requirements: application error logs must be collected (with LOG_LEVEL=ERROR and above)'
detection:
    keywords:
        - 'node:child_process'
    condition: keywords
falsepositives:
    - Puppeteer invocation exceptions often contain child_process related errors, that doesn't necessarily mean that the app is vulnerable.
level: high

---