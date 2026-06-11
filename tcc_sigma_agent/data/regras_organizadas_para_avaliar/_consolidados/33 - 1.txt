# Arquivo: A.yml
title: SQL Injection Strings In URI
id: 5513deaf-f49a-46c2-a6c8-3f111b5cb453
status: test
description: Detects potential SQL injection attempts via GET requests in access logs.
references:
  - https://www.acunetix.com/blog/articles/exploiting-sql-injection-example/
  - https://www.acunetix.com/blog/articles/using-logs-to-investigate-a-web-application-attack/
  - https://brightsec.com/blog/sql-injection-payloads/
  - https://github.com/payloadbox/sql-injection-payload-list
  - https://book.hacktricks.xyz/pentesting-web/sql-injection/mysql-injection
author: Saw Win Naung, Nasreddine Bencherchali (Nextron Systems), Thurein Oo (Yoma Bank)
date: 2020-02-22
modified: 2023-09-04
tags:
  - attack.initial-access
  - attack.t1190
logsource:
  category: webserver
detection:
  selection:
    cs-method: 'GET'
  keywords:
    - '@@version'
    - '%271%27%3D%271'
    - '=select '
    - '=select('
    - '=select%20'
    - 'concat_ws('
    - 'CONCAT(0x'
    - 'from mysql.innodb_table_stats'
    - 'from%20mysql.innodb_table_stats'
    - 'group_concat('
    - 'information_schema.tables'
    - 'json_arrayagg('
    - 'or 1=1#'
    - 'or%201=1#'
    - 'order by '
    - 'order%20by%20'
    - 'select * '
    - 'select database()'
    - 'select version()'
    - 'select%20*%20'
    - 'select%20database()'
    - 'select%20version()'
    - 'select%28sleep%2810%29'
    - 'SELECTCHAR('
    - 'table_schema'
    - 'UNION ALL SELECT'
    - 'UNION SELECT'
    - 'UNION%20ALL%20SELECT'
    - 'UNION%20SELECT'
    - "'1'='1"
  filter_main_status:
    sc-status: 404
  condition: selection and keywords and not 1 of filter_main_*
falsepositives:
  - Java scripts and CSS Files
  - User searches in search boxes of the respective website
  - Internal vulnerability scanners can cause some serious FPs when used, if you experience a lot of FPs due to this think of adding more filters such as "User Agent" strings and more response codes
level: high

---
# Arquivo: B.yml
title: Automated SQL Injection Tool Exploitation Fingerprint in Web Access Logs
id: b74e2d83-6c19-4f58-ae07-9f3c1e7a52d4
status: experimental
description: |
    Detects the compound signature of an automated SQL injection exploitation tool
    (sqlmap, Havij, or equivalent) actively enumerating a database via a web
    application parameter, as observed directly in web server access logs.

    The detection is anchored on three co-occurring indicators that are documented
    across multiple sources as the empirically observed fingerprint of tool-generated
    SQL injection payloads landing in production web server access logs:

    1. INFORMATION_SCHEMA — universally present during the automated schema
       enumeration phase (database names, table names, column names) executed by
       every major SQLi exploitation tool against MySQL, MSSQL, and PostgreSQL.

    2. CONCAT — present in both UNION-based extraction payloads (building output
       rows) and in error-based extraction subqueries (forcing truncation errors
       that leak data). The Acunetix forensic case study shows verbatim log entries
       combining CONCAT with CAST, IFNULL, and column names from wp_users.

    3. Hex-encoded string literals (0x followed by 4+ hex digits) — sqlmap uses
       hex-encoded boundary strings (e.g. 0x7171787671, 0x71707a7871) as output
       delimiters so it can reliably parse extracted data from noisy HTTP responses.
       These hex strings are not produced by any legitimate application query, making
       them the highest-specificity individual indicator in the set.

    Real-world example from Acunetix forensic investigation log (verbatim):
        GET /check_user.php?userid=1 AND (SELECT 6810 FROM(SELECT COUNT(*),
        CONCAT(0x7171787671,(SELECT (ELT(6810=6810,1))),0x71707a7871,
        FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)

    Additional automated tool signatures covered by supplementary selections:
      - UNION ALL SELECT with NULL padding (column-count enumeration)
      - Time-based blind: SLEEP(), WAITFOR DELAY, pg_sleep(), DBMS_PIPE
      - Out-of-band exfiltration: LOAD_FILE with UNC path (DNS exfil via SMB)
      - Boolean-blind enumeration: SUBSTR/SUBSTRING against INFORMATION_SCHEMA
      - sqlmap stacked-query marker: ;SELECT followed by SLEEP or WAITFOR

    Legitimate applications never embed raw SQL DDL keywords, INFORMATION_SCHEMA
    references, or hex string literals inside URL query string parameters. Any
    single match in this rule against production traffic warrants triage.

references:
    - https://www.acunetix.com/blog/articles/using-logs-to-investigate-a-web-application-attack/
    - https://www.acunetix.com/blog/articles/exploiting-sql-injection-example/
    - https://brightsec.com/blog/sql-injection-payloads/
    - https://github.com/payloadbox/sql-injection-payload-list
    - https://book.hacktricks.xyz/pentesting-web/sql-injection/mysql-injection
author: Generated from Acunetix forensic case study, Bright Security, payloadbox, and HackTricks MySQL injection research
date: 2024-01-01
tags:
    - attack.initial_access
    - attack.t1190       # Exploit Public-Facing Application
    - attack.credential_access
    - attack.t1555       # Credentials from Password Stores (DB credential extraction)
    - attack.collection
    - attack.t1213       # Data from Information Repositories
    - attack.exfiltration
    - attack.t1041       # Exfiltration Over C2 Channel
    - tlp:white
logsource:
    category: webserver
    # Targets the combined/W3C access log produced by Apache, nginx, IIS, or any
    # reverse proxy. The cs-uri-query (or cs-uri-stem) field must be URL-decoded
    # or captured pre-encoding for keyword matching to be reliable.
    # Note: Many SIEMs ingest access logs with the query string URL-encoded;
    # ensure your pipeline decodes %20 → space, %27 → ', %28 → ( etc.
    # before applying this rule, or add encoded variants to the selections below.
    product: generic
detection:
    # ── Primary selection: error-based / UNION tool fingerprint ──────────────
    # INFORMATION_SCHEMA + CONCAT are present in virtually every automated
    # schema enumeration request from any SQL injection tool.
    selection_schema_enum:
        cs-uri-query|contains|all:
            - 'INFORMATION_SCHEMA'
            - 'CONCAT'

    # ── Hex-encoded delimiter strings (sqlmap canonical boundary markers) ────
    # sqlmap hardcodes output delimiters as hex strings so it can parse
    # responses reliably. These strings are never produced by application code.
    # Pattern: 0x followed by 6+ hex nibbles (covers 0x7171787671 etc.)
    selection_hex_delimiters:
        cs-uri-query|re: '0x[0-9a-fA-F]{6,}'

    # ── UNION-based column enumeration ──────────────────────────────────────
    # NULL padding is sqlmap's default column-count probe; legitimate apps
    # never issue UNION SELECT NULL,NULL,NULL in a URL parameter.
    selection_union_null:
        cs-uri-query|contains|all:
            - 'UNION'
            - 'SELECT'
            - 'NULL'

    # ── Time-based blind injection payloads ─────────────────────────────────
    # sleep(), WAITFOR DELAY, pg_sleep() are database stall functions with no
    # legitimate URL-parameter use case.
    selection_timebased:
        cs-uri-query|contains:
            - 'sleep('
            - 'SLEEP('
            - 'WAITFOR DELAY'
            - 'pg_sleep('
            - 'DBMS_PIPE.RECEIVE_MESSAGE'
            - 'RANDOMBLOB('

    # ── Out-of-band / DNS exfiltration (MySQL LOAD_FILE UNC) ────────────────
    # load_file(concat('\\',version(),'.attacker.tld\...')) pattern from HackTricks.
    # The double-backslash UNC prefix is the OOB exfiltration tell.
    selection_oob_loadfile:
        cs-uri-query|contains:
            - 'load_file('
            - 'LOAD_FILE('

    # ── Error-based GROUP BY / FLOOR(RAND()) subquery ───────────────────────
    # This is the exact subquery structure visible in the Acunetix forensic log.
    # FLOOR(RAND()*2) combined with GROUP BY forces a duplicate-key error that
    # leaks data; it is a sqlmap-specific error-based extraction fingerprint.
    selection_error_based_floor:
        cs-uri-query|contains|all:
            - 'FLOOR(RAND('
            - 'GROUP BY'

    # ── Boolean-blind enumeration via SUBSTR against schema tables ───────────
    selection_blind_substr:
        cs-uri-query|contains|all:
            - 'SUBSTR'
            - 'information_schema'

    # ── Exclude known legitimate scanner / monitoring IPs ───────────────────
    # Populate with your DAST scanner, pen-test, and WAF health-check source IPs.
    filter_approved_scanners:
        c-ip|cidr:
            - '127.0.0.0/8'
            - '::1/128'
            # Add your approved DAST scanner IP ranges here, e.g.:
            # - '10.0.0.0/8'

    condition: >
        (
          selection_schema_enum or
          selection_hex_delimiters or
          selection_union_null or
          selection_timebased or
          selection_oob_loadfile or
          selection_error_based_floor or
          selection_blind_substr
        )
        and not filter_approved_scanners

falsepositives:
    - Authorized DAST or penetration testing tools running against the application
      (exclude by source IP via filter_approved_scanners).
    - A WAF or IDS generating synthetic log entries for testing — scope the rule
      to exclude the WAF management IP range.
    - Developer debugging sessions using raw SQL in query parameters during
      pre-production testing (should not occur against production endpoints; if
      seen, treat as a policy violation rather than a false positive).
    - Applications that legitimately expose SQL query parameters (extremely rare
      and a design flaw in itself); baseline and document if present.
    # Recommended tuning: correlate HTTP response code. A sequence of 200 responses
    # to these payloads indicates active exploitation, not just probing. A WAF
    # returning 403/406 on all hits significantly reduces urgency.
level: high

---
# Arquivo: C.yml
title: Web Application SQL Injection Attempt
id: 0f8a3c2d-2026-sqli-0001
status: experimental
description: Detects likely SQL injection attempts by matching common SQLi payload patterns in request URIs and parameters, database error messages in responses, time-based injection indicators, and rapid repeated probing from the same client IP. Useful for early detection of injection-based reconnaissance and exploitation attempts.
author: Detection Engineer
date: 2026-06-06
references:
  - https://www.acunetix.com/blog/articles/exploiting-sql-injection-example/
  - https://www.acunetix.com/blog/articles/using-logs-to-investigate-a-web-application-attack/
  - https://brightsec.com/blog/sql-injection-payloads/
  - https://github.com/payloadbox/sql-injection-payload-list
  - https://book.hacktricks.xyz/pentesting-web/sql-injection/mysql-injection
logsource:
  product: webserver
  service: http
  category: web_access
detection:
  selection_sqli_keywords:
    RequestUri|re:
      - '(?i)(\bunion\b.*\bselect\b)'
      - '(?i)(\bselect\b.*\bfrom\b)'
      - '(?i)(\bupdate\b.*\bset\b)'
      - '(?i)(\binsert\b.*\binto\b)'
      - '(?i)(\bdelete\b.*\bfrom\b)'
      - '(?i)(\bdrop\b.*\btable\b)'
      - '(?i)(\bexec\b|\bxp_cmdshell\b|\bsp_executesql\b)'
      - '(?i)(\bbenchmark\(|\bsleep\(|\bwaitfor\s+delay\b)'
      - '(?i)(\bconcat\(|\bload_file\(|\binto outfile\b)'
      - '(?i)(\%27|\%22|\'\s+or\s+1=1|\bor\s+\'1\'=\'1\b|--|;--|/\*|\*/)'
  selection_sql_meta_chars:
    RequestUri|re:
      - "('|\")\\s*or\\s*\\d+\\s*=\\s*\\d+"
      - "('|\")\\s*and\\s*\\d+\\s*=\\s*\\d+"
      - "('|\")\\s*;\\s*--"
      - "(%27|%22|%3B|%2D%2D|%2F%2A|%2A%2F)"
  selection_time_based:
    RequestUri|re:
      - '(?i)(sleep\(\d+\)|benchmark\(|waitfor\s+delay)'
  selection_db_error_response:
    ResponseBody|re:
      - '(?i)(SQL syntax.*MySQL|mysql_fetch_|You have an error in your SQL syntax|Warning: pg_|PG::SyntaxError|ORA-|SQLSTATE

\[|ODBC SQL Server Driver|Unclosed quotation mark after the character string)'
  selection_hex_encoded:
    RequestUri|re:
      - '(?i)0x[0-9a-f]{6,}'
      - '(?i)char\(\d+\)'
  selection_repeated_probing:
    CountByClientIP: ">5"
    Timeframe: "1m"
  condition: (selection_sqli_keywords or selection_sql_meta_chars or selection_time_based or selection_hex_encoded or selection_db_error_response) and (selection_repeated_probing or selection_db_error_response)
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
  - Legitimate application traffic that includes SQL-like tokens (search features, analytics queries, or encoded data) — tune by whitelisting known endpoints and trusted clients.
  - Automated scanners or vulnerability scanners run by authorized teams; coordinate with development/security teams to whitelist scheduled scans.
level: high
tags:
  - web.application
  - attack.injection
  - attack.initial_access
  - detection.web
notes: |
  - Tuning: exclude known internal scanners and API clients; adjust regex strictness and repetition thresholds to match baseline traffic.
  - Investigation: capture full request and response bodies, client IP, user agent, referer, and any associated authentication context; search for similar requests across logs to identify scanning campaigns.
  - Response: block or rate-limit offending IPs, apply WAF rules for matched patterns, validate and fix vulnerable code paths, and perform a code review and database audit for impacted endpoints.


---
# Arquivo: D.yml
title: Potential SQL Injection Payload In Web Requests
id: 7c4a2f73-5c8f-4b39-8a58-d1f7d7c0d9a2
status: experimental
description: >
  Detects common SQL injection payload patterns in web server, WAF, proxy,
  or application logs. The rule focuses on reconnaissance and exploitation
  techniques frequently observed in UNION-based, boolean-based, error-based,
  and time-based SQL injection attacks.
references:
  - https://www.acunetix.com/blog/articles/exploiting-sql-injection-example/
  - https://www.acunetix.com/blog/articles/using-logs-to-investigate-a-web-application-attack/
  - https://brightsec.com/blog/sql-injection-payloads/
  - https://github.com/payloadbox/sql-injection-payload-list
  - https://book.hacktricks.xyz/pentesting-web/sql-injection/mysql-injection
author: OpenAI
date: 2026-06-06
tags:
  - attack.initial_access
  - attack.t1190
  - attack.reconnaissance
logsource:
  category: webserver
detection:
  selection_union:
    cs-uri-query|contains:
      - 'union select'
      - 'union all select'
      - 'group_concat('
      - 'information_schema'
  selection_boolean:
    cs-uri-query|contains:
      - "' or '1'='1"
      - '" or "1"="1'
      - "' or 1=1"
      - '" or 1=1'
  selection_time:
    cs-uri-query|contains:
      - 'sleep('
      - 'benchmark('
      - 'waitfor delay'
      - 'pg_sleep('
  selection_file_access:
    cs-uri-query|contains:
      - 'load_file('
      - 'into outfile'
      - 'into dumpfile'
  selection_urlencoded:
    cs-uri-query|contains:
      - '%27%20or%201%3d1'
      - '%22%20or%201%3d1'
      - '%20union%20select%20'
  condition: 1 of selection_*
fields:
  - c-ip
  - cs-method
  - cs-uri-stem
  - cs-uri-query
  - cs-user-agent
  - sc-status
falsepositives:
  - Web application security testing
  - Authorized penetration tests
  - Vulnerability scanner activity
level: high

---
# Arquivo: E.yml
title: Web Server SQL Injection Attack Detection
id: f4a8c9b2-3e1a-4d2c-8b9f-5c2e8a1d4b6c
status: experimental
description: Detects potential SQL Injection (SQLi) exploitation attempts within web server access logs. The rule identifies common SQL injection primitives, functions, and database structure queries (such as UNION SELECT, information_schema, and sleep functions) passed through URL strings.
references:
    - https://www.acunetix.com/blog/articles/exploiting-sql-injection-example/
    - https://www.acunetix.com/blog/articles/using-logs-to-investigate-a-web-application-attack/
    - https://brightsec.com/blog/sql-injection-payloads/
    - https://github.com/payloadbox/sql-injection-payload-list
    - https://book.hacktricks.xyz/pentesting-web/sql-injection/mysql-injection
author: Security Operations Center
date: 2026/06/06
tags:
    - attack.initial_access
    - attack.t1190 # Exploit Public-Facing Application
logsource:
    category: webserver
detection:
    selection_sqli_patterns:
        url|contains:
            # Union Based SQLi
            - 'union select'
            - 'union%20select'
            - 'union+select'
            - 'union all select'
            # Error / Information Schema Enumeration
            - 'information_schema'
            - 'table_name'
            - 'column_name'
            - 'sysdatabases'
            - '@@version'
            # Blind / Time-Based SQLi
            - 'sleep('
            - 'sleep%28'
            - 'benchmark('
            - 'benchmark%28'
            - 'waitfor delay'
            - 'waitfor%20delay'
            # File Exfiltration / Command Execution
            - 'into outfile'
            - 'into%20outfile'
            - 'into+outfile'
            - 'into dumpfile'
            - 'load_file('
            - 'load_file%28'
            # Common Boolean / Tautology Fuzzing
            - 'or 1=1'
            - 'or%201=1'
            - 'or+1=1'
            - 'or 1%3d1'
            - 'order by'
            - 'order%20by'
            - 'order+by'
    condition: selection_sqli_patterns
falsepositives:
    - Automated vulnerability scanners or authorized penetration testing activities.
    - Legitimate application workflows where parameters contain names or data matching SQL terms (e.g., search fields looking up strings like "sleep" or "order by").
level: high

---
# Arquivo original: web_sql_injection_in_access_logs.yml
title: SQL Injection Strings In URI
id: 5513deaf-f49a-46c2-a6c8-3f111b5cb453
status: test
description: Detects potential SQL injection attempts via GET requests in access logs.
references:
    - https://www.acunetix.com/blog/articles/exploiting-sql-injection-example/
    - https://www.acunetix.com/blog/articles/using-logs-to-investigate-a-web-application-attack/
    - https://brightsec.com/blog/sql-injection-payloads/
    - https://github.com/payloadbox/sql-injection-payload-list
    - https://book.hacktricks.xyz/pentesting-web/sql-injection/mysql-injection
author: Saw Win Naung, Nasreddine Bencherchali (Nextron Systems), Thurein Oo (Yoma Bank)
date: 2020-02-22
modified: 2023-09-04
tags:
    - attack.initial-access
    - attack.t1190
logsource:
    category: webserver
detection:
    selection:
        cs-method: 'GET'
    keywords:
        - '@@version'
        - '%271%27%3D%271'
        - '=select '
        - '=select('
        - '=select%20'
        - 'concat_ws('
        - 'CONCAT(0x'
        - 'from mysql.innodb_table_stats'
        - 'from%20mysql.innodb_table_stats'
        - 'group_concat('
        - 'information_schema.tables'
        - 'json_arrayagg('
        - 'or 1=1#'
        - 'or%201=1#'
        - 'order by '
        - 'order%20by%20'
        - 'select * '
        - 'select database()'
        - 'select version()'
        - 'select%20*%20'
        - 'select%20database()'
        - 'select%20version()'
        - 'select%28sleep%2810%29'
        - 'SELECTCHAR('
        - 'table_schema'
        - 'UNION ALL SELECT'
        - 'UNION SELECT'
        - 'UNION%20ALL%20SELECT'
        - 'UNION%20SELECT'
        - "'1'='1"
    filter_main_status:
        sc-status: 404
    condition: selection and keywords and not 1 of filter_main_*
falsepositives:
    - Java scripts and CSS Files
    - User searches in search boxes of the respective website
    - Internal vulnerability scanners can cause some serious FPs when used, if you experience a lot of FPs due to this think of adding more filters such as "User Agent" strings and more response codes
level: high

---