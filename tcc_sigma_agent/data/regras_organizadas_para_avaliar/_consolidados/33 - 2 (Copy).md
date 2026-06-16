# Arquivo: A.yml
title: Webserver SQL Injection Attempt In GET URI
id: 7d9db8d2-34f8-4d2e-8f6d-2d7b6d8f0e55
status: experimental
description: Detects HTTP GET requests with URI patterns commonly associated with SQL injection attempts, including UNION-based extraction, information schema enumeration, blind injection, and URL-encoded variants. Excludes 404 responses to reduce noise from generic scanners.
references:

* [https://www.acunetix.com/blog/articles/exploiting-sql-injection-example/](https://www.acunetix.com/blog/articles/exploiting-sql-injection-example/)
* [https://www.acunetix.com/blog/articles/using-logs-to-investigate-a-web-application-attack/](https://www.acunetix.com/blog/articles/using-logs-to-investigate-a-web-application-attack/)
* [https://brightsec.com/blog/sql-injection-payloads/](https://brightsec.com/blog/sql-injection-payloads/)
* [https://github.com/payloadbox/sql-injection-payload-list](https://github.com/payloadbox/sql-injection-payload-list)
* [https://book.hacktricks.xyz/pentesting-web/sql-injection/mysql-injection](https://book.hacktricks.xyz/pentesting-web/sql-injection/mysql-injection)
  author: OpenAI
  date: 2026-06-06
  tags:
* attack.initial_access
* attack.t1190
  logsource:
  category: webserver
  detection:
  selection:
  cs-method: GET
  keywords:
  cs-uri|contains:

  * 'union select'
  * 'union%20select'
  * 'union+select'
  * 'information_schema'
  * 'information%5fschema'
  * 'database()'
  * 'database%28%29'
  * '@@version'
  * '%40%40version'
  * 'version()'
  * 'version%28%29'
  * 'or 1=1'
  * 'or%201%3D1'
  * 'and 1=1'
  * 'and%201%3D1'
  * '1=1'
  * '1%3D1'
  * 'sleep('
  * 'sleep%28'
  * 'benchmark('
  * 'benchmark%28'
  * 'extractvalue('
  * 'extractvalue%28'
  * 'updatexml('
  * 'updatexml%28'
  * 'group_concat('
  * 'group_concat%28'
  * 'load_file('
  * 'load_file%28'
  * 'concat_ws('
  * 'concat_ws%28'
    filter_main_404:
    status: 404
    condition: selection and keywords and not 1 of filter_main_*
    falsepositives:
* Security testing and vulnerability scanning
* Development or troubleshooting activity
* Legitimate requests containing SQL-like text in query parameters
  level: high


---
# Arquivo: B.yml
title: SQL Injection Attempt in Web Server Access Logs
id: b0c1d2e3-f4a5-6789-bcde-678901234567
status: experimental
description: Detects SQL injection attempts in web server access logs via GET requests whose URIs contain SQL injection payloads including schema enumeration, UNION-based extraction, blind injection, and URL-encoded variants of common SQLi strings.
references:
    - https://www.acunetix.com/blog/articles/exploiting-sql-injection-example/
    - https://www.acunetix.com/blog/articles/using-logs-to-investigate-a-web-application-attack/
    - https://brightsec.com/blog/sql-injection-payloads/
    - https://github.com/payloadbox/sql-injection-payload-list
    - https://book.hacktricks.xyz/pentesting-web/sql-injection/mysql-injection
author: Senior Threat Detection Engineer
date: 2024-01-01
tags:
    - attack.initial_access
    - attack.t1190
    - attack.credential_access
    - attack.t1110
logsource:
    category: webserver
detection:
    selection:
        cs-method: 'GET'
    keywords:
        cs-uri-query|contains:
            - 'UNION+SELECT'
            - 'UNION SELECT'
            - 'union+select'
            - 'union select'
            - '%55NION+%53ELECT'
            - '%55NION%20%53ELECT'
            - 'UNION%20SELECT'
            - 'union%20select'
            - 'information_schema'
            - 'INFORMATION_SCHEMA'
            - '%69nformation_schema'
            - 'information%5Fschema'
            - 'table_name'
            - 'TABLE_NAME'
            - 'table_schema'
            - 'TABLE_SCHEMA'
            - '@@version'
            - '@@VERSION'
            - '%40%40version'
            - 'database()'
            - 'DATABASE()'
            - 'schema()'
            - 'SCHEMA()'
            - 'sleep('
            - 'SLEEP('
            - 'waitfor+delay'
            - 'WAITFOR+DELAY'
            - 'WAITFOR DELAY'
            - 'waitfor delay'
            - 'benchmark('
            - 'BENCHMARK('
            - '1=1--'
            - '1+1=1'
            - "'1'='1"
            - "' OR '1'='1"
            - "' or '1'='1"
            - '+OR+1=1'
            - '+or+1=1'
            - '%27+OR+%271%27%3D%271'
            - "' AND 1=1"
            - "' and 1=1"
            - '+AND+1=1'
            - 'ORDER+BY+1'
            - 'order+by+1'
            - 'ORDER BY 1'
            - 'group_concat('
            - 'GROUP_CONCAT('
            - 'load_file('
            - 'LOAD_FILE('
            - 'into+outfile'
            - 'INTO+OUTFILE'
            - 'INTO OUTFILE'
            - 'into outfile'
            - 'char(0x'
            - 'CHAR(0x'
            - 'convert('
            - 'CONVERT('
            - 'extractvalue('
            - 'EXTRACTVALUE('
            - 'updatexml('
            - 'UPDATEXML('
    filter_main_404:
        sc-status: 404
    condition: selection and keywords and not 1 of filter_main_*
falsepositives:
    - Authorized penetration testing or vulnerability scanning activities
    - Web application firewalls or security tools testing their own rulesets
    - Developers testing SQL injection prevention in development environments
level: medium

---
# Arquivo: C.yml
title: SQL Injection Attempt in Web Server Logs
id: e4c8d52b-43a1-432d-9a84-18cfaefb81da
status: stable
description: Detects SQL injection attempts in web server access logs targeting GET requests, including schema enumeration, UNION-based extraction, blind injection, and URL-encoded variants.
references:

* [https://www.acunetix.com/blog/articles/exploiting-sql-injection-example/](https://www.acunetix.com/blog/articles/exploiting-sql-injection-example/)
* [https://www.acunetix.com/blog/articles/using-logs-to-investigate-a-web-application-attack/](https://www.acunetix.com/blog/articles/using-logs-to-investigate-a-web-application-attack/)
* [https://brightsec.com/blog/sql-injection-payloads/](https://brightsec.com/blog/sql-injection-payloads/)
* [https://github.com/payloadbox/sql-injection-payload-list](https://github.com/payloadbox/sql-injection-payload-list)
* [https://book.hacktricks.xyz/pentesting-web/sql-injection/mysql-injection](https://book.hacktricks.xyz/pentesting-web/sql-injection/mysql-injection)
author: Senior Threat Detection Engineer
date: 2026/06/06
tags:
* attack.initial_access
* attack.t1190
logsource:
category: webserver
detection:
selection:
cs-method: 'GET'
keywords:
cs-uri|contains:
* 'union select'
* 'union%20select'
* 'union+select'
* 'information_schema'
* 'information%5Fschema'
* 'select@@version'
* 'select%20%40%40version'
* 'select+%40%40version'
* 'or 1=1'
* 'or%201%3D1'
* 'or+1%3D1'
* 'waitfor delay'
* 'waitfor%20delay'
* 'waitfor+delay'
* 'pg_sleep'
* 'database()'
* 'database%28%29'
filter_main_404:
sc-status: 404
condition: selection and keywords and not 1 of filter_main_*
falsepositives:


* Security penetration testing or authorized vulnerability scanning activity.
* Legitimate application queries or parameter values that accidentally contain overlapping SQL keyword syntax.
level: high

---
# Arquivo: D.yml
title: SQL Injection Indicators in Web Server GET Requests
id: e2b7c9a4-5f3d-4a1b-9c2e-7d6f8a0b1c2d
status: experimental
description: Detects potential SQL injection attempts in web server access logs by identifying GET requests whose URIs contain common SQLi payloads (plain-text and URL-encoded variants). Excludes 404 responses to reduce noise from scanners hitting non-existent endpoints.
author: Senior Threat Detection Engineer
date: 2026/06/08
references:
  - [https://www.acunetix.com/blog/articles/exploiting-sql-injection-example/](https://www.acunetix.com/blog/articles/exploiting-sql-injection-example/)
  - [https://www.acunetix.com/blog/articles/using-logs-to-investigate-a-web-application-attack/](https://www.acunetix.com/blog/articles/using-logs-to-investigate-a-web-application-attack/)
  - [https://brightsec.com/blog/sql-injection-payloads/](https://brightsec.com/blog/sql-injection-payloads/)
  - [https://github.com/payloadbox/sql-injection-payload-list](https://github.com/payloadbox/sql-injection-payload-list)
  - [https://book.hacktricks.xyz/pentesting-web/sql-injection/mysql-injection](https://book.hacktricks.xyz/pentesting-web/sql-injection/mysql-injection)
tags:
  - attack.injection
  - web
  - detection
logsource:
  category: webserver
  description: Web server access logs (unstructured or semi-structured) containing HTTP Method, URI/Request, and ResponseCode fields.
detection:
  selection_method:
    Method:
      - 'GET'
  keywords:
    Uri|contains:
      - 'UNION SELECT'
      - 'UNION%20SELECT'
      - 'UNION+SELECT'
      - 'UNION+ALL+SELECT'
      - 'UNION%2BALL%2BSELECT'
      - 'information_schema'
      - 'information_schema.tables'
      - 'information_schema.columns'
      - 'SELECT%20%2A%20FROM'
      - 'SELECT%20%2A%20FROM%20information_schema'
      - 'concat('
      - 'concat%28'
      - 'group_concat('
      - 'group_concat%28'
      - 'version()'
      - 'version%28%29'
      - 'database()'
      - 'database%28%29'
      - 'sleep('
      - 'sleep%28'
      - 'benchmark('
      - 'benchmark%28'
      - "or 1=1"
      - "%27%20OR%20%271%27%3D%271"
      - "%27%20OR%20%271%27%3D%271%20--"
      - "' OR '1'='1"
      - "' OR 1=1 --"
      - 'ORDER BY 1--'
      - 'ORDER%20BY%201--'
      - 'ORDER+BY+1--'
      - '/*'
      - '%2F%2A'
      - '--'
      - '%2D%2D'
      - 'xp_cmdshell'
      - 'load_file('
      - 'load_file%28'
      - 'into outfile'
      - 'into%20outfile'
      - 'substr('
      - 'substr%28'
      - 'ascii('
      - 'ascii%28'
      - 'char('
      - 'char%28'
      - '%27--'
      - '%27%3B--'
      - '%3Cscript%3E' 
  filter_main_404:
    ResponseCode:
      - 404
  condition: selection_method and keywords and not 1 of filter_main_404
falsepositives:
  - Automated scanners or vulnerability scanners probing endpoints that return non-404 responses.
  - Legitimate application URLs or parameters that coincidentally contain SQL-like tokens (e.g., documentation pages, encoded examples).
level: high

---
# Arquivo: E.yml
title: SQL Injection Attempts in Web Server Access Logs
id: a7b8c9d0-e1f2-43a4-85b6-7c8d9e0f1a2b
status: experimental
description: Detects GET requests containing SQL injection payloads such as schema enumeration, UNION-based extraction, blind injection, and URL-encoded variants, excluding 404 responses to reduce noise.
references:
    - https://www.acunetix.com/blog/articles/exploiting-sql-injection-example/
    - https://www.acunetix.com/blog/articles/using-logs-to-investigate-a-web-application-attack/
    - https://brightsec.com/blog/sql-injection-payloads/
    - https://github.com/payloadbox/sql-injection-payload-list
    - https://book.hacktricks.xyz/pentesting-web/sql-injection/mysql-injection
author: Senior Threat Detection Engineer
date: 2026-06-06
logsource:
    category: webserver
detection:
    selection_method:
        cs-method: GET
    selection_payload:
        cs-uri-query|contains|all:
            # UNION-based
            - 'UNION'
            - 'SELECT'
            # information_schema
            - 'information_schema'
            # Version/database fingerprinting
            - '@@version'
            - 'database()'
            - 'user()'
            - 'version()'
            # Boolean-based and generic SQLi
            - "' OR '1'='1"
            - "' OR 1=1--"
            - "' OR '1'='1'--"
            - "\" OR \"1\"=\"1"
            - "'; DROP TABLE"
            - "' UNION SELECT"
            - "1=1;--"
            # URL-encoded variants
            - '%27%20OR%20%271%27%3D%271'
            - '%27%20OR%201%3D1--'
            - '%22%20OR%20%221%22%3D%221'
            - '%27%20UNION%20SELECT'
            - 'information_schema%2Etables'
            - '%40%40version'
            - 'database%28%29'
            - 'user%28%29'
            - 'version%28%29'
            - '%3B%20DROP%20TABLE'
    filter_main_404:
        sc-status: 404
    condition: selection_method and selection_payload and not filter_main_404
falsepositives:
    - Legitimate requests containing these strings in non-SQL contexts (e.g., search queries, user input)
    - Security scanners or crawlers without proper evasion
level: high
tags:
    - attack.initial_access
    - attack.t1190
    - attack.t1505.003
    - attack.t1590.005

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