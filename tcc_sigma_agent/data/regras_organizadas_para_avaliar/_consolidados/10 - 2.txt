# Arquivo: A.yml
title: Suspicious SQL Activity via Query Log Analysis
id: a1b2c3d4-e5f6-7890-1234-567890abcdef
status: experimental
description: Detects suspicious SQL keywords in database query logs associated with reconnaissance, exfiltration, or destructive activity including DROP, TRUNCATE, data dumping, or indiscriminate SELECT all columns.
references:
    - https://github.com/sqlmapproject/sqlmap
author: Senior Threat Detection Engineer
date: 2026-06-02
logsource:
    category: database
detection:
    # Documentation: Requires SQL query logging to be enabled
    selection:
        query|contains:
            # Destructive commands
            - 'DROP TABLE'
            - 'DROP DATABASE'
            - 'TRUNCATE TABLE'
            # Exfiltration / dumping
            - 'INTO OUTFILE'
            - 'INTO DUMPFILE'
            - 'BULK INSERT'
            - 'COPY ('
            - "COPY ("
            # Reconnaissance / schema grabbing
            - 'SELECT * FROM'
            - 'SELECT ALL FROM'
            - 'SELECT COUNT(*)'  # Potential enumeration
            - ' UNION SELECT'
            - ' INFORMATION_SCHEMA.'
            - 'sys.tables'
            - 'sys.columns'
            - 'all_tab_columns'
            - 'mysql.user'
            - 'sqlite_master'
            # Potential time-based or heavy queries
            - 'SLEEP('
            - 'WAITFOR DELAY'
            - 'BENCHMARK('
    condition: selection
falsepositives:
    - Legitimate administrative tasks (e.g., backups, schema changes).
    - Application ORM generating broad SELECT statements.
    - Database maintenance scripts.
level: medium
tags:
    - attack.exfiltration
    - attack.impact
    - attack.t1048
    - attack.t1485
    - attack.t1190

---
# Arquivo: B.yml
title: Suspicious SQL Query Activity
id: 4e97a23b-01ad-4674-bf72-4b2a8d18e950
status: experimental
description: Detects suspicious SQL keywords in database query logs associated with reconnaissance, exfiltration, or destructive activity, such as dropping or truncating tables, or selecting all columns indiscriminately. Note that this rule requires SQL query logging to be enabled on the target database system.
references:
- [https://github.com/sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)
author: Senior Threat Detection Engineer
date: 2026/06/02
tags:
- attack.reconnaissance
- attack.exfiltration
- attack.impact
logsource:
category: database
detection:
keywords:
- 'DROP TABLE'
- 'TRUNCATE TABLE'
- 'SELECT * FROM'
- 'UNION SELECT'
condition: keywords
falsepositives:
- Legitimate database administration, database backups, migrations, or application routine operations.
level: medium

---
# Arquivo: C.yml
title: Suspicious SQL Keywords Indicative of Reconnaissance or Destructive Activity
id: 9f4b2c6d-7a1e-4b2f-8c3d-5e6f7a8b9c0d
status: experimental
description: Detects database queries containing high-risk SQL keywords commonly used for reconnaissance, data exfiltration, or destructive actions (e.g., DROP, TRUNCATE, SELECT * , UNION SELECT, INTO OUTFILE). Requires SQL query logging to be enabled so raw query text is available in logs.
author: Senior Threat Detection Engineer
date: 2026/06/02
references:
  - [https://github.com/sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)
tags:
  - attack.reconnaissance
  - attack.exfiltration
  - attack.impact
  - detection
logsource:
  category: database
  product: generic
  description: SQL query logging must be enabled and capture raw query text (e.g., general_log, audit log, query_log).
detection:
  selection:
    Query|contains:
      - 'DROP TABLE'
      - 'TRUNCATE TABLE'
      - 'DELETE FROM'
      - 'SELECT *'
      - 'UNION SELECT'
      - 'INTO OUTFILE'
      - 'LOAD_FILE('
      - 'INFORMATION_SCHEMA'
      - 'xp_cmdshell'
      - 'EXECUTE IMMEDIATE'
      - 'ATTACH DATABASE'
  condition: selection
falsepositives:
  - Legitimate administrative or maintenance scripts performing schema changes or bulk operations.
  - Backup, ETL, or reporting jobs that legitimately use SELECT * or INFORMATION_SCHEMA.
level: high

---
# Arquivo: D.yml
title: Suspicious SQL Keywords Indicating Injection Reconnaissance or Destructive Activity
id: b7d3e9f2-4a1c-4d6e-b8f4-3c5a2d7e1b96
status: experimental
description: >
  Detects SQL keywords in database query logs that are characteristic of
  SQL injection reconnaissance, schema enumeration, data exfiltration, or
  destructive operations as executed by tools such as sqlmap. Coverage spans
  four attack categories: schema enumeration via information_schema and
  equivalent system catalog objects across major database engines; UNION-based
  data extraction; file-read and file-write primitives; and destructive DDL
  operations including DROP and TRUNCATE. Any single keyword match against
  a logged query is sufficient to trigger the rule, as each item in the list
  has minimal legitimate presence in application-generated query streams and
  represents a high-signal indicator of adversarial activity when observed
  in production database logs. Requires SQL query logging to be enabled on
  the monitored database engine and the resulting query log stream to be
  forwarded to the SIEM. For MySQL, enable general_log. For SQL Server,
  enable Extended Events or SQL Server Audit. For Oracle, enable Unified
  Auditing. For PostgreSQL, set log_statement to all or ddl in
  postgresql.conf. Environments with query logging disabled will not surface
  the events this rule depends on.
references:
  - https://github.com/sqlmapproject/sqlmap
author: Senior Threat Detection Engineer
date: 2026-05-25
tags:
  - attack.initial_access
  - attack.collection
  - attack.impact
  - attack.t1190
  - attack.t1213
  - attack.t1485
logsource:
  category: database
  definition: >
    Requirements: SQL query logging must be enabled on the monitored database
    instance and logs forwarded to the SIEM. Environments without query-level
    logging will not surface the events this rule depends on.
detection:
  keywords:
    - 'information_schema'
    - 'sysobjects'
    - 'sqlite_master'
    - 'all_tables'
    - 'UNION SELECT'
    - 'UNION ALL SELECT'
    - 'INTO OUTFILE'
    - 'INTO DUMPFILE'
    - 'LOAD_FILE('
    - 'xp_cmdshell'
    - 'WAITFOR DELAY'
    - 'SLEEP('
    - 'BENCHMARK('
    - 'DROP TABLE'
    - 'DROP DATABASE'
    - 'TRUNCATE TABLE'
  condition: keywords
falsepositives:
  - Database administrators running legitimate schema inspection queries
    against information_schema or system catalog objects during maintenance
    or migration work.
  - ORM frameworks and schema migration tooling that issue DROP TABLE or
    TRUNCATE TABLE statements as part of test-fixture teardown or versioned
    schema rollback operations in non-production environments.
  - Authorized penetration tests or red-team exercises operating under
    documented rules of engagement.
level: medium

---
# Arquivo: E.yml
title: Suspicious SQL Query Keywords Indicative Of Reconnaissance Or Destructive Activity
id: 6f2d5e7c-1c8a-4c5f-9e33-4b4d2a9b7d1f
status: experimental
description: Detects potentially suspicious SQL statements in database query logs that may indicate reconnaissance, data exfiltration, or destructive activity. Requires SQL query logging to be enabled and ingested into the logging platform.
references:

* [https://github.com/sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)
  author: OpenAI
  date: 2026-06-02
  tags:
* attack.discovery
* attack.collection
* attack.exfiltration
* attack.impact
  logsource:
  category: database
  detection:
  selection:
  keywords:

  * 'DROP TABLE'
  * 'TRUNCATE TABLE'
  * 'UNION SELECT'
  * 'SELECT * FROM'
  * 'INTO OUTFILE'
    condition: selection
    falsepositives:
* Legitimate database administration activities
* Database maintenance and migration scripts
* Authorized reporting and data export operations
  level: medium
  notes: SQL query logging must be enabled for this detection to function. Consider tuning based on approved administrative accounts, maintenance windows, and known application query patterns.


---
# Arquivo original: db_anomalous_query.yml
title: Suspicious SQL Query
id: d84c0ded-edd7-4123-80ed-348bb3ccc4d5
status: test
description: Detects suspicious SQL query keywrods that are often used during recon, exfiltration or destructive activities. Such as dropping tables and selecting wildcard fields
author: '@juju4'
date: 2022-12-27
references:
    - https://github.com/sqlmapproject/sqlmap
tags:
    - attack.exfiltration
    - attack.initial-access
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1190
    - attack.t1505.001
logsource:
    category: database
    definition: 'Requirements: Must be able to log the SQL queries'
detection:
    keywords:
        - 'drop'
        - 'truncate'
        - 'dump'
        - 'select \*'
    condition: keywords
falsepositives:
    - Inventory and monitoring activity
    - Vulnerability scanners
    - Legitimate applications
level: medium

---