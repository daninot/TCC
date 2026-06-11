# Arquivo: A.yml
title: Django SuspiciousOperation and Security Exceptions
id: 9f3b2a6e-1c4d-4b2a-8f7a-abcdef123456
status: experimental
description: Detect Django SuspiciousOperation exceptions and common subclasses logged at ERROR level which indicate tampering, malformed requests, or other security-relevant client behavior.
author: Daniela (generated)
date: 2026-06-02
references:
  - https://docs.djangoproject.com/en/1.11/ref/exceptions/
  - https://docs.djangoproject.com/en/1.11/topics/logging/#django-security
tags:
  - attack.tampering
  - attack.reconnaissance
  - web.application
logsource:
  product: django
  service: web
  category: application
detection:
  selection:
    level|contains: ERROR
    # match common Django security exception class names in the message or exception field
    message|contains:
      - SuspiciousOperation
      - DisallowedHost
      - DisallowedModelAdminLookup
      - DisallowedRedirect
      - InvalidSessionKey
      - RequestDataTooBig
      - SuspiciousFileOperation
      - SuspiciousMultipartForm
      - SuspiciousSession
      - TooManyFieldsSent
      - TooManyFilesSent
  condition: selection
falsepositives:
  - legitimate client misconfiguration (e.g., incorrect host header causing DisallowedHost)
  - large file uploads from valid users triggering RequestDataTooBig
  - automated scanners or benign bots producing malformed requests
level: high
fields:
  - timestamp
  - host
  - logger_name
  - level
  - message
  - client_ip
  - request_path
  - user_agent
  - exception_type

---
# Arquivo: B.yml
title: Django Security Logger SuspiciousOperation
id: 2f7f6a2d-6f35-4a18-8f2c-9a4a7f5dd2c1
status: experimental
description: Detects Django security log events for SuspiciousOperation and common subclasses such as DisallowedHost, which may indicate probing, malformed requests, or host-header attacks.
references:
  - https://docs.djangoproject.com/en/1.11/ref/exceptions/
  - https://docs.djangoproject.com/en/1.11/topics/logging/#django-security
tags:
  - attack.initial_access
  - attack.t1190
  - attack.defense_evasion
logsource:
  category: application
detection:
  selection_logger:
    logger|contains:
      - 'django.security'
      - 'django.security.DisallowedHost'
      - 'django.security.SuspiciousOperation'
  selection_message:
    message|contains:
      - 'SuspiciousOperation'
      - 'DisallowedHost'
      - 'Invalid HTTP_HOST header'
      - 'The host'
      - 'not allowed'
  condition: selection_logger or selection_message
fields:
  - logger
  - message
  - request
  - status_code
  - client_ip
  - user_agent
falsepositives:
  - Misconfigured ALLOWED_HOSTS settings
  - Health checks and monitoring tools using unexpected Host headers
  - Routine scanning by security tools
level: medium
---
# Arquivo: C.yml
title: Django Application - Security Logger Violation Detected (SuspiciousOperation)
id: 4c7d2e1b-8f93-4a56-b012-9e4c6d5a3f18
status: test
description: |
    Detects security violations logged by Django's built-in django.security logger,
    which automatically captures all SuspiciousOperation exceptions and their
    subclasses raised during request processing.

    Per the Django logging documentation, every SuspiciousOperation subclass is
    routed to a logger named django.security.. This creates a
    structured, reliable event stream purpose-built for SIEM ingestion.

    Six attack categories detected via the logger_name field:
      1. selection_traversal   — SuspiciousFileOperation: path traversal (HIGH)
      2. selection_session     — InvalidSessionKey + SuspiciousSession: session
                                 cookie tampering and brute force (HIGH)
      3. selection_host        — DisallowedHost: HTTP Host header injection,
                                 cache poisoning probes, web scanning (MEDIUM)
      4. selection_redirect    — DisallowedRedirect: open redirect exploitation,
                                 phishing enablement (MEDIUM)
      5. selection_form        — SuspiciousMultipartForm: malformed upload attacks,
                                 parser evasion attempts (MEDIUM)
      6. selection_dos         — TooManyFieldsSent + RequestDataTooBig: HashDoS
                                 and request flooding (LOW)

    Django automatically logs each SuspiciousOperation at WARNING level (or ERROR
    if the exception propagates to the WSGI handler), returning HTTP 400 to the
    client. The logger_name follows the dotted path hierarchy of Python logging:
    django.security is the parent; subclass loggers inherit its handlers.

    Prerequisite: configure a LOGGING handler in settings.py to forward
    django.security events to your log aggregation system.
references:
    - https://docs.djangoproject.com/en/1.11/ref/exceptions/
    - https://docs.djangoproject.com/en/1.11/topics/logging/#django-security
    - https://attack.mitre.org/techniques/T1190/
    - https://attack.mitre.org/techniques/T1083/
    - https://attack.mitre.org/techniques/T1550/004/
author: Security Team
date: 2026-05-25
tags:
    - attack.initial_access
    - attack.t1190       # Exploit Public-Facing Application (web attacks)
    - attack.discovery
    - attack.t1083       # File and Directory Discovery (SuspiciousFileOperation)
    - attack.credential_access
    - attack.t1550.004   # Use Alternate Auth Material: Web Session Cookie
logsource:
    category: application
    product: django
    definition: |
        Configure Django settings.py LOGGING to forward the django.security
        logger to your SIEM. Key fields: logger_name, message, level, request.
        Example handler: StreamHandler writing JSON to stdout (for log aggregators)
        or SysLogHandler forwarding to syslog.
detection:
    selection_traversal:
        # Path traversal — file path resolved outside the base directory
        # Attacker attempts ../../../etc/passwd or similar directory traversal
        logger_name: 'django.security.SuspiciousFileOperation'
    selection_session:
        # Session cookie tampering or session ID brute force attempts
        logger_name|in:
            - 'django.security.InvalidSessionKey'
            - 'django.security.SuspiciousSession'
    selection_host:
        # HTTP Host header injection — scanning, cache poisoning, SSRF recon
        logger_name: 'django.security.DisallowedHost'
    selection_redirect:
        # Open redirect exploitation — redirecting users to attacker-controlled domain
        logger_name: 'django.security.DisallowedRedirect'
    selection_form:
        # Malformed multipart/form-data — parser evasion, upload attack bypass
        logger_name: 'django.security.SuspiciousMultipartForm'
    selection_dos:
        # Request flooding — HashDoS via excessive fields / oversized body
        logger_name|in:
            - 'django.security.TooManyFieldsSent'
            - 'django.security.RequestDataTooBig'
    condition: 1 of selection_*
fields:
    - logger_name
    - message
    - level
    - request.META.REMOTE_ADDR
    - request.META.HTTP_HOST
    - request.path
    - request.method
falsepositives:
    - DisallowedHost fired by misconfigured load balancers or reverse proxies
      not yet added to ALLOWED_HOSTS after infrastructure changes
    - TooManyFieldsSent from complex legitimate forms exceeding DATA_UPLOAD_MAX_NUMBER_FIELDS
    - RequestDataTooBig from legitimate large file uploads before upload size is tuned
    - Automated health-check tools probing non-standard Host headers
level: medium
---
# Arquivo: D.yml
title: Django Security Logger Suspicious Operation
id: 9a3e21fb-56d4-4bb2-bd17-91cbef71a25d
status: experimental
description: Detects security-relevant exceptions logged by Django's application security logging framework. This includes Host header validation failures, suspicious URL redirects, session key tampering, and invalid multi-part form submissions which are often indicative of automated web application scanning, fuzzing, or targeted exploitation attempts.
references:
    - https://docs.djangoproject.com/en/1.11/ref/exceptions/
    - https://docs.djangoproject.com/en/1.11/topics/logging/#django-security
author: Security Operations Center
date: 2026/06/02
tags:
    - attack.initial_access
    - attack.t1190 # Exploit Public-Facing Application
logsource:
    category: application
detection:
    selection_logger:
        Message|contains: 'django.security'
    selection_exceptions:
        Message|contains:
            - 'SuspiciousOperation'
            - 'DisallowedHost'
            - 'DisallowedRedirect'
            - 'InvalidSessionKey'
            - 'SuspiciousFileOperation'
            - 'SuspiciousMultipartForm'
            - 'TooManyFieldsSent'
    condition: 1 of selection_*
falsepositives:
    - Public internet noise, bots, or web crawlers accessing the server directly via its raw IP address instead of the approved domain name configured in Django's ALLOWED_HOSTS, triggering a 'DisallowedHost' exception.
    - Misconfigured upstream reverse proxies, CDN layers, or load balancers failing to properly pass the original Host headers.
level: medium
---
# Arquivo: E.yml
title: Potential Django Security Exception - SuspiciousOperation or CSRF Failure
id: 11111111-1111-1111-1111-111111111111
status: experimental
description: Detects security-related exceptions in a Django application, specifically SuspiciousOperation occurrences (e.g., DisallowedHost, CSRF failure) which may indicate malicious requests or security scanning attempts.
references:
  - https://docs.djangoproject.com/en/1.11/ref/exceptions/
  - https://docs.djangoproject.com/en/1.11/topics/logging/#django-security
author: o0p
date: 2025-04-15
tags:
  - attack.t1190
  - attack.initial-access
logsource:
  product: django
  category: security
detection:
  selection:
    logger_name|startswith: 'django.security'
    level:
      - 'WARNING'
      - 'ERROR'
  condition: selection
falsepositives:
  - Legitimate requests with malformed or missing CSRF tokens due to user session timeouts or misconfigured clients.
  - Automated security scanning tools.
  - Internal testing or debugging with DEBUG=True.
level: medium
---
# Arquivo original: appframework_django_exceptions.yml
title: Django Framework Exceptions
id: fd435618-981e-4a7c-81f8-f78ce480d616
status: stable
description: Detects suspicious Django web application framework exceptions that could indicate exploitation attempts
references:
    - https://docs.djangoproject.com/en/1.11/ref/exceptions/
    - https://docs.djangoproject.com/en/1.11/topics/logging/#django-security
author: Thomas Patzke
date: 2017-08-05
modified: 2020-09-01
tags:
    - attack.initial-access
    - attack.t1190
logsource:
    category: application
    product: django
detection:
    keywords:
        - SuspiciousOperation
        # Subclasses of SuspiciousOperation
        - DisallowedHost
        - DisallowedModelAdminLookup
        - DisallowedModelAdminToField
        - DisallowedRedirect
        - InvalidSessionKey
        - RequestDataTooBig
        - SuspiciousFileOperation
        - SuspiciousMultipartForm
        - SuspiciousSession
        - TooManyFieldsSent
        # Further security-related exceptions
        - PermissionDenied
    condition: keywords
falsepositives:
    - Application bugs
level: medium

---