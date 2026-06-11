# Arquivo: A.yml
title: Django Security Exception Logging
id: 1f3a9d72-7e2d-4d7a-9c58-3f4c9af1d2b8
status: stable
description: Detects Django security-relevant exceptions in application logs, including SuspiciousOperation and its subclasses plus PermissionDenied. These errors can indicate exploitation attempts such as path traversal, session tampering, redirect abuse, oversized request payloads, or other malicious probing. Django security logging must be enabled and application logs should capture ERROR-level events or above.
references:

* [https://docs.djangoproject.com/en/1.11/ref/exceptions/](https://docs.djangoproject.com/en/1.11/ref/exceptions/)
* [https://docs.djangoproject.com/en/1.11/topics/logging/#django-security](https://docs.djangoproject.com/en/1.11/topics/logging/#django-security)
  author: OpenAI
  date: 2026/06/02
  tags:
* attack.initial-access
* attack.t1190
  logsource:
  product: django
  category: application
  detection:
  selection:
  message|contains:

  * 'SuspiciousOperation'
  * 'DisallowedHost'
  * 'DisallowedModelAdminLookup'
  * 'DisallowedModelAdminToField'
  * 'DisallowedRedirect'
  * 'InvalidSessionKey'
  * 'RequestDataTooBig'
  * 'SuspiciousFileOperation'
  * 'SuspiciousMultipartForm'
  * 'SuspiciousSession'
  * 'TooManyFieldsSent'
  * 'PermissionDenied'
    condition: selection
    falsepositives:
* Legitimate application requests that trigger Django security protections.
* Malformed or user-generated input that is rejected by the application.
* Security testing, fuzzing, or web scanning performed by authorized teams.
  level: medium

---
# Arquivo: B.yml
title: Django Security Exception
id: b3c7e5d9-8a1f-4e2b-9c6d-7f8a9b0c1d2e
status: experimental
description: Detects Django framework security exceptions in application logs, which may indicate exploitation attempts such as path traversal, session tampering, redirect abuse, or oversized request payloads. Requires Django logging configuration to capture security-related exceptions.
references:
  - https://docs.djangoproject.com/en/1.11/ref/exceptions/
  - https://docs.djangoproject.com/en/1.11/topics/logging/#django-security
author: Senior Threat Detection Engineer
date: 2026-06-02
tags:
  - attack.initial-access
  - attack.t1190
  - attack.credential-access
  - attack.t1528
logsource:
  product: django
  category: application
detection:
  keywords:
    - SuspiciousOperation
    - DisallowedHost
    - SuspiciousMultipartForm
    - TooManyFieldsSent
    - SuspiciousFileOperation
    - SuspiciousRedirect
    - PermissionDenied
  condition: keywords
falsepositives:
  - Legitimate but malformed client requests
  - Development or testing environments with incomplete configurations
level: medium
---
# Arquivo: C.yml
title: Django Security Exception Raised in Application Log
id: f2e9c4b7-3a6d-4f1e-b8d5-7c2a4f8e1b39
status: experimental
description: >
  Detects Django security exception class names in application logs emitted
  by the django.security logger at ERROR level or above. Django raises
  SuspiciousOperation and its subclasses whenever the framework intercepts
  a request that exhibits security-relevant anomalies: path traversal probes
  trigger SuspiciousFileOperation; crafted session cookies or invalid session
  data trigger InvalidSessionKey or SuspiciousSession; open-redirect attempts
  trigger DisallowedRedirect; oversized request bodies trigger
  RequestDataTooBig; malformed multipart submissions trigger
  SuspiciousMultipartForm; and field-flooding attacks trigger
  TooManyFieldsSent. DisallowedHost fires when the HTTP Host header does not
  match ALLOWED_HOSTS, a common indicator of host-header injection probing.
  PermissionDenied fires when application-layer access control explicitly
  rejects a request and is logged by the django.request logger at WARNING
  level; its presence in error logs at higher severity indicates repeated
  or unusual access control violations. A burst of these exceptions across
  short timeframes is a strong indicator of automated web-application
  scanning, exploit tooling, or targeted exploitation. Requires Django
  application logging to be configured to emit the django.security and
  django.request loggers at LOG_LEVEL ERROR or above and to forward those
  log streams to the SIEM.
references:
  - https://docs.djangoproject.com/en/1.11/ref/exceptions/
  - https://docs.djangoproject.com/en/1.11/topics/logging/#django-security
author: Senior Threat Detection Engineer
date: 2026-05-25
tags:
  - attack.initial_access
  - attack.t1190
logsource:
  category: application
  product: django
  definition: >
    Requirements: Django logging must be configured with the django.security
    and django.request handlers emitting at LOG_LEVEL ERROR or WARNING
    respectively, and the resulting log stream must be ingested by the SIEM.
    Applications with logging disabled or configured below the required
    threshold will not surface the exception events this rule depends on.
detection:
  keywords:
    - 'SuspiciousOperation'
    - 'DisallowedHost'
    - 'DisallowedModelAdminLookup'
    - 'DisallowedModelAdminToField'
    - 'DisallowedRedirect'
    - 'InvalidSessionKey'
    - 'RequestDataTooBig'
    - 'SuspiciousFileOperation'
    - 'SuspiciousMultipartForm'
    - 'SuspiciousSession'
    - 'TooManyFieldsSent'
    - 'PermissionDenied'
  condition: keywords
falsepositives:
  - Misconfigured HTTP clients, load balancers, or reverse proxies that
    submit Host headers not listed in ALLOWED_HOSTS, triggering
    DisallowedHost without malicious intent, particularly during initial
    deployment or DNS migration events.
  - Legitimate users with large file uploads or form submissions that
    exceed the application's configured DATA_UPLOAD_MAX_MEMORY_SIZE,
    triggering RequestDataTooBig or TooManyFieldsSent under normal usage
    patterns on upload-heavy applications.
  - Automated integration-test suites that deliberately exercise
    error-handling paths by submitting invalid or boundary-condition
    requests as part of functional regression testing in non-production
    environments.
level: medium
---
# Arquivo: D.yml
title: Django Security Exceptions Indicating Potential Exploitation
id: 1be45cb9-00f7-4952-b892-2dc09d949d97
status: stable
description: Detects Django web framework security exceptions in application logs, such as SuspiciousOperation and its subclasses or PermissionDenied. These exceptions often serve as indicators of exploitation attempts like path traversal, session tampering, redirect abuse, or oversized request payloads.
references:

* [https://docs.djangoproject.com/en/1.11/ref/exceptions/](https://docs.djangoproject.com/en/1.11/ref/exceptions/)
* [https://docs.djangoproject.com/en/1.11/topics/logging/#django-security](https://docs.djangoproject.com/en/1.11/topics/logging/#django-security)
author: Senior Threat Detection Engineer
date: 2026/06/02
tags:
* attack.initial_access
* attack.t1190
logsource:
product: django
category: application
detection:
keywords:
* 'SuspiciousOperation'
* 'DisallowedHost'
* 'DisallowedRedirect'
* 'InvalidSessionKey'
* 'RequestDataTooBig'
* 'TooManyFieldsSent'
* 'SuspiciousMultipartForm'
* 'SuspiciousFileOperation'
* 'PermissionDenied'
condition: keywords
falsepositives:


* Legitimate application errors caused by misconfigurations, malformed web crawler requests, or automated internal vulnerability scanning.
level: medium
---
# Arquivo: E.yml
title: Django Security Exception Detection
id: 3c9b7f6a-2b8e-4e6c-9f8d-django-sec-exceptions
description: Detects Django security-related exceptions in application logs that may indicate exploitation attempts (path traversal, session tampering, redirect abuse, oversized payloads).
status: experimental
author: Copilot
date: 2026/06/02
references:
  - https://docs.djangoproject.com/en/1.11/ref/exceptions/
  - https://docs.djangoproject.com/en/1.11/topics/logging/#django-security
logsource:
  category: application
  product: django
detection:
  selection:
    message|contains:
      - "SuspiciousOperation"
      - "DisallowedHost"
      - "DisallowedModelAdminLookup"
      - "DisallowedModelAdminToField"
      - "DisallowedRedirect"
      - "InvalidSessionKey"
      - "RequestDataTooBig"
      - "PermissionDenied"
  condition: selection
fields:
  - timestamp
  - level
  - logger
  - message
falsepositives:
  - Misconfigured application behavior
  - Legitimate but unusual user input
level: high
tags:
  - attack.web
  - attack.exploitation
  - attack.session
  - attack.redirect
  - attack.payload

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