# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters

Queries use JDBC PreparedStatement placeholders and MyBatis #{} (never string concatenation or ${}); dynamic ORDER BY columns come from a fixed <choose> allowlist.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-no-untrusted-deserialize -->
### sec-no-untrusted-deserialize — Never deserialize request data

Request bytes or XML must not reach ObjectInputStream, XStream, fastjson autotype or xlsx streaming parsers; those endpoints are disabled. If input parsing is needed, bind to a fixed DTO with Jackson default typing off.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-secrets-env -->
### sec-secrets-env — Keep secrets out of source

Database and cloud credentials come from environment placeholders (SPRING_DATASOURCE_PASSWORD, JSC_ACCESS_KEY_SECRET). Rotate the old values because they remain in git history, and do not commit PoC payloads or encoded blobs.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xml-hardened -->
### sec-xml-hardened — Parse untrusted XML with hardened factories

Use JAXP DocumentBuilderFactory/SAXParserFactory with DOCTYPE and external entities disabled, secure-processing on and XInclude off for every XML parse of request data.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-outbound-allowlist -->
### sec-outbound-allowlist — Constrain outbound requests, commands and redirects

Outbound URLs, JDBC URLs, OS commands, redirects and Groovy/SpEL expressions are chosen from closed allowlists or rebuilt from validated components, not passed through from the request. Fail closed on no match.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-headers-no-reflect -->
### sec-headers-no-reflect — Do not reflect request values into headers or HTML

CORS origins, Location, Content-Disposition and cookies use allowlisted or rebuilt values, and HTML output is encoded through WebUtils.htmlSafeRebuild. Credentialed CORS stays off, and cookies are Secure and HttpOnly.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-paths-confined -->
### sec-paths-confined — Confine file paths and avoid check-then-use

User-supplied paths go through SecurityUtil.resolveInBase, which normalizes and confines to the base directory and rechecks symlinks. Perform the file operation directly and handle IOException instead of pre-checking exists(); use UUID.randomUUID for generated names.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-no-leaky-errors-logs -->
### sec-no-leaky-errors-logs — No exception text or request data in responses and logs

Responses return a constant error message and loggers receive constant text or non-tainted facts, so exception messages and request values are never echoed to clients or log lines. Trust the socket peer address rather than hand-read forwarded headers.
<!-- /harness-remediation -->
