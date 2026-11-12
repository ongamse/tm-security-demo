# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters

Request values reach MyBatis and JDBC only through #{} placeholders or PreparedStatement parameters; ORDER BY columns come from a fixed allowlist, never from ${} interpolation.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-owner-binding -->
### sec-owner-binding — Bind lookups to the authenticated user

User-record endpoints in SQLI.java check the requested username against the Spring Security principal (admin excepted) and return 403 otherwise, so a caller-supplied id never selects another user's data.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-exec-no-request-values -->
### sec-exec-no-request-values — Keep request values out of process and expression execution

Commands and SpEL expressions are chosen from server-side tables by exact match, and directory listings use java.nio under a configured base; no request string is passed to ProcessBuilder or an expression parser.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-path-containment -->
### sec-path-containment — Resolve file paths once and check containment

File access goes through one helper that rejects traversal input, resolves the canonical path, verifies it stays under the base directory and opens only that resolved path, which also removes the check-then-read race.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xml-hardening -->
### sec-xml-hardening — Parse XML only with hardened parsers

All XML from requests is parsed by JDK parsers with DOCTYPE and external entities disabled; library parsers (jdom2, Digester, XStream) are fed through them or replaced by explicit field binding instead of being used directly on request bodies.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-no-native-deserialization -->
### sec-no-native-deserialization — Do not deserialize request data into objects

The /xstream endpoint binds a fixed set of validated fields into User from a DOCTYPE-free document, and rememberMe is JSON bound to a concrete type with default typing off, so no request-controlled class names are instantiated.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-ssrf-public-only -->
### sec-ssrf-public-only — Fetch only public targets and connect to the checked address

Outbound requests parse the URL strictly, allow only http/https on approved ports, resolve the host once to public addresses and connect to that address with redirects disabled; JDBC URLs are rebuilt from validated host, port and database name.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-origin-allowlist -->
### sec-origin-allowlist — Exact-match CORS origins and redirect targets

Access-Control-Allow-Origin is set only when the request Origin equals an entry of the configured allowlist, and redirects go only to same-site paths or allowlisted hosts, falling back to a fixed default.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-output-encoding -->
### sec-output-encoding — Encode output for its context

Reflected values are HTML-escaped and returned as text/plain, JSONP callback names must be plain identifiers with the body serialized by Jackson and nosniff set, and response header values are restricted to a safe character set.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-no-client-ip-headers -->
### sec-no-client-ip-headers — Trust only the TCP peer address

The application takes the client address from request.getRemoteAddr(); X-Forwarded-For is not read in application code, so forwarded-header handling belongs in the container configured with explicit trusted proxies.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-error-and-log-hygiene -->
### sec-error-and-log-hygiene — Do not leak exceptions or log raw request data

Controllers log exceptions server-side and return a generic message, and request-derived values are sanitized before logging to prevent log forging.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-no-secrets-in-source -->
### sec-no-secrets-in-source — Keep secrets and exploit payloads out of source

Credentials and exploit blobs are not committed, including in demo main methods; rotate any secret that has been committed and load it from configuration or a secret manager.
<!-- /harness-remediation -->
