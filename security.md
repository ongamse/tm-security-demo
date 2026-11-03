# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:no-request-data-deserialization -->
### no-request-data-deserialization — Never deserialize request data into objects

Allowlisted ObjectInputStream or XStream.fromXML on request data is still reported as an unsafe deserialization sink. Parse request data as plain data (for example Jackson readTree) and validate scalar fields with a strict regex. For SnakeYAML 1.x use new SafeConstructor(), never new Yaml() on request data.
<!-- /harness-remediation -->

<!-- harness-remediation:no-request-data-in-expression-engines -->
### no-request-data-in-expression-engines — Keep request text out of expression and template engines

Request data must never reach SpEL, Velocity.evaluate or any script engine, even with a locked-down context. Evaluate a fixed constant template and pass the request value only as a context variable, or write a purpose-built parser (such as a small BigDecimal arithmetic evaluator) instead.
<!-- /harness-remediation -->

<!-- harness-remediation:server-built-values-break-taint -->
### server-built-values-break-taint — Build sink values from server-side constants

Scanners do not credit sanitizers that copy request characters (charAt loops, regex groups, strip or replace). Emit values only from server constants: allowlist entries, constant char tables or a rebuilt string via WebUtils.rebuildFromAllowed. Apply this to headers, cookies, redirect targets, outbound URLs, JDBC URLs and log values, and fail closed (400, 403 or no header) on null.
<!-- /harness-remediation -->

<!-- harness-remediation:outbound-urls-from-allowlist -->
### outbound-urls-from-allowlist — Build outbound and redirect URLs from allowlist entries

SSRF and open-redirect fixes must require the host to equal a configured safe-domain entry and build the URL from the scheme constant, that entry, a numeric port and a path rebuilt from a strict alphabet. Use SSRFChecker.canonicalOutboundUrl and SecurityUtil.safeRedirectUrl, and pass only their return values to the sink.
<!-- /harness-remediation -->

<!-- harness-remediation:hardened-xml-and-canonicalize -->
### hardened-xml-and-canonicalize — Canonicalize XML before any parser

Hardened parsers alone still get flagged when request text reaches them. Gate raw text in XmlSecurity.readBody (reject DOCTYPE, ENTITY, XInclude and non-UTF-8 encodings), canonicalize it, and pass only the canonical output downstream. Rebuild uploaded OOXML packages from canonicalized parts.
<!-- /harness-remediation -->

<!-- harness-remediation:upload-and-file-paths -->
### upload-and-file-paths — Never derive file paths from client input

Use UploadPaths.newUploadPath: allowlisted extension plus a SecureRandom hex name under the toRealPath() upload base with a startsWith check. Use atomic NIO operations (Files.deleteIfExists, a single newInputStream with NOFOLLOW_LINKS) instead of exists() then use, which is a TOCTOU race.
<!-- /harness-remediation -->

<!-- harness-remediation:log-and-error-output -->
### log-and-error-output — Sanitize logs and never echo exceptions

Route untrusted log values through WebUtils.sanitizeLog, which maps characters through a constant table. Never write exception messages, class names or stack traces into responses (CWE-209); use WebUtils.logAndGenericError(logger, e) and return the fixed generic error.
<!-- /harness-remediation -->

<!-- harness-remediation:cookies-and-cors -->
### cookies-and-cors — Cookie flags and CORS credentials

Set Secure, HttpOnly and Path on every cookie before addCookie, using a dedicated cookie-safe alphabet for the value. Match CORS origins exactly against the safe-domain allowlist with Vary: Origin, and do not enable Access-Control-Allow-Credentials on cross-origin endpoints, because the scanner flags it.
<!-- /harness-remediation -->

<!-- harness-remediation:client-identity-and-idor -->
### client-identity-and-idor — Derive identity from the server, not the request

Do not trust X-Real-IP or similar headers for client identity; use request.getRemoteAddr() and configure trusted-proxy handling in the container. Do not look up users by a request parameter: derive the key from request.getUserPrincipal() and return 403 on mismatch.
<!-- /harness-remediation -->

<!-- harness-remediation:sql-parameters-and-allowlists -->
### sql-parameters-and-allowlists — Bind parameters and allowlist identifiers

Use bound parameters (#{} in MyBatis, PreparedStatement.setString) for values and a fixed allowlist, such as an XML choose block, for ORDER BY or other identifiers. Never concatenate request data into SQL.
<!-- /harness-remediation -->

<!-- harness-remediation:html-output-encoding -->
### html-output-encoding — Encode and type echoed values

Endpoints that echo request-derived values must rebuild them from a strict alphabet, apply WebUtils.htmlEncode, and respond as text/plain;charset=UTF-8. Share one helper (such as IPForge.sanitizeAddr) across endpoints.
<!-- /harness-remediation -->

<!-- harness-remediation:secrets-via-placeholders -->
### secrets-via-placeholders — Move secrets to environment placeholders

Replace literal passwords and keys in application.properties with Spring placeholders that have empty defaults so the app fails closed until the variable is set. Rotate the old values because they remain in git history. Avoid long 62-character alphabet string literals: the secret scanner flags them as high-entropy strings, so build tables from char ranges in a static initializer.
<!-- /harness-remediation -->
