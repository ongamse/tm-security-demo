# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters

Request values reach SQL through PreparedStatement placeholders and MyBatis #{} only, never string concatenation or ${}. ORDER BY columns cannot be bound, so UserMapper.xml selects them from an allowlisted choose block.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xml-parsers -->
### sec-xml-parsers — Harden XML parsers and XStream

Every XML parser that reads request data disables DOCTYPE declarations and external entities, and XInclude stays off. XStream uses a deny-by-default type allowlist instead of the default permissions.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-deserialization -->
### sec-deserialization — Allowlist deserialized types

ObjectInputStream wrappers accept only an exact allowlist of class names, and YAML is parsed with SafeConstructor. Add a new deserializable type to AntObjectInputStream.ALLOWED_CLASSES explicitly.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-path-confinement -->
### sec-path-confinement — Confine file paths

Request-supplied file names and paths are reduced to a base name or normalized and checked to stay under a fixed directory before any file I/O. Reuse FileUpload.resolveUploadPath for uploads.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-command-exec -->
### sec-command-exec — Run commands without a shell

Commands run as an argv array through ProcessBuilder with no sh -c, program names come from SecurityUtil.safeCommand, and arguments pass SecurityUtil.cmdFilter. Script and SpEL evaluation never receives request data as code.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-output-encoding -->
### sec-output-encoding — Encode HTML responses

Controllers return request-, header- or command-derived text through HtmlUtils.htmlEscape or the XSS.encode helper, because @RestController string returns default to text/html.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-ssrf-urls -->
### sec-ssrf-urls — Validate outbound URLs

Server-side fetches call SecurityUtil.isSafeOutboundUrl (http/https and an internal-address check on the resolved host) before connecting, and HTTP clients do not follow redirects. JDBC URLs built from request data go through SecurityUtil.isSafeJdbcUrl.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-redirect-targets -->
### sec-redirect-targets — Restrict redirect targets

Redirect destinations go through SecurityUtil.checkRedirectURL, which allows only single-slash relative paths or http(s) URLs on the safe-domain list, and rejects //host, backslashes and control characters.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-response-headers -->
### sec-response-headers — Sanitize response header values

Untrusted values written to response headers pass through SecurityUtil.sanitizeHeaderValue to strip CR, LF and other control characters.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-cors-origins -->
### sec-cors-origins — Allowlist CORS origins

Access-Control-Allow-Origin and Access-Control-Allow-Credentials are set only for origins accepted by SecurityUtil.checkURL, with Vary: Origin. Never reflect the Origin header or combine a wildcard with credentials.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-authz-identity -->
### sec-authz-identity — Bind lookups to the caller

User lookups by username or id check the authenticated principal (admin excepted) before returning a record, and client IP comes from request.getRemoteAddr() rather than X-Real-IP unless a trusted proxy is configured.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-jwt-claims -->
### sec-jwt-claims — Read JWT claims after verification

Claims come from the DecodedJWT returned by JWTVerifier.verify(), never from a separate JWT.decode of the same token. Request-derived Base64 goes through SafeBase64 with a length cap and alphabet check.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-config-secrets -->
### sec-config-secrets — Keep credentials out of properties files

Database passwords and access keys in application.properties are Spring placeholders filled from the environment. Credentials that were committed stay in git history and must be rotated.
<!-- /harness-remediation -->
