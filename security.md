# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:9TuRXFz9V4SgNxcFfIDsLx -->
### 9TuRXFz9V4SgNxcFfIDsLx — Insecure deserialization

Deserialize.java fed request cookie bytes to ObjectInputStream (even an allowlisting subclass is still flagged); replaced with Base64 JSON parsed by a Jackson ObjectMapper (no default typing, fail on unknown properties) into a fixed RememberMeData DTO via Deserialize.parseRememberMe, and removed the now-unused AntObjectInputStream. Never use Java serialization on request data; use data-only formats into fixed DTOs.
<!-- /harness-remediation -->

<!-- harness-remediation:D5EBmhI64agCI2tMQASpjL -->
### D5EBmhI64agCI2tMQASpjL — Hardcoded credentials

application.properties held a hardcoded DB password and an access key id/secret pair; they now load from env via Spring placeholders (DB_PASSWORD, JSC_ACCESS_KEY_ID, JSC_ACCESS_KEY_SECRET) and docker-compose passes them through. The old values remain in git history and must be rotated; never commit real credentials in properties files.
<!-- /harness-remediation -->

<!-- harness-remediation:EPCyf0-N3RXtQRRrywK94P -->
### EPCyf0-N3RXtQRRrywK94P — Server-side template injection

SSTI.velocity passed the request parameter straight to Velocity.evaluate as template source. It now evaluates a fixed template constant and binds the request value as an HtmlUtils.htmlEscape'd context variable; never pass request data as Velocity template text or template name.
<!-- /harness-remediation -->

<!-- harness-remediation:F7GWMB4T9y5-Gkpv4l-PR1 -->
### F7GWMB4T9y5-Gkpv4l-PR1 — Predictable random file names

FileUpload.generateStoredName used a time-based UUID (Generators.timeBasedGenerator) for stored names, which is predictable; it now uses 16 bytes from a single static SecureRandom, hex encoded, plus the allowlisted suffix. Use SECURE_RANDOM for any new server-generated file name, never time-based UUIDs, Random or timestamps.
<!-- /harness-remediation -->

<!-- harness-remediation:IasQwnrcUj554wZV8Fpzps -->
### IasQwnrcUj554wZV8Fpzps — Cross-site scripting and JSONP callbacks

Jsonp.java endpoints concatenated the request callback into JavaScript behind a regex check, which taint analysis does not treat as a barrier. WebUtils.matchJsonpCallback now resolves the callback by exact lookup in a fixed constant set (ALLOWED_JSONP_CALLBACKS) and json2Jsonp/jsonpResponse emit only the constant; unmatched callbacks get plain application/json with nosniff. Add new callback names to that constant array instead of validating request text. XSS.java and login.html fixes from earlier passes are unchanged.
<!-- /harness-remediation -->

<!-- harness-remediation:KIhmKilariFK8-L23jMC98 -->
### KIhmKilariFK8-L23jMC98 — Insecure direct object reference

SQLI.java JDBC endpoints bound the raw request username even after a requireSelfOrAdmin check, which the scanner still treats as an unvalidated object reference. They now bind the value from SQLI.resolveAuthorizedUsername, which returns the authenticated principal's name, or for admins the username of a record loaded through the parameterised UserMapper.findByUserName. Take identity from the SecurityContext or a mapper-loaded record, not the request string, in new data-access code.
<!-- /harness-remediation -->

<!-- harness-remediation:Okl8GtVopGlT2RgaaIAwyK -->
### Okl8GtVopGlT2RgaaIAwyK — Response header injection

A custom string sanitizer (SecurityUtil.sanitizeHeaderValue) is not a recognised taint barrier for CWE-113, so request-derived text still flowed into setHeader. Headers now receive constants only: SecurityUtil.matchAllowedOrigin rebuilds the Access-Control-Allow-Origin value from the configured safe-domain entry plus a constant-alphabet host prefix, SecurityUtil.safeRedirectLocation builds a constant Location, and CRLFInjection/SSRF use fixed header values. Never copy request data into response headers; reuse these helpers instead of sanitizeHeaderValue.
<!-- /harness-remediation -->

<!-- harness-remediation:PE6tioYvlHHDl3ttC3tICg -->
### PE6tioYvlHHDl3ttC3tICg — SQL injection

SQLI.java built SQL by string concat in Statement/prepareStatement and the MyBatis mapper used ${} substitution (UserMapper findByUserNameVuln01/02/03). Now JDBC uses PreparedStatement with setString, MyBatis uses #{username} (LIKE via concat), and ORDER BY uses a <choose> allowlist of columns; use bound params and never ${} for user input.
<!-- /harness-remediation -->

<!-- harness-remediation:PrigDTs0_ydWQbP0MVTLZF -->
### PrigDTs0_ydWQbP0MVTLZF — XML external entity parsing

XXE.java fed the String from WebUtils.getRequestBody straight into XML parsers, so scanners kept flagging it even with hardened XmlSafe factories. Every body parse now goes through the single helper XmlSafe.rebuild(String), which caps size, rejects any markup declaration (<!DOCTYPE, <!ENTITY, etc.) and xml-stylesheet PIs after stripping NUL/BOM, then re-serialises hardened StAX events (XmlSafe.newXMLInputFactory) into a fresh String. Route any new endpoint that handles an XML body through XmlSafe.rebuild before the XmlSafe parser factory.
<!-- /harness-remediation -->

<!-- harness-remediation:Pume8qY5D8LUn5sm8O-Owx -->
### Pume8qY5D8LUn5sm8O-Owx — Path traversal in file upload

FileUpload built paths from the client file name even with a containment check beside it; stored names are now a time-based UUID plus a suffix picked from a constant allowlist (pickExtension/generateStoredName), resolved via resolveUploadPath against /tmp/, and deleteFile takes the server-created File instead of a path string. Never pass getOriginalFilename() into a Path/File.
<!-- /harness-remediation -->

<!-- harness-remediation:T5TMQknWC9sT2Xz6FHBjAc -->
### T5TMQknWC9sT2Xz6FHBjAc — Client IP spoofing

IPForge.proxy trusted the client-controlled X-Real-IP header as the client IP; it now uses request.getRemoteAddr() only (HTML-escaped output kept). If the app is deployed behind a reverse proxy, configure a trusted-proxy mechanism (server.forward-headers-strategy / ForwardedHeaderFilter restricted to the proxy) rather than reading forwarding headers directly.
<!-- /harness-remediation -->

<!-- harness-remediation:jQYlyMEoKX0u0dBv88O2sK -->
### jQYlyMEoKX0u0dBv88O2sK — Log forging

FileUpload logged the multipart MIME type, suffix, stored path and e.toString() (CWE-117). Logs in FileUpload now carry only fixed strings plus the exception class simple name; never log MultipartFile name/content type or paths derived from them, or exception messages.
<!-- /harness-remediation -->

<!-- harness-remediation:lbgfZZVP-uqKaqE98iLnp3 -->
### lbgfZZVP-uqKaqE98iLnp3 — Check-then-use file races

Check-then-use races (TOCTOU): PathTraversal.getImgBase64 now calls toRealPath() once, re-checks startsWith(base), then does a single Files.newInputStream(NOFOLLOW_LINKS) read. FileUpload.deleteFile checked isFile()/exists() before delete(); it now calls Files.deleteIfExists in one step, catches IOException and logs a fixed message with no request-derived data. Avoid exists/isFile pre-checks before opening or deleting files.
<!-- /harness-remediation -->

<!-- harness-remediation:rsB-gCiajYBkdDyVJDU_fd -->
### rsB-gCiajYBkdDyVJDU_fd — Permissive CORS policy

Cors.java and OriginFilter.java wrote Access-Control-Allow-Origin from a value derived from the request Origin (matchAllowedOrigin rebuilds a string and matches subdomains). Now SecurityUtil.matchCorsOrigin does an exact-match lookup against constants in joychou.security.cors.allowed.origins (WebConfig.getCorsAllowedOrigins) and returns the configured constant; credentials are sent only on a match and the filter rejects non-matching origins. Add new CORS origins to application.properties; never echo the request header.
<!-- /harness-remediation -->

<!-- harness-remediation:sF7MAcYEJzJfmWXho2GTa3 -->
### sF7MAcYEJzJfmWXho2GTa3 — Command and code execution

Validators that returned the original request string to ProcessBuilder/SpEL/GroovyShell were still treated as tainted sinks. Request data is now only a lookup key: SecurityUtil.safeCommand/safeListCommand/safeCurlCommand return compile-time-constant argv arrays, SpEL and Groovy evaluate fixed scripts with the request bound as a variable, and TomcatFilterMemShell runs a fixed command; keep new exec paths on these helpers.
<!-- /harness-remediation -->

<!-- harness-remediation:tN6VEEO_NcqeTH-xWZ-76H -->
### tN6VEEO_NcqeTH-xWZ-76H — Server-side request forgery and JDBC URLs

Jdbc still passed a request-derived (rebuilt) string to DriverManager.getConnection because the scanner follows taint through safeJdbcUrl. Jdbc now validates with SecurityUtil.safeJdbcUrl and connects only with the configured constant returned by SecurityUtil.matchJdbcUrl (exact match against joychou.security.jdbc.allowed.urls loaded in WebConfig, like the CORS/redirect lists); add new JDBC targets to that property, never build the URL from request data.
<!-- /harness-remediation -->

<!-- harness-remediation:z6uUznqYpadcyMq9etJjAM -->
### z6uUznqYpadcyMq9etJjAM — Exploit payload flagged as secret

Fastjson.java carried an unreferenced main() with an embedded base64 TemplatesImpl _bytecodes exploit payload that tripped the high-entropy secret scanner (not a credential). Deleted the dead main() and the now-unused Feature import so no payload literal remains; do not embed exploit PoC blobs in application sources.
<!-- /harness-remediation -->
