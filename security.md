# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:PE6tioYvlHHDl3ttC3tICg -->
### PE6tioYvlHHDl3ttC3tICg — SQL injection

SQLI.java built SQL by concatenation (JDBC Statement / prepareStatement with concatenated string) and passed user input to MyBatis ${} sinks (order by, like, annotation @Select). Use PreparedStatement with ? and setString, MyBatis #{} (with <bind> for LIKE), and for ORDER BY identifiers pass only values from a constant allowlist (SQLI.allowedSortColumn) since identifiers cannot be bound; SecurityUtil.sqlFilter alone is a regex and not sufficient.
<!-- /harness-remediation -->

<!-- harness-remediation:PrigDTs0_ydWQbP0MVTLZF -->
### PrigDTs0_ydWQbP0MVTLZF — XML external entities

XXE.java: SAXBuilder endpoints now parse through a DocumentBuilderFactory hardened inline (disallow-doctype-decl, external entities off, XIncludeAware false, secure processing) and convert with jdom2 DOMBuilder; Digester endpoints use new Digester(SAXParser) from an inline-hardened SAXParserFactory. The scanner still flagged SAXBuilder.build and Digester.parse after setFeature hardening, so prefer the factory-based pattern for new parsers. xlsx-streamer 2.0.0 uses its own unsafe parser; the root fix is upgrading it to 2.1.0+ (needs POI alignment in pom.xml), and the DOCTYPE byte pre-scan in xlsxStreamerXXE is a stopgap.
<!-- /harness-remediation -->

<!-- harness-remediation:Pume8qY5D8LUn5sm8O-Owx -->
### Pume8qY5D8LUn5sm8O-Owx — Path traversal

PathTraversal.getImgBase64 built a Path from the request filepath; it now accepts only a bare image file name (no separators, extension allowlist) and opens the matching entry returned by Files.list on a fixed server-side directory (user.dir, /tmp), so request text never forms the opened Path. Do the same for any by-name file read instead of resolving user paths.
<!-- /harness-remediation -->

<!-- harness-remediation:T5TMQknWC9sT2Xz6FHBjAc -->
### T5TMQknWC9sT2Xz6FHBjAc — Client IP spoofing

IPForge.proxy trusted the client-controlled X-Real-IP header as the client IP; it now uses request.getRemoteAddr() only. If a reverse proxy is needed, configure the container's trusted-proxy handling (forward-headers strategy / RemoteIpValve with an internal proxy allowlist) instead of reading headers in controllers.
<!-- /harness-remediation -->

<!-- harness-remediation:jQYlyMEoKX0u0dBv88O2sK -->
### jQYlyMEoKX0u0dBv88O2sK — Log forging

The scanner does not treat a custom log-sanitizer helper as a CWE-117 sanitizer, so request-derived values (bodies, URLs, hosts, file paths, exception messages) still counted as reaching log calls. Fixed at the sink by logging constant messages plus non-tainted facts only (body/url length, boolean presence, exception class name) and deleting the unused org.joychou.util.LogSanitizer; do not log request-derived values in this repo.
<!-- /harness-remediation -->

<!-- harness-remediation:rsB-gCiajYBkdDyVJDU_fd -->
### rsB-gCiajYBkdDyVJDU_fd — Overly permissive CORS

CORS was opting in to credentialed cross-site requests via allowCredentials(true) in CustomCorsConfig and Access-Control-Allow-Credentials: true in SecurityUtil.applyCorsHeaders. Now allowCredentials(false) and no Allow-Credentials header; the allowlist-equals loop, constant Allow-Origin and Vary: Origin are kept. Only enable credentials for an endpoint that truly needs cookies, with an exact-origin allowlist.
<!-- /harness-remediation -->

<!-- harness-remediation:sF7MAcYEJzJfmWXho2GTa3 -->
### sF7MAcYEJzJfmWXho2GTa3 — Remote code execution

The scanner does not treat regex/allowlist helpers (SecurityUtil.parseAllowedCommand, cmdFilter) as sanitizers, so request text still reached ProcessBuilder and the SpEL parser. Request values are now only keys into server-side constant catalogues (org.joychou.security.FixedCommands.lookup for argv, a constant key->expression map in SpEL evaluated with SimpleEvaluationContext.forReadOnlyDataBinding); the executed argv/expression is never request-derived, and the Host-header curl demo was replaced by a constant message. Add new demo commands to FixedCommands rather than parsing request text; never add eval-style endpoints for request data, and keep javax.script (not jdk.nashorn) for the jsEngine endpoint.
<!-- /harness-remediation -->

<!-- harness-remediation:tN6VEEO_NcqeTH-xWZ-76H -->
### tN6VEEO_NcqeTH-xWZ-76H — Server-side request forgery

Validating a request URL and then passing the same string to new URI/HttpGet/Request.Get is still reported as SSRF. SecurityUtil.parseUrl (strict regex parser, no java.net.URI on request text) plus SecurityUtil.resolveOutboundTarget now rebuild the outgoing URI from validated components (constant http/https scheme, validated host, int port, decoded then re-encoded path/query via the multi-arg URI constructor) and resolve the host once; HttpUtils.pinnedGetBytes/pinnedRedirectLocation/request/httpClient request that rebuilt URI through the DNS-pinned client. Jdbc maps the request value to a constant JDBC URL in a server-side table (like SecurityUtil.resolveRedirectTarget). New outbound fetchers should go through SecurityUtil.resolveOutboundTarget + HttpUtils.pinnedClient, never the raw strin
<!-- /harness-remediation -->

<!-- harness-remediation:z6uUznqYpadcyMq9etJjAM -->
### z6uUznqYpadcyMq9etJjAM — High-entropy Base64 strings

Two high-entropy Base64 strings were found in source: a ~2KB TemplatesImpl demo gadget literal in Fastjson.java main() (left as is: a deliberate vulnerable-demo payload, not a credential; moving it to a resource file would only hide it from the scanner) and Base64 alias keys in the Jdbc.java target maps (removed: they duplicated the plain keys, and resolveJdbcTarget already decodes Base64 input and compares it to the server-side constants). Do not store encoded URLs as map keys; derive them at lookup time.
<!-- /harness-remediation -->
