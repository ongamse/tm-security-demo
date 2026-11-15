# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:1TNIlXd3U4ONx6irN90iHA -->
### 1TNIlXd3U4ONx6irN90iHA — JwtUtils hardcoded the HMAC secret "123456" (and a base64 copy) in static fields

JwtUtils hardcoded the HMAC secret "123456" (and a base64 copy) in static fields. The key is now a byte[] loaded once from env JWT_SECRET or system property jwt.secret, falling back to a SecureRandom 32-byte per-process key; never commit a literal signing key, and set JWT_SECRET in deployments so tokens survive restarts.
<!-- /harness-remediation -->

<!-- harness-remediation:2xwtkvh_bK7Xa6UOOz5iGa -->
### 2xwtkvh_bK7Xa6UOOz5iGa — JwtUtils.getNicknameByJavaJwt verified the token but then re-parsed it with JWT.decode (unverified)

JwtUtils.getNicknameByJavaJwt verified the token but then re-parsed it with JWT.decode (unverified). It now reads claims from the DecodedJWT returned by JWTVerifier.verify (HMAC256 pinned, so unsigned/alg=none and expired tokens fail closed). Always use the verifier return value, never JWT.decode, for claims.
<!-- /harness-remediation -->

<!-- harness-remediation:9TuRXFz9V4SgNxcFfIDsLx -->
### 9TuRXFz9V4SgNxcFfIDsLx — rememberMe cookies were Java-deserialized even after HMAC verification and an allowlist stream

rememberMe cookies were Java-deserialized even after HMAC verification and an allowlist stream; RememberMeCodec now signs a plain-text username:expiry payload and readVerified parses it with a strict regex, so no ObjectInputStream touches cookie data. Never deserialize cookie-derived bytes; use signed text/JSON formats.
<!-- /harness-remediation -->

<!-- harness-remediation:D5EBmhI64agCI2tMQASpjL -->
### D5EBmhI64agCI2tMQASpjL — application.properties committed a DB password and a cloud access key pair

application.properties committed a DB password and a cloud access key pair; they are now Spring placeholders (${DB_PASSWORD:}, ${JSC_ACCESS_KEY_ID:}, ${JSC_ACCESS_KEY_SECRET:}) fed from env via docker-compose. Never commit credentials in properties files; the old access key must be rotated since it remains in git history.
<!-- /harness-remediation -->

<!-- harness-remediation:EPCyf0-N3RXtQRRrywK94P -->
### EPCyf0-N3RXtQRRrywK94P — SSTI.velocity passed the request parameter as Velocity template source to Velocity.evaluate

SSTI.velocity passed the request parameter as Velocity template source to Velocity.evaluate. Now the template is a fixed constant and the parameter is HTML-escaped (Spring HtmlUtils.htmlEscape) and put in the VelocityContext as data only; never evaluate request data as a template.
<!-- /harness-remediation -->

<!-- harness-remediation:F7GWMB4T9y5-Gkpv4l-PR1 -->
### F7GWMB4T9y5-Gkpv4l-PR1 — FileUpload used a time-based UUID generator (predictable) for stored upload names

FileUpload used a time-based UUID generator (predictable) for stored upload names; replaced with a static SecureRandom producing 16 hex-encoded bytes in FileUpload.randomName(), keeping the allowlisted extension and path containment check. Use SecureRandom for any unguessable file name in this repo.
<!-- /harness-remediation -->

<!-- harness-remediation:IasQwnrcUj554wZV8Fpzps -->
### IasQwnrcUj554wZV8Fpzps — Jsonp.java reflected the request callback into the response through response.getWriter()

Jsonp.java reflected the request callback into the response through response.getWriter(); callback is now allowlisted/rebuilt (WebUtils.isValidJsonpCallback/rebuildJsonpCallback), JSON escaped with WebUtils.escapeJsonForScript, and the body is written as UTF-8 bytes via getOutputStream() with Content-Length, nosniff and a JS content type. Route all JSONP output through Jsonp.writeBody.
<!-- /harness-remediation -->

<!-- harness-remediation:KIhmKilariFK8-L23jMC98 -->
### KIhmKilariFK8-L23jMC98 — SQLI.jdbc_* handlers bound the raw username request parameter into JDBC

SQLI.jdbc_* handlers bound the raw username request parameter into JDBC. Now SQLI.resolveEffectiveUsername enforces checkOwnerOrAdmin (403 before JDBC) and binds the principal name (non-admin) or the server-side userMapper lookup result (admin); passwords are no longer returned. Derive sink values from the principal, not from request parameters.
<!-- /harness-remediation -->

<!-- harness-remediation:Okl8GtVopGlT2RgaaIAwyK -->
### Okl8GtVopGlT2RgaaIAwyK — Response headers were set from strings derived from request data (rebuilt Origin, Host built from th

Response headers were set from strings derived from request data (rebuilt Origin, Host built from the request URL). CORS now looks the lower-cased Origin up in a fixed map of configured safe domains and writes the map value (SecurityUtil.corsOrigin); Location/content-disposition values go through URLEncoder (SecurityUtil.safeHeaderValue); outbound clients no longer set an explicit Host header and let the HTTP client derive it from the pinned url.
<!-- /harness-remediation -->

<!-- harness-remediation:PE6tioYvlHHDl3ttC3tICg -->
### PE6tioYvlHHDl3ttC3tICg — SQLI.java and UserMapper used string concatenation and MyBatis ${} substitution for user input

SQLI.java and UserMapper used string concatenation and MyBatis ${} substitution for user input. Replaced these with bound parameters: JDBC PreparedStatement with setString, MyBatis #{username}, and concat('%', #{_parameter}, '%') for LIKE. ORDER BY cannot be bound, so the XML mapper now uses an allowlist <choose> over id, username and password. Use #{} by default and allowlist any dynamic identifier.
<!-- /harness-remediation -->

<!-- harness-remediation:PrigDTs0_ydWQbP0MVTLZF -->
### PrigDTs0_ydWQbP0MVTLZF — Untrusted XML from WebUtils.getRequestBody was parsed with per-site feature setting that scanners di

Untrusted XML from WebUtils.getRequestBody was parsed with per-site feature setting that scanners did not recognise; added org.joychou.util.XmlUtils (secure SAXParserFactory/SAXParser, SAXBuilder, Digester factories, sanitizeXml pre-check, xlsx part checker) and routed the jdom2, Digester, XStream and xlsx-streamer parse sites through it. Round 2: Digester.parse(Reader) in XXE.java still used the Digester's default parser, so newSecureDigester() now returns new Digester(newSecureSaxParser()) and the controllers parse an InputSource of the sanitized body. New XML parse sites here should call Xm
<!-- /harness-remediation -->

<!-- harness-remediation:Pume8qY5D8LUn5sm8O-Owx -->
### Pume8qY5D8LUn5sm8O-Owx — FileUpload built paths from client filename pieces

FileUpload built paths from client filename pieces; now stored names are server-generated (UUID + regex-allowlisted extension) via newUploadPath with startsWith(realRoot) check, content is validated in memory (no temp file). PathTraversal.getImgBase64 uses toRealPath + startsWith and reads through an opened channel to avoid check-then-read.
<!-- /harness-remediation -->

<!-- harness-remediation:T5TMQknWC9sT2Xz6FHBjAc -->
### T5TMQknWC9sT2Xz6FHBjAc — IPForge.proxy trusted the client-supplied X-Real-IP header as the client IP

IPForge.proxy trusted the client-supplied X-Real-IP header as the client IP; it now uses only request.getRemoteAddr() (still HTML-escaped) because the repo has no trusted-proxy configuration. If forwarding headers are needed later, add a trusted-proxy allowlist and honor them only when getRemoteAddr() is in it.
<!-- /harness-remediation -->

<!-- harness-remediation:jQYlyMEoKX0u0dBv88O2sK -->
### jQYlyMEoKX0u0dBv88O2sK — SQLI.java logged request/DB-derived values, PreparedStatement.toString() and exception text directly

SQLI.java logged request/DB-derived values, PreparedStatement.toString() and exception text directly. Now every logger call uses a constant message, SQLI.sanitizeForLog(...) for DB values, or e.getClass().getSimpleName() for exceptions; never log statements or exception messages built from user input.
<!-- /harness-remediation -->

<!-- harness-remediation:rsB-gCiajYBkdDyVJDU_fd -->
### rsB-gCiajYBkdDyVJDU_fd — CORS handlers echoed the request Origin (or '*') with Allow-Credentials and no allowlist

CORS handlers echoed the request Origin (or '*') with Allow-Credentials and no allowlist. Cors.vuls1/vuls2 now echo Origin only when SecurityUtil.checkURL (url_safe_domain.xml allowlist) accepts it and add Vary: Origin; seccode and OriginFilter only emit ACAO/ACAC for a non-null validated origin; CustomCorsConfig sets explicit allowedOrigins so credentials are never paired with an open origin. Reuse SecurityUtil.checkURL for any new CORS endpoint.
<!-- /harness-remediation -->

<!-- harness-remediation:sF7MAcYEJzJfmWXho2GTa3 -->
### sF7MAcYEJzJfmWXho2GTa3 — Request values for command execution are only Map lookup keys (SecurityUtil.fixedCommand/fixedDir, C

Request values for command execution are only Map lookup keys (SecurityUtil.fixedCommand/fixedDir, CommandInject.FIXED_HOSTS) resolving to fixed argv; SpEL evaluates a constant expression with input bound as a variable. Rce.groovyshell now evaluates only fixed Groovy scripts chosen via FIXED_GROOVY_SCRIPTS key lookup (no request data compiled, SecureASTCustomizer removed), and RMI.Server no longer starts a registry or exports objects; never pass request data into GroovyShell/ScriptEngine source.
<!-- /harness-remediation -->

<!-- harness-remediation:tN6VEEO_NcqeTH-xWZ-76H -->
### tN6VEEO_NcqeTH-xWZ-76H — User URLs used to reach URL/InetAddress/connection sinks after a boolean check

User URLs used to reach URL/InetAddress/connection sinks after a boolean check; every outbound request now goes through SecurityUtil.safeTarget(String), which parses to java.net.URI, enforces scheme/host/port/no-userinfo, resolves and validates all addresses, and returns a SafeTarget rebuilt from validated components (pinned IP for http, validated canonical host plus a connect-time address re-check in PinnedSslSocketFactory for https). New outbound code in this repo must consume SafeTarget.getClientUrl()/SecurityUtil.openConnection, never the raw string.
<!-- /harness-remediation -->

<!-- harness-remediation:z6uUznqYpadcyMq9etJjAM -->
### z6uUznqYpadcyMq9etJjAM — Fastjson.java embedded a base64 TemplatesImpl exploit payload in an unused demo main()

Fastjson.java embedded a base64 TemplatesImpl exploit payload in an unused demo main(); removed the main and its unused Feature import so no high-entropy literal remains. Keep exploit payloads out of source; load from test resources or env if needed.
<!-- /harness-remediation -->
