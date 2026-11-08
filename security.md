# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:untrusted-input-selector -->
### untrusted-input-selector — Use request values as selectors, never as code or commands

Never pass request data to ProcessBuilder, SpEL, GroovyShell or Velocity. Map a request token to a server-owned constant with a switch or equals chain (see SafeCommands.lookup, SpEL.selectExpression, Rce.selectScript). Do not use Map.get on request input, and do not rely on filters or restricted contexts alone.
<!-- /harness-remediation -->

<!-- harness-remediation:xml-parse-canonical -->
### xml-parse-canonical — Parse XML only after whitelist canonicalization

Hardening parser flags is not enough. Route every XML sink through SecureXml.canonicalize, which rejects DOCTYPE, entities, processing instructions and oversize input and rebuilds the document from validated pieces. Upload packages such as xlsx must be rebuilt part by part before streaming.
<!-- /harness-remediation -->

<!-- harness-remediation:outbound-url-trusted-parts -->
### outbound-url-trusted-parts — Build outbound URLs and JDBC targets from trusted parts

Validating a request URL and re-parsing it still leaves it tainted. Assemble the target from a constant scheme, an int port and alphabet-table rebuilt host, path and query via the multi-argument URI constructor (ParsedUrl.toURI). JDBC endpoints must use the request value only as a lookup key into server-side URLs (JSC_JDBC_URL_POSTGRESQL, JSC_JDBC_URL_DB2). Revalidate every redirect hop.
<!-- /harness-remediation -->

<!-- harness-remediation:no-java-deserialization -->
### no-java-deserialization — Never deserialize request bytes

Do not run ObjectInputStream on request or cookie data, even with a class allowlist. The rememberMe cookie is a signed string (Base64 payload plus HMAC-SHA256) verified against the JSC_REMEMBERME_KEY environment variable, and it fails closed when the key is unset.
<!-- /harness-remediation -->

<!-- harness-remediation:cors-no-credentials -->
### cors-no-credentials — Do not emit credentialed CORS from shared policy

CorsPolicy.apply sets only Vary: Origin and an exact allowlist constant for Access-Control-Allow-Origin. Never send Allow-Credentials from the shared policy. Endpoints that need cookies cross-origin should be served same-site. Review BaseCorsFilter and WebSecurityConfig, which still call setAllowCredentials(true).
<!-- /harness-remediation -->

<!-- harness-remediation:header-cookie-values-rebuilt -->
### header-cookie-values-rebuilt — Build header and cookie values server-side

Stripping CR/LF is not enough for scanners or for safety. Use the SecurityUtil helpers (safeOrigin, safeRedirectLocation, safeFilename, whitelistRebuild, cookieValueRebuild, matchAllowlisted). Encode any request-derived cookie value with a standard encoder, and set Secure and HttpOnly on every servlet Cookie.
<!-- /harness-remediation -->

<!-- harness-remediation:redirect-constant-targets -->
### redirect-constant-targets — Redirect only to server-owned targets

Use the request value only as a lookup key into a constant map (URLRedirect.REDIRECT_TARGETS, URLWhiteList.REDIRECT_TARGETS) and never as the Location. Non-matching requests get 403.
<!-- /harness-remediation -->

<!-- harness-remediation:output-context-encoding -->
### output-context-encoding — Encode for the output context

HtmlUtils.htmlEscape is wrong for JSONP callbacks. Use WebUtils.safeCallback, send nosniff, return text/plain for non-HTML data, and keep th:inline=javascript away from request data. Escape fetched bodies and never return e.getMessage(); log the Throwable and return a constant such as Request failed.
<!-- /harness-remediation -->

<!-- harness-remediation:log-constant-messages -->
### log-constant-messages — Log constant messages, not request data

Do not concatenate request or principal values into log strings. Log the Throwable or a fixed message so log forging is not possible, and avoid dereferencing getUserPrincipal() before a null check.
<!-- /harness-remediation -->

<!-- harness-remediation:identity-from-verified-sources -->
### identity-from-verified-sources — Take identity from verified sources

Read JWT claims only from the verifier's return value, never from JWT.decode. Derive per-user keys from the authenticated principal rather than a request parameter, and use getRemoteAddr() instead of client-controlled forwarded headers unless the container is configured to trust the proxy.
<!-- /harness-remediation -->

<!-- harness-remediation:files-no-check-then-use -->
### files-no-check-then-use — Avoid check-then-use on file paths

Open a directory or file directly after a lexical containment check, then verify real-path containment on the open handle. Use SecureRandom names with Files.createFile (owner-only permissions) for uploads, and fetch URLs into memory before handing bytes to ImageIO.
<!-- /harness-remediation -->

<!-- harness-remediation:secrets-and-exploit-code -->
### secrets-and-exploit-code — Keep secrets and exploit payloads out of source

Datasource and cloud credentials are env-backed placeholders (JSC_DB_PASSWORD, JSC_ACCESS_KEY_ID, JSC_ACCESS_KEY_SECRET). Keys that were committed remain in git history and must be rotated. Do not keep encoded exploit gadgets or detonating main methods under src/.
<!-- /harness-remediation -->

<!-- harness-remediation:base-image-pinning -->
### base-image-pinning — Pin container base images to a supported OS release

The Dockerfile now uses eclipse-temurin:11-jre-jammy and a non-root user. The scanner still reported Alpine 3.14 as end-of-life after this change, so the owner should check which image or layer carries it, for example a third-party image or an older tag, and rebuild or replace that image.
<!-- /harness-remediation -->
