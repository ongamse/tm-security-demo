# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sql-injection -->
### sql-injection — Bind SQL parameters; allowlist ORDER BY columns

Never concatenate request data into SQL or MyBatis ${}. Use PreparedStatement or #{} bound parameters. ORDER BY cannot be bound, so map the input through a fixed column allowlist before calling the mapper. Derive per-user lookup keys from the authenticated Principal, never from a request parameter.
<!-- /harness-remediation -->

<!-- harness-remediation:xxe-parsers -->
### xxe-parsers — Create XML parsers only through a hardened factory

Build every DOM/SAX/XMLReader/Digester/SAXBuilder parser from one central hardened factory (secure processing on, DOCTYPE and external entities and XInclude off, fail closed if a feature is unsupported). Check library API names against the versions in pom.xml before use, for example commons-digester3 takes the reader through its constructor.
<!-- /harness-remediation -->

<!-- harness-remediation:deserialization -->
### deserialization — Authenticate serialized payloads before parsing

Class allowlists alone do not make ObjectInputStream or XStream.fromXML safe on attacker data. Verify an HMAC-SHA256 signature with a constant-time compare and a key from the environment, failing closed when the key is empty, before any deserialization. Apply the same gate to every new deserialization endpoint.
<!-- /harness-remediation -->

<!-- harness-remediation:secrets-config -->
### secrets-config — Keep credentials out of source and config defaults

Use env-backed placeholders such as ${NAME} with no committed default for passwords and keys, and wire them through docker-compose and the README. Delete unused payload or gadget constants. Credentials already in git history must be rotated. Long allowlist alphabets look like high-entropy secrets to scanners, so build them from character ranges.
<!-- /harness-remediation -->

<!-- harness-remediation:template-injection -->
### template-injection — Never use request data as template source

Evaluate fixed templates and pass user input only as an escaped context value. Request data must not become a template body or template name.
<!-- /harness-remediation -->

<!-- harness-remediation:url-fetch-redirect -->
### url-fetch-redirect — Rebuild outbound and redirect URLs from allowlist-owned values

Scanners keep treating sanitized request strings as tainted. Route every outbound fetch, JDBC URL and redirect through one chokepoint that parses with a strict regex, allows https and known ports, takes the host from the configured allowlist entry, and rebuilds path and query from closed alphabets. Use only the returned value. Decide internal-address checks on the host text before DNS.
<!-- /harness-remediation -->

<!-- harness-remediation:header-cors-jsonp -->
### header-cors-jsonp — Emit headers, CORS origins and JSONP callbacks from server-owned values

Do not reflect request strings into headers, cookies, Location or script responses. Percent-encode or rebuild values over a closed alphabet, return the allowlist's own origin or callback string, never use * with credentials, and add Vary: Origin on origin-dependent responses. Add new callback names to the JSONP allowlist.
<!-- /harness-remediation -->

<!-- harness-remediation:upload-paths-races -->
### upload-paths-races — Constrain file paths and open files once

Sanitize client file names to a closed alphabet, resolve against the real path of a fixed directory and check containment, and give every write or read sink only the returned Path. Avoid exists or isFile checks before reads. Open once with NOFOLLOW_LINKS. Use UUID.randomUUID() for unguessable names, not time-based UUIDs.
<!-- /harness-remediation -->

<!-- harness-remediation:log-forging -->
### log-forging — Log fixed messages, not request-derived values

The scanner does not credit logSafe-style helpers as log-forging sanitizers. In request-handling classes log only fixed strings, counters and exception class names, never URLs, hosts, paths, file names or exception messages.
<!-- /harness-remediation -->

<!-- harness-remediation:proxy-headers-exec -->
### proxy-headers-exec — Validate proxy headers and keep exec and eval on fixed inputs

Accept proxy-supplied headers such as X-Real-IP only from trusted proxies and only if they parse as literal IP addresses, then HTML-escape before output. Keep command and expression endpoints on fixed commands with strict-regex arguments, and restrict SpEL and Groovy input to a closed character set.
<!-- /harness-remediation -->
