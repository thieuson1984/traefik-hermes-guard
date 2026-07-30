# Hermes Guard — WAF Middleware for Traefik 3

Traefik 3 middleware plugin — intelligent WAF with pattern detection, rate limiting, GeoIP, Turnstile CAPTCHA, and Hermes Agent AI integration. Zero external dependencies, pure Go stdlib.

## Quick Start

```bash
# 1. Copy source to Traefik plugins directory
mkdir -p /opt/traefik/plugins/src/github.com/thieuson1984/
cp -r traefik-hermes-guard /opt/traefik/plugins/src/github.com/thieuson1984/

# 2. Configure Traefik (traefik.yml)
experimental:
  localPlugins:
    hermes-guard:
      moduleName: github.com/thieuson1984/traefik-hermes-guard

# 3. Add middleware (dynamic.yml)
http:
  middlewares:
    hermes-guard:
      plugin:
        hermes-guard:
          mode: "protect"
          redisAddr: "redis:6379"
          collectionsDir: "/etc/traefik/collections"
          minRiskScore: 0.5

  routers:
    myapp:
      rule: "Host(`myapp.example.com`)"
      middlewares: [hermes-guard]
```

## Defense Layers

| Order | Layer | What | Latency |
|-------|-------|------|---------|
| 1 | API Endpoints | Hermes callback API (auth) | ~0ms |
| 2 | Admin Dashboard | Stats / unblock / metrics (auth) | ~0ms |
| 3 | Excluded Paths | Regex bypass for health/webhooks | ~0ms |
| 4 | Local Requests | Auto-allow private IPs (opt-in) | ~0ms |
| 5 | Turnstile Verify | Captcha token verification | ~500ms |
| 6 | Challenge Check | Hermes-ordered challenge marker | ~0ms |
| 7 | GeoIP | Country block/challenge by CIDR | ~0ms |
| 8 | Rate Limiting | Sliding-window Redis counter | ~1ms |
| 9 | IP Lists (Lua) | Atomic blocklist + whitelist + verdict | ~1ms |
| 10 | Pattern Detection | 15 collections, 145+ regex patterns | ~0ms |
| 11 | Response Inspection | Data leak scan (credit cards, keys) | ~0ms |

## Configuration

### Environment Variables

```bash
HG_REDIS_ADDR=redis:6379
HG_REDIS_PASSWORD=
HG_REDIS_DB=0
HG_MODE=protect
HG_LOG_LEVEL=info
HG_MIN_RISK_SCORE=0.5
HG_CACHE_TTL=3600
HG_TURNSTILE_SITE_KEY=
HG_TURNSTILE_SECRET_KEY=
HG_WEBHOOK_URL=
HG_RATE_LIMIT_REQS=120
HG_RATE_LIMIT_WINDOW=60
HG_ADMIN_SECRET=
HG_HERMES_ENDPOINT=http://hermes-agent:8642
HG_HERMES_TOKEN=
HG_HERMES_BLOCK_WEBHOOK_SECRET=
```

### Full Config Reference

```yaml
http:
  middlewares:
    hermes-guard:
      plugin:
        hermes-guard:

          # Core
          mode: "protect"           # monitor | protect
          silentStartUp: false
          logLevel: "info"          # debug | info | warn | error
          adminEnabled: true
          fallbackWhenError: true   # pass through on panic
          httpStatusCodeDenied: 403
          redirectUrlIfDenied: ""

          # Hermes Agent
          hermesEndpoint: ""
          hermesToken: ""
          hermesTLSInsecure: false
          hermesTLSCAFile: ""
          hermesRetryEnabled: true
          hermesRetryInterval: 30
          hermesBlockWebhookURL: "/webhooks/traefik-block-events"
          hermesBlockWebhookSecret: ""
          hermesAnalyzeURL: "/webhooks/hermes-guard-analyze"

          # Redis
          redisAddr: ""
          redisPassword: ""
          redisDB: 0

          # Detection
          minRiskScore: 0.5
          cacheTTL: 3600
          maxBodySize: 1048576

          # Rate Limiting
          rateLimitReqs: 120
          rateLimitWindow: 60
          rateLimitBlockTTL: 300

          # Collections (auto-load all *.json)
          collectionsDir: "/etc/traefik/collections"
          patternsFile: ""          # legacy fallback
          patternsWatchSec: 60

          # Profile (ban vs captcha per category)
          profileFile: "/etc/traefik/profile.json"

          # Pages
          banPageFile: "/etc/traefik/hermes-ban.html"
          captchaPageFile: "/etc/traefik/hermes-captcha.html"

          # Turnstile
          turnstileSiteKey: ""
          turnstileSecretKey: ""

          # Cloudflare
          trustCFHeaders: false

          # GeoIP
          geoipDBFile: "/etc/traefik/geoip.json"
          blockCountries: []
          challengeCountries: []
          blackListMode: false
          addCountryHeader: false

          # IP Lists (CIDR supported)
          trustedProxies: []
          ipWhitelist: ["127.0.0.1"]
          ipBlacklist: []

          # Inline patterns (fallback)
          suspiciousPatterns: []

          # Notifications
          webhookURL: ""
          adminSecret: ""

          # Paths to skip
          excludedPathPatterns:
            - "^[^/]+/health$"
            - "^[^/]+/ping$"

          # Response inspection
          inspectResponses: false
          allowLocalRequests: false
```

## Hermes Agent Integration

### Admin API (requires `?secret=<adminSecret>`)

| Endpoint | Action |
|----------|--------|
| `/api/block?ip=X&ttl=N` | Block IP |
| `/api/unblock?ip=X` | Remove from blocklist |
| `/api/challenge?ip=X&ttl=N` | Mark for captcha on next visit |
| `/api/whitelist?ip=X` | Add to whitelist |
| `/api/unwhitelist?ip=X` | Remove from whitelist |
| `/api/status?ip=X` | Query IP state |

### Collection Management

| Endpoint | Method | Action |
|----------|--------|--------|
| `/api/collections/list` | GET | List all collections |
| `/api/collections/update?name=X` | POST | Create/update collection |
| `/api/collections/delete?name=X` | GET | Delete collection |
| `/api/collections/reload` | GET | Reload all collections |

### Block Notifications (POST to Hermes)

```json
{
  "ip": "203.0.113.50",
  "host": "example.com",
  "rule": "sqli",
  "method": "GET",
  "service": "/products?id=1+UNION+SELECT",
  "time": "2026-07-30T...",
  "reason": "sqli"
}
```

### Analyze Telemetry (POST to Hermes)

```json
{
  "ip": "...",
  "path": "/...",
  "method": "GET",
  "host": "example.com",
  "risk_score": 0.70,
  "categories": ["sqli"],
  "matched_patterns": ["UNION SELECT"],
  "body_snippet": "...",
  "user_agent": "..."
}
```

## Advanced Features

### Rate Limit by Path
```yaml
rateLimitPaths:
  - {path: "/login", maxReqs: 5, window: 60}
  - {path: "/api", maxReqs: 60, window: 60}
```

### Honeypot Mode
```yaml
honeypotPaths:
  - "/wp-admin"
  - "/\.env$"
```
Alerts Hermes + blocks immediately on access.

### AbuseIPDB Reputation
```yaml
abuseIPDBKey: "your-api-key"
abuseIPDBThreshold: 80
```
Checks IP against AbuseIPDB on first request. Blocks if confidence score ≥ threshold.

### Multi-Tenancy Profiles
```yaml
hostProfiles:
  - {host: "api.example.com", mode: "monitor", minRiskScore: 0.3}
  - {host: "admin.example.com", mode: "protect", minRiskScore: 0.7, blockCountries: ["CN","RU"]}
```

### Slack/Discord Webhook
```yaml
webhookURL: "https://hooks.slack.com/services/..."
```
Formatted messages with color-coded fields (blocked=red, challenged=yellow).

### GeoIP Auto-Update
```yaml
geoipUpdateURL: "https://example.com/geoip.json"
geoipUpdateIntervalH: 24
```
Cron goroutine fetches updated geoip.json periodically.

### JA3 Fingerprinting
```yaml
ja3BlockList:
  - "GET_HTTP/1.1_curl/7.88"
  - "POST_HTTP/1.1_python-requests/2"
```
Blocks known bot fingerprints before pattern detection.

### Hermes AI Feedback Loop
```yaml
hermesFeedbackEnabled: true
```
Tracks Hermes block accuracy at `/.hermes-guard/feedback?secret=...`.

```json
{
  "ip": "...",
  "path": "/...",
  "method": "GET",
  "host": "example.com",
  "risk_score": 0.70,
  "categories": ["sqli"],
  "matched_patterns": ["UNION SELECT"],
  "body_snippet": "...",
  "user_agent": "..."
}
```

## Collections (15 categories, 145+ patterns)

Drop `.json` files into `config/collections/`:

| File | Category | Patterns |
|------|----------|----------|
| `sqli.json` | SQL Injection | 7 (union, blind, tautology, time-based, procedures) |
| `xss.json` | Cross-Site Scripting | 9 (script, js:uri, handlers, eval, encoded) |
| `path-traversal.json` | Path Traversal / LFI | 5 (dot-dot, system files, wrappers, unicode) |
| `cmd-injection.json` | Command Injection | 6 (unix, windows, pipe, backtick, reverse shell) |
| `xxe.json` | XML External Entity | 4 (entity, parameter, doctype, xinclude) |
| `ssti.json` | Server-Side Template Injection | 4 (generic, jinja2, freemarker, velocity) |
| `ssrf.json` | Server-Side Request Forgery | 4 (schemes, metadata, url-param, encoded) |
| `nosql-injection.json` | NoSQL Injection | 3 (mongodb, js, json) |
| `code-injection.json` | Code Injection | 4 (php, jsp, asp, python) |
| `webshell.json` | Web Shells | 3 (filenames, eval, obfuscated) |
| `scanner.json` | Scanner Signatures | 12 (sqlmap, nikto, nessus, burp, metasploit...) |
| `header-injection.json` | HTTP Header Injection | 4 (crlf, raw, host, encoded) |
| `ldap-injection.json` | LDAP Injection | 3 (filters, wildcard, auth-bypass) |
| `open-redirect.json` | Open Redirect | 3 (url-param, encoded, protocol-relative) |
| `cve.json` | CVE Signatures | 25 (Log4Shell, Spring4Shell, Shellshock, Confluence...) |

Delete a file → removed on next reload. Add a file → auto-loaded.

## Profile (Ban vs Captcha)

`config/profile.json` maps categories to actions:

```json
{
  "rules": {
    "cve": "ban",
    "sqli": "ban",
    "xss": "ban",
    "path-traversal": "captcha",
    "scanner": "captcha",
    "rate_limit": "captcha",
    "geoip": "ban"
  },
  "default_action": "ban"
}
```

If `captcha` → Turnstile page shown. Turnstile keys must be configured.

## Project Structure

```
├── hermes_guard.go       # Main middleware (Config, ServeHTTP, APIs)
├── hermes_client.go      # Hermes HTTP client (health, notify, webhook)
├── detector.go           # Pattern scanner with hot-reload
├── cache.go              # Redis + in-memory cache + Lua EVAL
├── resp_client.go        # Redis RESP protocol client + connection pool
├── types.go              # Shared types, interfaces
├── geoip.go              # CIDR country lookup engine
├── hermes_guard_test.go  # Tests
├── config/
│   ├── dynamic.yml       # Plugin config reference
│   ├── traefik.yml       # Static config reference
│   ├── profile.json      # Ban/captcha action mapping
│   ├── geoip.json        # Country CIDR database
│   ├── collections/      # Pattern collection files (15 files)
│   ├── hermes-ban.html   # Access denied page
│   └── hermes-captcha.html # Turnstile challenge page
├── docker-compose.yml    # Dev stack (Traefik + Redis)
├── .env.example          # Environment template
├── .traefik.yml          # Plugin catalog manifest
├── Makefile              # Build/test helpers
└── go.mod                # Module: github.com/thieuson1984/traefik-hermes-guard
```

## Troubleshooting

| Symptom | Check |
|---------|-------|
| No logs at all | `logLevel: debug`, check Traefik logs for `[hermes-guard]` |
| No blocks | `mode: protect`, `minRiskScore: 0.5`, verify collections loaded |
| All requests allowed | `allowLocalRequests: false`, remove private ranges from whitelist |
| Captcha loop | Check `captcha passed` log for `blocked=true` |
| Hermes not notified | Verify `hermesEndpoint`, `hermesBlockWebhookSecret` |
| Admin 403 | Add `?secret=<adminSecret>` to URL |
| Redis connection failed | Check `redisAddr`, Redis container running |

## License

MIT — See [LICENSE](LICENSE)
