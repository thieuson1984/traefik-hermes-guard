# Changelog

## v2.0.0

### Core
- 20 Crowdsec-style collection files (170+ patterns)
- 11-layer defense model
- Profile system (ban vs captcha per category)
- Hermes Agent integration (13 API endpoints)
- Redis connection pool with Lua EVAL atomic checks
- In-memory cache fallback when Redis unavailable
- Pattern hot-reload from collections directory

### Features
- Cloudflare Turnstile CAPTCHA with HMAC verification
- GeoIP country blocking (CIDR-based, 107 networks)
- Rate limiting (global + per-path)
- IP blacklist/whitelist (CIDR-supported)
- Slack/Discord webhook notifications
- AbuseIPDB IP reputation check
- Honeypot mode (fake vulnerable paths)
- Scheduled time-based blocking rules
- Multi-tenancy host profiles
- JA3 TLS fingerprinting
- Request/Response body inspection
- Hermes AI feedback loop
- GeoIP auto-update cron

### APIs
- `/api/block`, `/api/unblock`, `/api/challenge`, `/api/whitelist`, `/api/unwhitelist`
- `/api/status`
- `/api/collections/list`, `/api/collections/update`, `/api/collections/delete`, `/api/collections/reload`
- `/.hermes-guard/admin`, `/.hermes-guard/metrics`, `/.hermes-guard/feedback`, `/.hermes-guard/audit`, `/.hermes-guard/health`

### Infrastructure
- Redis TLS support
- Configuration via dynamic.yml + environment variables
- Panic recovery with pass-through fallback
- Admin dashboard with live stats
- Prometheus metrics export
- Cloudflare CF-Connecting-IP support
- GitHub Actions CI workflow
- Dockerfile for validation

### Collections
sqli, xss, path-traversal, cmd-injection, xxe, ssti, ssrf, nosql-injection,
code-injection, webshell, scanner, header-injection, ldap-injection,
open-redirect, cve, csrf, file-upload, http-smuggling, cors, jwt

## v1.0.0
- Initial release with basic pattern detection and Redis caching
