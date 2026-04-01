# ProxyDLP — Context for Claude

## What is this project

ProxyDLP is a **Data Loss Prevention proxy** that intercepts TLS traffic between corporate endpoints and AI services (ChatGPT, GitHub Copilot, Claude, Gemini, etc.), extracts conversations and uploaded files, evaluates DLP rules, and provides a web dashboard for security teams.

## Service topology

```
Clients (browser / IDE plugin / agent)
    │ :8080 / :443
    ▼
HAProxy  ──── load balances across proxy replicas
    ▼
Proxy (mitmproxy, 2–10 replicas, Python)
    │ gRPC :50051
    ▼
Monitor (DLP rule engine + FAISS semantic search, Python, gRPC :50051)
    │
    ▼
MongoDB 6.0 (central DB — database "ProxyDLP")
    ▲
Web Console (Node.js/Express + EJS, :3000 internal)
    ▲
Nginx  ──── :80 (web), :8443 (ws-term WebSocket), :4443

Autoscaler — watches Docker memory stats, scales proxy replicas 2–10
```

Networks: `internal-net` (proxy ↔ monitor ↔ mongo ↔ web) and `web-net` (haproxy, nginx, autoscaler, web).

## Key directories

| Path | Language | Role |
|---|---|---|
| `proxy/src/` | Python 3.11 | mitmproxy addon; site handlers; gRPC server |
| `proxy/src/sites/` | Python | Per-AI-service interceptors (10 sites) |
| `monitor/src/` | Python | DLP rule evaluation, FAISS, file parsing |
| `web/` | Node.js 18 | Express web console + REST API |
| `web/views/` | EJS | Tailwind-styled templates |
| `web/agents.js` | Node.js | Agent registration/heartbeat API (no auth on register) |
| `proto/` | Protobuf | `proxy.proto` and `monitor.proto` — shared by proxy and web |
| `autoscaler/` | Python | Docker SDK autoscaler |
| `haproxy/` | HAProxy config | Injects `X-Forwarded-For` so proxy knows real client IP |
| `nginx_server/` | Nginx config | Reverse proxy + WebSocket for `/ws-term` |

## Proto / gRPC conventions

- `proto/proxy.proto` — service `Proxy` (port 50051 on each replica): `GetMitmStats`, `GetActiveSessions`, `SiteRejectEnabled`, `SiteMonitoringToggled`
- `proto/monitor.proto` — service `Monitor` (port 50051, single container): event notifications, rule reload, etc.
- **Proxy** compiles protos at Docker build time via `grpc_tools.protoc` (see `proxy/Dockerfile` lines 65–66). Generated `*_pb2.py` files are not committed.
- **Web** loads protos at runtime via `@grpc/proto-loader` (dynamic, no code generation needed).
- When adding a new RPC: update `proto/proxy.proto` → implement in `proxy/src/main.py` → add endpoint in `web/server.js`. The Dockerfile handles codegen automatically on rebuild.

## MongoDB collections (database: `ProxyDLP`)

| Collection | Key fields |
|---|---|
| `events` | `user`, `source_ip`, `site`, `rational`, `content`, `conversation_id`, `agent_id`, `timestamp`, `leak{}` |
| `agents` | `guid`, `ip`, `user`, `computer_name`, `os_version`, `ip_addresses`, `lastHeartbeat` |
| `users` | `username`, `password` (bcrypt), `permissions[]` |
| `sites` | `name`, `urls[]`, `enabled` |
| `domains` | `content` (allowed email domain) |
| `domain-settings` | `check_domain`, `allow_anonymous` |
| `regex_rules`, `topic_rules`, `yara_rules` | DLP rule definitions |
| `alert-rules`, `alert-destinations`, `alert-logs` | Alerting pipeline |
| `retention-settings` | `retentionDays` |

## Web permission scopes

`events`, `statistics`, `rules`, `sites`, `agents`, `user_management`, `alerts`, `mitmterminal`, `retention`, `playground`, `rawlogs`

Auth is cookie-based JWT. `authMiddleware` + `requirePermission(scope)` guard every route.

## Proxy session tracking (`proxy/src/main.py`)

Real client IP comes from `X-Forwarded-For` injected by HAProxy, stored in `_real_source_ips: dict[conn_id, ip]`.

IP→user mapping (`_ip_to_user: dict[ip, email]`) is populated from:
1. `account_login_callback` — user authenticates to an AI service
2. `account_check_callback` — domain check on an identified account
3. `conversation_callback` — email is present in the intercepted conversation

`GetActiveSessions` RPC iterates active connections, resolves IP then user (with MongoDB `agents` collection fallback for machines running the desktop agent but not yet logged into an AI service).

## Supported AI services

ChatGPT, GitHub Copilot, Microsoft Copilot, Claude (Anthropic), Gemini, DeepSeek, Perplexity, DeepL, Grok, BlackBox

Each site handler in `proxy/src/sites/` fires callbacks: `account_login_callback`, `account_check_callback`, `conversation_callback`, `attached_file_callback`.

## Environment variables (`.env` at repo root, never committed)

| Variable | Used by |
|---|---|
| `MONGO_INITDB_ROOT_PASSWORD` | mongo, web, proxy, monitor |
| `JWT_SECRET` | web, proxy |
| `COMPOSE_PROJECT_NAME` | autoscaler (default: `proxygpt`) |

`APP_VERSION` is set directly in `docker-compose.yml` on the `web-console` service and must be bumped manually when tagging.

## Release process

1. Bump `APP_VERSION` in `docker-compose.yml` (web-console environment)
2. Commit: `chore(app): update APP_VERSION to vX.Y.Z`
3. Tag: `git tag -a vX.Y.Z -m "vX.Y.Z\n\n## Changelog\n..."` — include changelog grouped by Features / Fixes / Refactors / Infrastructure
4. Previous tag for changelog base: `git log <prev-tag>..HEAD --oneline`

## Build & run

```bash
docker compose up --build          # full stack
docker compose up --build proxy    # rebuild only proxy after Python/proto changes
docker compose logs -f proxy       # follow proxy logs
```

CSS must be rebuilt when Tailwind classes change: `npm run build:css` (inside `web/`).
