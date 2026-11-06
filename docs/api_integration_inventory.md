# TTI — API Integration Inventory

Generated from live project state. Live source: `GET /api/v1/integrations`
and the dashboard page `/api-management`.

**No secret value appears in this document.** "Credential available" means the
environment variable is present and syntactically valid, nothing more.

## A. Discovered configurations

Configuration sources inspected:

| Source | Path | Result |
|---|---|---|
| Local env | `.env` | 2 real credentials (Telegram api_id/api_hash); bot token, session, webhook URL were **absent** |
| Env template | `.env.example` | Documents 30+ vars incl. bot token, session, webhook |
| Backend settings | `backend/app/core/config.py` | Single `Settings` class, `env_file=".env"` |
| Backend deps | `backend/requirements.txt`, `pyproject.toml` | aiogram, telethon, httpx, celery, redis |
| Frontend deps | `frontend/package.json` | No provider SDKs; only `VITE_TTI_API_MODE` |
| Frontend client | `frontend/src/services/api.ts` | Proxies `/api` → `127.0.0.1:8000` |
| Connectors | `backend/app/connectors/**` | Telegram MTProto + stub, dark-web stub |
| Docs | `docs/`, `README.md`, `vfra-engineering-org-blueprint/` | Policy + expected provider list |

## Inventory

| API provider | API purpose | API endpoint | Credential available | Existing implementation | Backend integration | Frontend integration | Test status | Dependent modules |
|---|---|---|---|---|---|---|---|---|
| Telegram MTProto (Telethon) | Live channel/group message collection feeding ingestion | my.telegram.org (api_id/api_hash) | Yes (api_id + api_hash) | Yes | Connected (code complete; inert until `TTI_MTPROTO_ENABLED=true` + session) | Connected — `/api-management`, `/mtproto/status` | Not tested (no `TTI_TELEGRAM_SESSION`) | `app.connectors.telegram.mtproto`, `app.services.mtproto_collector`, `app/api/v1/endpoints/mtproto.py` |
| Telegram Bot API (aiogram) | Consent bot: /start, consent capture, submissions, webhook intake | `https://api.telegram.org` | **No** (`TTI_TELEGRAM_BOT_TOKEN` empty) | Yes | Connected (code complete; unauthenticated) | Connected — `/api-management`, webhook route | Failed — `401 Unauthorized` on `getMe` with placeholder token | `app.adapters.telegram.bot`, `app.adapters.telegram.handlers`, `app/api/v1/endpoints/telegram_webhook.py` |
| Telegram webhook | Signed delivery of bot updates | `TTI_WEBHOOK_URL` | **No** (empty) | Yes | Connected (`/telegram/webhook` + constant-time secret check) | N/A (server-to-server) | Not tested (no public URL locally) | `app/api/v1/endpoints/telegram_webhook.py` |
| PostgreSQL 16 | Primary datastore (iam, threat, app, audit schemas) | `localhost:5432/tti_dev` | Yes (dev defaults) | Yes | Connected | Connected (health card) | Failed locally — nothing listening on 5432 | `app.database.session`, `observability.health.check_database_health` |
| Redis 7 | Celery broker, result backend, distributed rate limiter | `localhost:6379/0` | N/A (no password in dev) | Yes | Connected (circuit-breaker fallback active) | Connected (health card) | Failed locally — nothing listening on 6379 | `app.core.redis_breaker`, `app.workers.celery_app`, `app.core.rate_limit` |
| Celery worker mesh | Async ingestion/detection/alert/cleanup queues | redis broker | N/A | Yes | Connected (inline dispatcher default) | Connected (health card) | Passed — eager/inline mode healthy | `app.workers.celery_app`, `app.workers.detection_tasks` |
| Dark web (Tor SOCKS5) | Dark-web marketplace/leak collection | `socks5h://127.0.0.1:9050` | N/A | Yes (stub) | Connected but inert by policy | Connected — `/api-management` | Not tested (disabled by policy) | `app.connectors.darkweb.stub` |
| AI/LLM provider | Optional classification/summarisation behind `AIAnalysisEngineInterface` | none configured | **No** | Interface only | Not connected | Connected (reported as missing) | Not tested | `app.ai.interface` |
| IOC enrichment (VirusTotal / GreyNoise / AbuseIPDB / Shodan / ipinfo) | Domain/IP reputation for extracted URL indicators | none configured | **No** | Not built | Not connected | Connected (reported as missing) | Not tested | `app.detection.url_indicators` |

## B. Placement decisions

- Telegram MTProto → ingestion (**existing** `MTProtoTelegramConnector` → `ThreatService.ingest_batch` → `ThreatDetectionService.analyze_and_record`). **Not reimplemented.**
- Telegram Bot API → consent intake (**existing** aiogram dispatcher + webhook).
- PostgreSQL / Redis / Celery → infrastructure probes (**existing** `observability.health` functions reused by the registry; no duplicate clients).
- Dark web → collection stub (policy-gated).
- AI + IOC enrichment → left unbuilt. No credential was supplied and the deterministic local rule engine is the authoritative analyser. Inventing a client would violate "only integrate providers that are actually available".

## C. What was added (minimum diff)

| File | Purpose |
|---|---|
| `backend/app/integrations/registry.py` | Single inventory + probes + secret fingerprinting |
| `backend/app/integrations/__init__.py` | Package exports |
| `backend/app/api/v1/endpoints/integrations.py` | `GET /api/v1/integrations` |
| `backend/app/api/v1/api.py` | Router mount (2 lines) |
| `backend/app/observability/health.py` | `integrations` component in `/health` (static, no network) |
| `frontend/src/pages/ApiManagement.tsx` | API Management dashboard |
| `frontend/src/types/index.ts` | `ApiIntegration`, `ApiIntegrationsResponse` |
| `frontend/src/services/api.ts` | `ttiApi.integrations()` |
| `frontend/src/App.tsx`, `Sidebar.tsx` | `/api-management` route + nav |
| `.env` | Added the missing keys (empty, ready to fill) |
| `backend/tests/test_integrations_registry.py`, `test_integrations_api.py` | 6 tests |
| `frontend/src/test/ApiManagement.test.tsx` | 1 test |

## D. Missing credentials — exact actions

### `TTI_TELEGRAM_BOT_TOKEN` (blocks the consent bot)
1. Open @BotFather in Telegram → `/newbot` (or `/mybots` → API Token).
2. Set in `.env`: `TTI_TELEGRAM_BOT_TOKEN=123456789:AA...`
3. Set `TELEGRAM_MODE=polling` for local dev.
4. Verify: `curl https://api.telegram.org/bot<token>/getMe` → `"ok":true`.
5. Restart the backend. `/api/v1/integrations` flips auth to `authenticated`.

### `TTI_TELEGRAM_SESSION` (blocks live MTProto collection)
1. `cd backend && python -m app.cli mtproto-login`
2. Paste the printed StringSession into `TTI_TELEGRAM_SESSION`.
3. `python -m app.cli mtproto-login` requires your api_id/api_hash (already present).
4. Then **only after collection authorization**: `TTI_MTPROTO_ENABLED=true`.

### `POSTGRES_*` / `REDIS_*`
Already defaulted in `.env`. They fail only because no local service is listening —
start them with `docker compose up -d postgres redis` (Docker is not installed on
this machine) or install native services.

## E. Secrets policy in the dashboard

- Backend returns only `credential_fingerprint` = `configured (len=NN, sha256=xxxxxxxx)`.
- Boolean `credential_available` drives the missing/available badge.
- `test_integrations_api.py` asserts the raw values (bot token, session, api_hash,
  secret key) never appear in the response body.