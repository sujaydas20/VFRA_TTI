# REPORT: Why API Is Offline & Not Connected to TTI System

Date: 11-06-2026

## Root Cause

**The backend API process is simply not running.** A live probe on
`GET http://127.0.0.1:8000/api/v1/health` and
`GET http://127.0.0.1:8000/api/v1/connectors` returned
`Unable to connect to the remote server` — nothing is listening on port 8000.

Evidence gathered:

| Check | Result |
|---|---|
| `Invoke-WebRequest http://127.0.0.1:8000/api/v1/health` | Connection refused / unreachable |
| `netstat -ano` for ports 8000 / 5173 / 6379 | No listener (only a leftover PostgreSQL FIN_WAIT_1 on 5432) |
| Running Python / uvicorn processes | None |
| `docker` command | Not installed on this machine |

So the stack is down at the source: no FastAPI/uvicorn process, no Redis, no
docker, and no running PostgreSQL accepting connections. Dependencies are
installed (`backend/.venv` has uvicorn 0.54.0 + fastapi 0.162.0), so the app
*can* start — it just is not started.

## Why It Is Not Connected to the TTI System

This is **by design**, not a fault. Live Telegram collection is deliberately
turned off:

1. **Connector flag is false.** `TTI_TELEGRAM_CONNECTOR_ACTIVE=false` everywhere
   (`.env`/`.env.example`, `docker-compose.yml`, and the config default). The
   stub returns `ConnectorStatus.DISABLED`.
2. **MTProto collector is disabled.** `.env` sets `TTI_MTPROTO_ENABLED=false`,
   and `TTI_TELEGRAM_SESSION` is empty. Telegram API credentials
   (`TTI_TELEGRAM_API_ID`/`TTI_TELEGRAM_API_HASH`) are present in `.env`, but
   with no authorized Telethon session string the background collector
   `app.services.mtproto_collector` never connects/authenticates.
3. **Policy gate.** `docs/security_baseline.md` and the Phase 1 stub explicitly
   prohibit live collection ("disabled_by_policy") until formal Chief Legal
   Counsel collection authorization. The `/api/v1/health` payload hard-codes
   `connectors.live_collection = disabled_by_policy`.

Result: the API, even when started, will report connectors as `DISABLED` and
the `mtproto_collector` as not authenticated. There is no live Telegram data
feeds into TTI, hence "not connected and no updates."

## How to Bring It Online (Local Dev)

Backend + DB + Redis. PostgreSQL doesn't need to be dockerized if a local
service/exe listens on 5432:

```powershell
cd backend
..\backend\.venv\Scripts\uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Then verify:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/health
```

Frontend (optional; separate tab):

```powershell
cd frontend
npm run dev
```

## How to Enable Live Telegram Collection (Requires Approval + Session)

1. Authorize an account session (needs your valid api_id/api_hash):
   `python -m app.cli mtproto-login`, paste the printed string into
   `TTI_TELEGRAM_SESSION` in `.env`.
2. Set `TTI_MTPROTO_ENABLED=true` (and restart the API so the collector starts).
3. Only with legal-approval, later: `TTI_TELEGRAM_CONNECTOR_ACTIVE=true`.

Until a Telethon session exists, "online but no Telegram updates" is expected
behavior — the connector is authenticated disabled by policy.
