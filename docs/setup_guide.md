# TTI (Telegram Threat Intelligence) — Setup & Developer Guide

This guide details how to set up, test, and run the **TTI (Telegram Threat Intelligence)** project on **Windows PowerShell** as well as with **Docker Compose**.

---

## 1. Prerequisites

- **Python**: Version 3.12 or 3.13 (verified with Python 3.13)
- **Node.js & npm**: Node.js v20+ or v24+ with npm 10+
- **Docker & Docker Compose** (Optional for containerized services)
- **Git**

---

## 2. Windows PowerShell Setup (Native Local Development)

### Step 2.1: Initialize Environment Configuration
From the workspace root (`d:\TTI`), copy `.env.example` to `.env`:

```powershell
Copy-Item .env.example .env
```

### Step 2.2: Backend Virtual Environment & Dependencies
1. Create and activate a Python virtual environment:
   ```powershell
   python -m venv backend/.venv
   .\backend\.venv\Scripts\Activate.ps1
   ```
2. Upgrade `pip` and install dependencies:
   ```powershell
   python -m pip install --upgrade pip
   python -m pip install -r backend/requirements.txt
   ```

### Step 2.3: Run Backend Tests
Run the automated test suite using `pytest`:

```powershell
# From the repository root (d:\TTI)
.\backend\.venv\Scripts\pytest backend/tests -v
```

### Step 2.4: Start the FastAPI Backend
Start the backend development server on port 8000:

```powershell
# From backend directory
cd backend
..\backend\.venv\Scripts\uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Once started, test the health check endpoint:
- **Health Check**: [http://127.0.0.1:8000/api/v1/health](http://127.0.0.1:8000/api/v1/health)
- **Swagger Interactive API Docs**: [http://127.0.0.1:8000/api/v1/docs](http://127.0.0.1:8000/api/v1/docs)
- **Status Endpoint**: [http://127.0.0.1:8000/api/v1/status](http://127.0.0.1:8000/api/v1/status)

### Step 2.5: Frontend Setup & Dev Server
Open a second PowerShell window:

```powershell
cd d:\TTI\frontend
npm install
npm run dev
```
Open your browser to:
- **Vite Dashboard**: [http://localhost:5173](http://localhost:5173)

---

## 3. Docker Compose Setup (Containerized Development)

When Docker Desktop is installed and running on Windows:

```powershell
# Build and launch all 4 services (FastAPI, React, PostgreSQL 16, Redis 7)
docker compose up --build -d

# Check service status
docker compose ps

# View backend logs
docker compose logs -f backend

# Run database migrations
docker compose exec backend alembic upgrade head

# Tear down services
docker compose down
```

Service mapping:
- **Frontend Dashboard**: [http://localhost:5173](http://localhost:5173)
- **Backend API**: [http://localhost:8000](http://localhost:8000)
- **PostgreSQL**: `localhost:5432` (`tti_user` / `tti_dev_password_change_in_production`)
- **Redis**: `localhost:6379`

---

## 4. Database Migrations (Alembic)

To apply database migrations to PostgreSQL:

```powershell
cd backend
..\backend\.venv\Scripts\alembic upgrade head
```

To create a new auto-generated migration schema:
```powershell
cd backend
..\backend\.venv\Scripts\alembic revision --autogenerate -m "add_new_table"
```

---

## 5. Security & Ingestion Policy Verification

To verify that connectors remain strictly inert during Phase 1:

```powershell
curl http://127.0.0.1:8000/api/v1/connectors
```

Expected JSON response:
```json
[
  {
    "connector_id": "telegram-stub",
    "status": "disabled",
    "message": "Telegram connector is running in Phase 1 safe stub mode (live collection disabled).",
    "is_live_collection_active": false
  },
  {
    "connector_id": "darkweb-stub",
    "status": "disabled",
    "message": "Dark-web connector is running in Phase 1 safe stub mode (live collection disabled).",
    "is_live_collection_active": false
  }
]
```
