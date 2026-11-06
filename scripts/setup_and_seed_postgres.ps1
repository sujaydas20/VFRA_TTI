# ==============================================================================
# TTI Local PostgreSQL Initialization and Telemetry Seeding Script
# ==============================================================================
param(
    [string]$PgZipPath = "C:\Users\user\AppData\Local\Temp\pg16.zip",
    [string]$PgInstallDir = "c:\Users\user\Desktop\TTI\pgsql"
)

$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "Continue"

Write-Host "=================================================================="
Write-Host "  TTI PORTABLE POSTGRESQL SETUP & DATABASE INITIALIZATION"
Write-Host "=================================================================="

# 1. Extract PostgreSQL
if (!(Test-Path "$PgInstallDir\pgsql\bin\postgres.exe")) {
    Write-Host "[1/6] Extracting PostgreSQL binaries to $PgInstallDir..."
    if (!(Test-Path $PgZipPath)) {
        throw "PostgreSQL zip not found at $PgZipPath"
    }
    New-Item -ItemType Directory -Path $PgInstallDir -Force | Out-Null
    & tar.exe -xf $PgZipPath -C $PgInstallDir
    Write-Host "      Extraction complete."
} else {
    Write-Host "[1/6] PostgreSQL binaries already exist at $PgInstallDir."
}

$pgBin = "$PgInstallDir\pgsql\bin"
$pgData = "$PgInstallDir\data"

# 2. Initialize Database Cluster
if (!(Test-Path "$pgData\PG_VERSION")) {
    Write-Host "[2/6] Initializing PostgreSQL cluster in $pgData..."
    & "$pgBin\initdb.exe" -D $pgData -U tti_user --auth=trust -E UTF8
    Write-Host "      initdb complete."
} else {
    Write-Host "[2/6] Database cluster already initialized."
}

# 3. Start PostgreSQL Server
Write-Host "[3/6] Starting PostgreSQL server on port 5432..."
$pgProcess = Get-Process -Name "postgres" -ErrorAction SilentlyContinue
if (!$pgProcess) {
    Start-Process -FilePath "$pgBin\pg_ctl.exe" -ArgumentList "start -D `"$pgData`" -l `"$PgInstallDir\pg_server.log`"" -NoNewWindow
    Start-Sleep -Seconds 4
} else {
    Write-Host "      PostgreSQL is already running."
}

# 4. Create Database and Run Init SQL
Write-Host "[4/6] Creating tti_dev database and schemas..."
& "$pgBin\psql.exe" -U tti_user -d postgres -c "CREATE DATABASE tti_dev;" 2>$null
& "$pgBin\psql.exe" -U tti_user -d tti_dev -f "c:\Users\user\Desktop\TTI\infra\docker\postgres\init-dev.sql"

# Set password for tti_user to match .env
& "$pgBin\psql.exe" -U tti_user -d tti_dev -c "ALTER USER tti_user WITH PASSWORD 'tti_dev_password_change_in_production';"

# 5. Run Alembic Migrations
Write-Host "[5/6] Running Alembic migrations to head..."
Set-Location "c:\Users\user\Desktop\TTI\backend"
& ".venv\Scripts\alembic.exe" upgrade head

# 6. Seed Forensic Telemetry Data
Write-Host "[6/6] Seeding forensic telemetry and adversary dossier..."
& ".venv\Scripts\python.exe" "c:\Users\user\Desktop\TTI\scripts\seed_forensic_telemetry.py"

Write-Host "=================================================================="
Write-Host "  DATABASE READY & FULLY SEEDED! ALL SYSTEMS OPERATIONAL"
Write-Host "=================================================================="
