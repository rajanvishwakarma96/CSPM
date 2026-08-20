import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, text

engine=create_engine(os.getenv("DATABASE_URL","sqlite:///./autopilot.db"),pool_pre_ping=True)

def now(): return datetime.now(timezone.utc).isoformat()

def init_db():
    with engine.begin() as c:
        c.execute(text("""CREATE TABLE IF NOT EXISTS aws_accounts(
        id TEXT PRIMARY KEY, account_name TEXT NOT NULL, account_id TEXT,
        role_arn TEXT NOT NULL, external_id TEXT, regions TEXT NOT NULL,
        status TEXT NOT NULL, created_at TEXT NOT NULL)"""))
        c.execute(text("""CREATE TABLE IF NOT EXISTS resources(
        id TEXT PRIMARY KEY, account_id TEXT NOT NULL, resource_type TEXT NOT NULL,
        resource_id TEXT NOT NULL, region TEXT, name TEXT, data TEXT NOT NULL,
        discovered_at TEXT NOT NULL)"""))
        c.execute(text("""CREATE TABLE IF NOT EXISTS findings(
        id TEXT PRIMARY KEY, account_id TEXT NOT NULL, severity TEXT NOT NULL,
        title TEXT NOT NULL, check_id TEXT, resource_id TEXT, resource_type TEXT,
        region TEXT, status TEXT NOT NULL, description TEXT NOT NULL,
        recommendation TEXT NOT NULL, raw TEXT NOT NULL, created_at TEXT NOT NULL)"""))
        c.execute(text("""CREATE TABLE IF NOT EXISTS costs(
        id TEXT PRIMARY KEY, account_id TEXT NOT NULL, service TEXT NOT NULL,
        amount REAL NOT NULL, currency TEXT NOT NULL, period_start TEXT NOT NULL,
        period_end TEXT NOT NULL, raw TEXT NOT NULL, created_at TEXT NOT NULL)"""))
        c.execute(text("""CREATE TABLE IF NOT EXISTS remediation_plans(
        id TEXT PRIMARY KEY, account_id TEXT NOT NULL, finding_id TEXT,
        action TEXT NOT NULL, resource_id TEXT, approved INTEGER NOT NULL DEFAULT 0,
        executed INTEGER NOT NULL DEFAULT 0, result TEXT, created_at TEXT NOT NULL,
        executed_at TEXT)"""))

init_db()
