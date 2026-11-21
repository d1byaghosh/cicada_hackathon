from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

COLLECTOR_DIR = Path(__file__).resolve().parent
REPO_ROOT = COLLECTOR_DIR.parent

# Load .env from repo root first, then collector/ if present
load_dotenv(REPO_ROOT / ".env")
load_dotenv(COLLECTOR_DIR / ".env")


def _parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class CollectorSettings:
    saas_base_url: str = os.getenv("SAAS_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
    collector_token: str = os.getenv("COLLECTOR_TOKEN", "dev-token-tenant-alpha")
    tenant_id: str = os.getenv("TENANT_ID", "tenant-alpha")
    region: str = os.getenv("REGION", "ap-south-1")
    collector_id: str = os.getenv("COLLECTOR_ID", "collector-edge-01")
    collector_version: str = os.getenv("COLLECTOR_VERSION", "1.0.0")

    organizer_stream_url: str = os.getenv("ORGANIZER_STREAM_URL", "").strip()
    organizer_stream_mode: str = os.getenv("ORGANIZER_STREAM_MODE", "demo").strip().lower()

    local_db_path: Path = Path(
        os.getenv("COLLECTOR_LOCAL_DB", str(COLLECTOR_DIR / "collector_local.db"))
    ).resolve()

    hmac_secret_salt: str = os.getenv("COLLECTOR_HMAC_SALT", "local-tier1-pseudonym-salt-v1")
    tls_ca_bundle: str | None = os.getenv("TLS_CA_BUNDLE") or None

    enable_host_probes: bool = _parse_bool(os.getenv("ENABLE_HOST_PROBES"), default=False)
    ping_target: str = os.getenv("NETWORK_PING_TARGET", "8.8.8.8")

    ingest_interval_sec: float = float(os.getenv("INGEST_INTERVAL_SEC", "2.0"))
    heartbeat_interval_sec: float = float(os.getenv("HEARTBEAT_INTERVAL_SEC", "15.0"))
    http_timeout_sec: float = float(os.getenv("HTTP_TIMEOUT_SEC", "5.0"))
    raw_retention_limit: int = int(os.getenv("RAW_RETENTION_LIMIT", "2000"))

    auth_failure_window_sec: int = int(os.getenv("AUTH_FAILURE_WINDOW_SEC", "60"))
    auth_failure_threshold: int = int(os.getenv("AUTH_FAILURE_THRESHOLD", "5"))


settings = CollectorSettings()