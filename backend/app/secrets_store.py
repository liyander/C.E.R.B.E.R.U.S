"""Encrypt saved credentials before they enter SQLite."""
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

PREFIX = "enc:v1:"
SECRET_FIELDS = {"token", "api_key", "abuseipdb_key", "password", "sudo_password", "indexer_password",
                 "dashboard_password", "secret", "client_secret", "webhook_token"}


def _cipher(data_dir: Path, *, create: bool = True) -> Fernet:
    supplied = os.environ.get("CERBERUS_MASTER_KEY", "").strip()
    if supplied:
        return Fernet(supplied.encode())
    path = data_dir / "master.key"
    if not path.exists():
        if not create:
            raise RuntimeError("Saved credentials cannot be decrypted. Restore data/master.key or CERBERUS_MASTER_KEY.")
        data_dir.mkdir(parents=True, exist_ok=True)
        try:
            with path.open("xb") as handle:
                handle.write(Fernet.generate_key())
            if os.name != "nt":
                path.chmod(0o600)
        except FileExistsError:
            pass
    return Fernet(path.read_bytes().strip())


def encrypt(value: str, data_dir: Path) -> str:
    if not value or value.startswith(PREFIX):
        return value
    return PREFIX + _cipher(data_dir).encrypt(value.encode()).decode()


def decrypt(value: str, data_dir: Path) -> str:
    if not isinstance(value, str) or not value.startswith(PREFIX):
        return value
    try:
        return _cipher(data_dir, create=False).decrypt(value[len(PREFIX):].encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError("Saved credentials cannot be decrypted. Restore data/master.key or CERBERUS_MASTER_KEY.") from exc


def transform_config(config: dict, data_dir: Path, *, reveal: bool) -> dict:
    convert = decrypt if reveal else encrypt
    def walk(value):
        if isinstance(value, dict):
            return {k: convert(v, data_dir) if k in SECRET_FIELDS and isinstance(v, str) else walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v) for v in value]
        return value
    return walk(config)


def migrate(conn, data_dir: Path) -> None:
    for row in conn.execute("SELECT key,config FROM integrations"):
        raw = json.loads(row["config"])
        protected = transform_config(raw, data_dir, reveal=False)
        if protected != raw:
            conn.execute("UPDATE integrations SET config=? WHERE key=?", (json.dumps(protected), row["key"]))
    for row in conn.execute("SELECT id,api_key FROM ai_providers WHERE api_key != ''"):
        protected = encrypt(row["api_key"], data_dir)
        if protected != row["api_key"]:
            conn.execute("UPDATE ai_providers SET api_key=? WHERE id=?", (protected, row["id"]))
