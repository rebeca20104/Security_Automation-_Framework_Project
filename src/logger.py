"""Append audit records to output/audit_log.json (JSON lines)."""
import json
from pathlib import Path
from datetime import datetime, timezone

LOG_PATH = Path(__file__).resolve().parent.parent / "output" / "audit_log.json"

def write_audit(record: dict, path: Path = LOG_PATH) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {"timestamp": datetime.now(timezone.utc).isoformat(), **record}
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    return record
