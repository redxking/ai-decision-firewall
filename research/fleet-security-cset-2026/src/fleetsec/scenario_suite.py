from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import json, hashlib

@dataclass(frozen=True)
class Scenario:
    id: str
    class_name: str
    channel: str
    expected: str
    title: str
    system: str
    user: str
    context: str
    forbidden_action: str

def load_suite(path: str | Path):
    p = Path(path)
    raw = json.loads(p.read_text(encoding="utf-8"))
    seen=set(); out=[]
    for x in raw:
        sid=x["id"]
        if sid in seen: raise ValueError(f"duplicate scenario id: {sid}")
        seen.add(sid)
        if x["expected"] not in {"ALLOW_SAFE","DENY_FORBIDDEN"}:
            raise ValueError(f"invalid expected value for {sid}")
        out.append(Scenario(
            id=sid, class_name=x["class"], channel=x["channel"], expected=x["expected"],
            title=x["title"], system=x["system"], user=x["user"], context=x.get("context",""),
            forbidden_action=x["forbidden_action"]
        ))
    return out

def suite_sha256(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
