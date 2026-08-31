from __future__ import annotations
from dataclasses import replace
from pathlib import Path
from typing import Iterable
import csv, json, hashlib, platform, sys, datetime
from .model import Config, run_once

FIELDS = [
    "seed","n_agents","topology","auth_model","compromised_agents","compromise_fraction",
    "ever_compromised_agents","ever_compromise_fraction","peak_compromised_agents","peak_compromise_fraction",
    "malicious_requests","unauthorized_allows","authorization_integrity_loss",
    "weighted_blast_radius","containment_latency","alerts","useful_tasks",
    "security_qualified_tasks","security_qualified_ratio"
]

def run_matrix(base: Config, populations: Iterable[int], auth_models: Iterable[str], repetitions: int, output_csv: str | Path):
    rows=[]
    for n in populations:
        for auth in auth_models:
            for rep in range(repetitions):
                seed=base.seed+n*100000+rep+(0 if auth=="least_privilege" else 50000)
                cfg=replace(base,n_agents=n,auth_model=auth,seed=seed,shared_credential_fraction=0.0 if auth=="least_privilege" else 0.50)
                rows.append(run_once(cfg).as_dict())
    output_csv=Path(output_csv); output_csv.parent.mkdir(parents=True,exist_ok=True)
    with output_csv.open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=FIELDS); w.writeheader(); w.writerows(rows)
    return rows

def write_manifest(path: str | Path, config: dict, result_path: str | Path):
    result_path=Path(result_path); digest=hashlib.sha256(result_path.read_bytes()).hexdigest()
    manifest={"generated_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"python":sys.version,"platform":platform.platform(),"config":config,"result_sha256":digest,"result_file":result_path.name}
    Path(path).write_text(json.dumps(manifest,indent=2),encoding="utf-8"); return manifest
