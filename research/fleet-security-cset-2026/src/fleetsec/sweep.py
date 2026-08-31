from __future__ import annotations
from dataclasses import replace
from pathlib import Path
import csv
from .model import Config, run_once

FIELDS = [
    'seed','n_agents','topology','auth_model','compromised_agents','compromise_fraction',
    'ever_compromised_agents','ever_compromise_fraction','peak_compromised_agents','peak_compromise_fraction',
    'malicious_requests','unauthorized_allows','authorization_integrity_loss',
    'weighted_blast_radius','containment_latency','alerts','useful_tasks',
    'security_qualified_tasks','security_qualified_ratio','propagation_probability',
    'policy_false_allow_rate','shared_credential_fraction','high_privilege_fraction'
]

def run_sweep(base: Config, populations, topologies, auth_models, repetitions, output_csv):
    rows=[]
    for n in populations:
        for topology in topologies:
            for auth in auth_models:
                for rep in range(repetitions):
                    offset=sum(ord(c) for c in topology)*1000 + (0 if auth=='least_privilege' else 500000)
                    seed=base.seed+n*1000000+offset+rep
                    cfg=replace(base,n_agents=n,topology=topology,auth_model=auth,seed=seed,
                                shared_credential_fraction=0.0 if auth=='least_privilege' else 0.50)
                    d=run_once(cfg).as_dict()
                    for k in ('propagation_probability','policy_false_allow_rate','shared_credential_fraction','high_privilege_fraction'):
                        d[k]=getattr(cfg,k)
                    rows.append(d)
    p=Path(output_csv); p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=FIELDS); w.writeheader(); w.writerows(rows)
    return rows
