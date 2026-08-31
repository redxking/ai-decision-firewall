from __future__ import annotations
import random,tempfile
from pathlib import Path
from fleetsec.model import Config,build_graph,run_once
from fleetsec.experiment import run_matrix
from fleetsec.analysis import summarize_csv

def check(name,condition):
    if not condition: raise AssertionError(name)
    print(f"PASS: {name}")

g=build_graph(8,"ring",random.Random(1)); check("ring degree",all(len(v)==2 for v in g.values()))
r=run_once(Config(n_agents=16,topology="isolated",compromise_probability=1.0,propagation_probability=1.0,policy_false_allow_rate=0.0,seed=7)); check("isolated graph blocks propagation",r.compromise_fraction<=1/16)
r=run_once(Config(n_agents=16,compromise_probability=1.0,propagation_probability=0.5,malicious_request_probability=1.0,policy_false_allow_rate=0.0,seed=11)); check("perfect policy AIL zero",r.authorization_integrity_loss==0.0); check("perfect policy blast zero",r.weighted_blast_radius==0.0)
for seed in range(20):
    r=run_once(Config(seed=seed))
    for x in (r.compromise_fraction,r.authorization_integrity_loss,r.weighted_blast_radius,r.security_qualified_ratio): check(f"metric bounded seed {seed} value {x:.6f}",0.0<=x<=1.0)
cfg=Config(seed=1234); check("deterministic same-seed run",run_once(cfg).as_dict()==run_once(cfg).as_dict())
with tempfile.TemporaryDirectory() as td:
    raw=Path(td)/"raw.csv"; summary=Path(td)/"summary.csv"; rows=run_matrix(Config(seed=2),[1,4],["least_privilege","shared_privilege"],3,raw); check("matrix row count",len(rows)==12); grouped=summarize_csv(raw,summary); check("summary group count",len(grouped)==4); check("summary file exists",summary.exists())
r=run_once(Config(n_agents=4,topology="isolated",compromise_probability=1.0,malicious_request_probability=1.0,policy_false_allow_rate=1.0,steps=3,seed=99)); check("failed policy produces malicious requests",r.malicious_requests>0); check("failed policy AIL one",r.authorization_integrity_loss==1.0)
print("ALL SELF-TESTS PASSED")
