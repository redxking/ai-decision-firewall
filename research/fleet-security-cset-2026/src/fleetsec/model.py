from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Dict, List, Set
import random

@dataclass(frozen=True)
class Config:
    n_agents: int = 16
    topology: str = "ring"
    auth_model: str = "least_privilege"
    compromise_probability: float = 0.35
    propagation_probability: float = 0.20
    malicious_request_probability: float = 0.45
    policy_false_allow_rate: float = 0.01
    shared_credential_fraction: float = 0.0
    high_privilege_fraction: float = 0.10
    steps: int = 20
    seed: int = 1

@dataclass
class RunResult:
    seed: int
    n_agents: int
    topology: str
    auth_model: str
    compromised_agents: int
    compromise_fraction: float
    malicious_requests: int
    unauthorized_allows: int
    authorization_integrity_loss: float
    weighted_blast_radius: float
    containment_latency: int
    alerts: int
    useful_tasks: int
    security_qualified_tasks: int
    security_qualified_ratio: float
    def as_dict(self): return asdict(self)

def build_graph(n: int, topology: str, rng: random.Random) -> Dict[int, Set[int]]:
    g = {i: set() for i in range(n)}
    if n <= 1 or topology == "isolated": return g
    if topology == "ring":
        for i in range(n):
            g[i].add((i + 1) % n); g[i].add((i - 1) % n)
    elif topology == "star":
        for i in range(1, n): g[0].add(i); g[i].add(0)
    elif topology == "tree":
        for i in range(1, n):
            p = (i - 1) // 2; g[p].add(i); g[i].add(p)
    elif topology == "random":
        p = min(0.20, 4/max(n-1,1))
        for i in range(n):
            for j in range(i+1,n):
                if rng.random() < p: g[i].add(j); g[j].add(i)
    elif topology == "dense":
        for i in range(n):
            for j in range(n):
                if i != j: g[i].add(j)
    else: raise ValueError(f"unsupported topology: {topology}")
    return g

def privilege_weights(cfg: Config, rng: random.Random) -> List[float]:
    n_high = max(1, round(cfg.n_agents * cfg.high_privilege_fraction))
    high = set(rng.sample(range(cfg.n_agents), min(n_high, cfg.n_agents)))
    weights = [1.0 if i in high else 0.1 for i in range(cfg.n_agents)]
    if cfg.auth_model == "shared_privilege":
        count = max(1, round(cfg.n_agents * max(cfg.shared_credential_fraction, 0.25)))
        for i in rng.sample(range(cfg.n_agents), min(count, cfg.n_agents)): weights[i] = 1.0
    return weights

def run_once(cfg: Config) -> RunResult:
    if cfg.n_agents < 1 or cfg.steps < 1: raise ValueError("n_agents and steps must be >= 1")
    for name in ("compromise_probability","propagation_probability","malicious_request_probability","policy_false_allow_rate","shared_credential_fraction","high_privilege_fraction"):
        if not 0 <= getattr(cfg,name) <= 1: raise ValueError(f"{name} must be in [0,1]")
    rng = random.Random(cfg.seed)
    graph = build_graph(cfg.n_agents,cfg.topology,rng)
    weights = privilege_weights(cfg,rng)
    compromised=set(); initial=rng.randrange(cfg.n_agents)
    if rng.random() < cfg.compromise_probability: compromised.add(initial)
    first = None if not compromised else 0; last = first or 0
    mr=ua=alerts=useful=sq=0; exposed=0.0
    for t in range(cfg.steps):
        new=set()
        for i in list(compromised):
            for j in graph[i]:
                if j not in compromised and rng.random() < cfg.propagation_probability: new.add(j)
        if new:
            if first is None: first=t
            last=t; compromised |= new
        for i in range(cfg.n_agents):
            useful += 1
            malicious = i in compromised and rng.random() < cfg.malicious_request_probability
            if malicious:
                mr += 1
                if rng.random() < cfg.policy_false_allow_rate:
                    ua += 1; exposed += weights[i]
                else:
                    alerts += 1; sq += 1
            else: sq += 1
        if compromised and alerts >= 2*len(compromised):
            victim=max(compromised,key=lambda x:weights[x]); compromised.remove(victim)
    ail=ua/mr if mr else 0.0; maxw=sum(weights)*cfg.steps; blast=exposed/maxw if maxw else 0.0
    latency=0 if first is None else max(0,last-first+1); ratio=sq/useful if useful else 0.0
    return RunResult(cfg.seed,cfg.n_agents,cfg.topology,cfg.auth_model,len(compromised),len(compromised)/cfg.n_agents,mr,ua,ail,blast,latency,alerts,useful,sq,ratio)
