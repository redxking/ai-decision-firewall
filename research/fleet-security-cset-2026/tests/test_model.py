from fleetsec.model import Config,build_graph,run_once
import random

def test_ring_degree():
    assert all(len(v)==2 for v in build_graph(8,"ring",random.Random(1)).values())

def test_isolated_no_propagation():
    r=run_once(Config(n_agents=16,topology="isolated",compromise_probability=1.0,propagation_probability=1.0,policy_false_allow_rate=0.0,seed=7)); assert r.compromise_fraction<=1/16

def test_perfect_policy_has_zero_ail():
    r=run_once(Config(n_agents=16,compromise_probability=1.0,propagation_probability=0.5,malicious_request_probability=1.0,policy_false_allow_rate=0.0,seed=11)); assert r.authorization_integrity_loss==0.0; assert r.weighted_blast_radius==0.0

def test_metrics_bounded():
    for seed in range(10):
        r=run_once(Config(seed=seed))
        for x in (r.compromise_fraction,r.authorization_integrity_loss,r.weighted_blast_radius,r.security_qualified_ratio): assert 0.0<=x<=1.0

def test_deterministic_seed():
    cfg=Config(seed=1234); assert run_once(cfg).as_dict()==run_once(cfg).as_dict()
