from __future__ import annotations
import argparse,json
from dataclasses import asdict
from .model import Config,run_once
from .experiment import run_matrix,write_manifest
from .analysis import summarize_csv

def main(argv=None):
    p=argparse.ArgumentParser(description="Fleet Security synthetic experiment harness"); sub=p.add_subparsers(dest="cmd",required=True)
    s=sub.add_parser("smoke"); s.add_argument("--seed",type=int,default=1)
    r=sub.add_parser("run"); r.add_argument("--populations",default="1,4,16,64"); r.add_argument("--auth-models",default="least_privilege,shared_privilege"); r.add_argument("--repetitions",type=int,default=30); r.add_argument("--topology",default="ring",choices=["isolated","ring","star","tree","random","dense"]); r.add_argument("--steps",type=int,default=20); r.add_argument("--compromise-probability",type=float,default=0.35); r.add_argument("--propagation-probability",type=float,default=0.20); r.add_argument("--malicious-request-probability",type=float,default=0.45); r.add_argument("--policy-false-allow-rate",type=float,default=0.01); r.add_argument("--seed",type=int,default=20260831); r.add_argument("--output",default="results/raw.csv"); r.add_argument("--manifest",default="results/manifest.json")
    a=sub.add_parser("analyze"); a.add_argument("--input",default="results/raw.csv"); a.add_argument("--output",default="results/summary.csv")
    args=p.parse_args(argv)
    if args.cmd=="smoke": print(json.dumps(run_once(Config(seed=args.seed)).as_dict(),indent=2)); return 0
    if args.cmd=="run":
        base=Config(topology=args.topology,steps=args.steps,compromise_probability=args.compromise_probability,propagation_probability=args.propagation_probability,malicious_request_probability=args.malicious_request_probability,policy_false_allow_rate=args.policy_false_allow_rate,seed=args.seed)
        pops=[int(x) for x in args.populations.split(",")]; auth=[x.strip() for x in args.auth_models.split(",")]
        rows=run_matrix(base,pops,auth,args.repetitions,args.output); write_manifest(args.manifest,{"base":asdict(base),"populations":pops,"auth_models":auth,"repetitions":args.repetitions},args.output); print(f"wrote {len(rows)} runs to {args.output}"); return 0
    rows=summarize_csv(args.input,args.output); print(f"wrote {len(rows)} grouped summaries to {args.output}"); return 0
