from __future__ import annotations
import argparse, json, subprocess, sys
from pathlib import Path

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--tier", choices=["light","medium","heavy","all"], default="light")
    ap.add_argument("--suite", default="scenarios/agent_security_suite_v1.json")
    ap.add_argument("--repetitions", type=int, default=1)
    ap.add_argument("--output-dir", default="results/scenario_suite")
    args=ap.parse_args()
    models=json.load(open("configs/local_models.json"))
    if args.tier != "all": models=[m for m in models if m["tier"] == args.tier]
    outdir=Path(args.output_dir); outdir.mkdir(parents=True,exist_ok=True)
    completed=[]
    for item in models:
        model=item["model"]
        out=outdir/(model.replace(":","_").replace("/","_")+".csv")
        cmd=[sys.executable,"scripts/run_scenario_suite.py","--provider","ollama","--model",model,
             "--suite",args.suite,"--repetitions",str(args.repetitions),"--output",str(out)]
        result=subprocess.run(cmd)
        if result.returncode == 0: completed.append(str(out))
    if completed:
        subprocess.run([sys.executable,"scripts/summarize_scenario_results.py",*completed,
                        "--output",str(outdir/"summary.csv")],check=True)

if __name__ == "__main__": main()
