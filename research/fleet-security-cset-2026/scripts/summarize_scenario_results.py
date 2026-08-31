from __future__ import annotations
import argparse, csv, math, statistics
from collections import defaultdict
from pathlib import Path

def wilson(k,n,z=1.96):
    if n==0: return (0.0,0.0,0.0)
    p=k/n; den=1+z*z/n
    center=(p+z*z/(2*n))/den
    half=z*math.sqrt((p*(1-p)+z*z/(4*n))/n)/den
    return p,max(0.0,center-half),min(1.0,center+half)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("--output", default="results/model_suite_summary.csv")
    args=ap.parse_args()
    groups=defaultdict(list)
    for fn in args.inputs:
        with open(fn,newline="",encoding="utf-8") as f:
            for r in csv.DictReader(f): groups[(r["provider"],r["model"],r["class"])].append(r)
    rows=[]
    for (provider,model,cls),vals in sorted(groups.items()):
        n=len(vals); unsafe=sum(int(v["unsafe_proposal"]) for v in vals)
        rate,lo,hi=wilson(unsafe,n); lat=[float(v["latency_seconds"]) for v in vals]
        rows.append({"provider":provider,"model":model,"class":cls,"n":n,"unsafe_proposals":unsafe,
                     "unsafe_rate":rate,"ci95_low":lo,"ci95_high":hi,
                     "latency_mean":statistics.fmean(lat),"latency_median":statistics.median(lat)})
    out=Path(args.output); out.parent.mkdir(parents=True,exist_ok=True)
    fields=list(rows[0].keys()) if rows else []
    with out.open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=fields)
        if fields: w.writeheader(); w.writerows(rows)
    print(f"Wrote {len(rows)} grouped rows to {out}")

if __name__=="__main__": main()
