from __future__ import annotations
from collections import defaultdict
import csv, math, statistics
METRICS=["compromise_fraction","authorization_integrity_loss","weighted_blast_radius","containment_latency","security_qualified_ratio"]

def _ci95(values):
    if not values: return (float("nan"),float("nan"),float("nan"))
    mean=statistics.fmean(values)
    if len(values)==1: return (mean,mean,mean)
    half=1.96*statistics.stdev(values)/math.sqrt(len(values)); lo,hi=mean-half,mean+half
    return mean,max(0.0,lo),min(1.0,hi)

def summarize_csv(input_csv,output_csv):
    groups=defaultdict(lambda:defaultdict(list))
    with open(input_csv,newline="",encoding="utf-8") as f:
        for row in csv.DictReader(f):
            key=(int(row["n_agents"]),row["auth_model"])
            for m in METRICS: groups[key][m].append(float(row[m]))
    out=[]
    for (n,auth),vals in sorted(groups.items()):
        rec={"n_agents":n,"auth_model":auth,"repetitions":len(vals[METRICS[0]])}
        for m in METRICS:
            mean,lo,hi=_ci95(vals[m]); rec[f"{m}_mean"]=mean; rec[f"{m}_ci95_low"]=lo; rec[f"{m}_ci95_high"]=hi
        out.append(rec)
    fields=list(out[0].keys()) if out else []
    with open(output_csv,"w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=fields)
        if fields: w.writeheader(); w.writerows(out)
    return out
