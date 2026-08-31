from __future__ import annotations
import csv, random, statistics
from collections import defaultdict

METRICS=['compromise_fraction','ever_compromise_fraction','peak_compromise_fraction','authorization_integrity_loss','weighted_blast_radius','containment_latency','security_qualified_ratio']

def bootstrap_ci(values, iterations=2000, confidence=0.95, seed=20260831):
    vals=list(values)
    if not vals: return (float('nan'),float('nan'),float('nan'))
    mean=statistics.fmean(vals)
    if len(vals)==1: return mean,mean,mean
    rng=random.Random(seed); boots=[]; n=len(vals)
    for _ in range(iterations):
        boots.append(statistics.fmean(vals[rng.randrange(n)] for __ in range(n)))
    boots.sort(); alpha=(1-confidence)/2
    lo=boots[max(0,int(alpha*iterations))]; hi=boots[min(iterations-1,int((1-alpha)*iterations)-1)]
    return mean,lo,hi

def summarize_bootstrap(input_csv, output_csv, iterations=2000):
    groups=defaultdict(lambda:defaultdict(list))
    with open(input_csv,newline='',encoding='utf-8') as f:
        for row in csv.DictReader(f):
            key=(int(row['n_agents']),row['topology'],row['auth_model'])
            for m in METRICS: groups[key][m].append(float(row[m]))
    rows=[]
    for (n,topology,auth),vals in sorted(groups.items()):
        rec={'n_agents':n,'topology':topology,'auth_model':auth,'repetitions':len(vals[METRICS[0]])}
        for m in METRICS:
            mean,lo,hi=bootstrap_ci(vals[m],iterations=iterations,seed=20260831+n+sum(map(ord,topology)))
            rec[m+'_mean']=mean; rec[m+'_bootstrap95_low']=lo; rec[m+'_bootstrap95_high']=hi
        rows.append(rec)
    if rows:
        with open(output_csv,'w',newline='',encoding='utf-8') as f:
            w=csv.DictWriter(f,fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    return rows
