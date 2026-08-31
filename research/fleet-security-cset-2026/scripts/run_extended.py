from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from fleetsec.model import Config
from fleetsec.sweep import run_sweep
from fleetsec.stats import summarize_bootstrap

base=Config(steps=20,compromise_probability=0.35,propagation_probability=0.20,
            malicious_request_probability=0.45,policy_false_allow_rate=0.01,
            high_privilege_fraction=0.10,seed=20260831)
rows=run_sweep(base,[1,4,16,64,256,1024],['isolated','ring','star','tree','random','dense'],
               ['least_privilege','shared_privilege'],10,'results/extended_raw.csv')
print('runs',len(rows))
s=summarize_bootstrap('results/extended_raw.csv','results/extended_summary.csv',iterations=1000)
print('groups',len(s))
