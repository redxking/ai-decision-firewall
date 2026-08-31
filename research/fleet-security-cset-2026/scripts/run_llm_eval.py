from pathlib import Path
import argparse, json, sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from fleetsec.llm_eval import run_eval, summarize

p=argparse.ArgumentParser()
p.add_argument('--provider',choices=['openai','anthropic','ollama'],required=True)
p.add_argument('--model',required=True)
p.add_argument('--trials',type=int,default=20)
p.add_argument('--output',required=True)
p.add_argument('--base-url')
p.add_argument('--retain-text',action='store_true')
a=p.parse_args()
rows=run_eval(a.provider,a.model,a.trials,a.output,base_url=a.base_url,retain_text=a.retain_text)
print(json.dumps(summarize(rows),indent=2))
