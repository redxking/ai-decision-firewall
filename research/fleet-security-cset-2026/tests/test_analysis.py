from fleetsec.model import Config
from fleetsec.experiment import run_matrix
from fleetsec.analysis import summarize_csv

def test_matrix_and_summary(tmp_path):
    raw=tmp_path/"raw.csv"; summary=tmp_path/"summary.csv"; rows=run_matrix(Config(seed=2),[1,4],["least_privilege","shared_privilege"],3,raw); assert len(rows)==12; grouped=summarize_csv(raw,summary); assert len(grouped)==4; assert summary.exists()
