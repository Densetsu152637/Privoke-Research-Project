"""Preprocessing-level invariance: share of rows where norm(perturbed) == norm(clean); lists mismatches."""
import sys, json, hashlib
sys.dont_write_bytecode=True
sys.path[:0]=[r"D:/Git Repositories/Privoke-Research-Project-wt-r-robustfix/extension/client-runtime", r"D:/Git Repositories/Privoke-Research-Project-wt-r-robustfix/shared/python", r"D:/Git Repositories/Privoke-Research-Project-wt-c-robust/evaluation"]
import robustness_probe as probe
from pathlib import Path
from src.detection.preprocessing import normalize_with_offsets as n, RobustnessOptions as R
cond=sys.argv[1]; split=sys.argv[2]; show=int(sys.argv[3]); only_neg = len(sys.argv)>4 and sys.argv[4]=="neg"
rows=probe.load_rows(split, Path("D:/Git Repositories/Privoke-Research-Project"))
ALL=R(True,True,True)
tot=ok=chg=0; shown=0
for r in rows:
    if split=="dev" and int(hashlib.sha256(r["group_id"].encode()).hexdigest(),16)%2: continue
    if only_neg and r["expected_has_pii"]: continue
    t=probe.apply_transform(cond,r["text"],r["id"])
    if t==r["text"]: continue
    tot+=1
    a=n(t,lowercase=False,robustness=ALL).text; b=n(r["text"],lowercase=False,robustness=ALL).text
    if a==b: ok+=1
    elif shown<show:
        shown+=1; print("CLEAN:",repr(b[:260])); print("PERT :",repr(a[:260])); print()
print(f"{cond} {split}: changed rows {tot}, canonical==clean canonical {ok} ({100*ok/max(tot,1):.1f}%)")
