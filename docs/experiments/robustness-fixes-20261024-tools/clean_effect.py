"""How many CLEAN rows does each canonicalisation change (preprocessing level, no detectors)?"""
import sys
sys.dont_write_bytecode=True
sys.path[:0]=[r"D:/Git Repositories/Privoke-Research-Project-wt-r-robustfix/extension/client-runtime", r"D:/Git Repositories/Privoke-Research-Project-wt-r-robustfix/shared/python", r"D:/Git Repositories/Privoke-Research-Project-wt-c-robust/evaluation"]
import robustness_probe as probe
from pathlib import Path
from src.detection import preprocessing as pp
dotmin=int(sys.argv[1]); show=int(sys.argv[2])
pp._MIN_SINGLE_DIGIT_CHAIN.update({".":dotmin,"/":dotmin})
off=pp.RobustnessOptions()
for name,opt in (("strip",pp.RobustnessOptions(strip_format_chars=True)),("digits",pp.RobustnessOptions(canonicalise_digits=True)),("email",pp.RobustnessOptions(canonicalise_email_words=True))):
    for split in ("dev","personalized","openai"):
        rows=probe.load_rows(split, Path("D:/Git Repositories/Privoke-Research-Project"))
        ch=[]
        for r in rows:
            a=pp.normalize_with_offsets(r["text"],lowercase=False,robustness=opt).text
            b=pp.normalize_with_offsets(r["text"],lowercase=False,robustness=off).text
            if a!=b: ch.append((r["expected_has_pii"],b,a))
        print(f"{name:7}{split:13} changed {len(ch)}/{len(rows)} (pos {sum(c[0] for c in ch)}, neg {sum(not c[0] for c in ch)})")
        if show and name!="strip":
            import difflib
            for e,b,a in ch[:show]:
                sm=difflib.SequenceMatcher(None,b,a,autojunk=False)
                diffs=[(b[i1-8:i2+8],a[j1-8:j2+8]) for tag,i1,i2,j1,j2 in sm.get_opcodes() if tag!="equal"][:2]
                print("    ",e,diffs)
