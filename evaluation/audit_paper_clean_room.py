"""Compare committed-worktree availability with exact historical inference closure."""
import argparse
from collections import Counter
from pathlib import Path
from paper_evidence_audit import PIPE_PROTOCOL, read_bound, sha, retained

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--evidence-root',type=Path,required=True);p.add_argument('--clean-worktree',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();protocol=read_bound(a.evidence_root/'evaluation/results/pipeline_v1_v3_20261014/runs/cpu-01/protocol.json',PIPE_PROTOCOL)
    counts=Counter();differences=[];normalized=Counter()
    for relative,expected in protocol['source_files'].items():
        path=a.clean_worktree/relative;state='missing' if not path.is_file() else ('matches' if sha(path)==expected else 'different')
        counts[state]+=1
        if state!='matches':
            kind='missing' if not path.is_file() else ('newline_only' if path.read_bytes().replace(b'\r\n',b'\n')==(a.evidence_root/relative).read_bytes().replace(b'\r\n',b'\n') else 'different_after_crlf_normalization')
            normalized[kind]+=1
            differences.append({'path':relative,'status':state,'difference_kind':kind,'expected':expected,'actual':sha(path) if path.is_file() else None})
    assets={}
    for entry in protocol['entries']:
        original=Path(entry['directory']);relative=original.relative_to(a.evidence_root)
        assets[entry['name']]={name:('matches' if (a.clean_worktree/relative/name).is_file() and sha(a.clean_worktree/relative/name)==digest else 'missing_or_different') for name,digest in entry['assets'].items()}
    retained(a.output,{'schema':1,'protocol_sha256':PIPE_PROTOCOL,'source_closure':protocol['source_closure'],'clean_worktree_source_counts':dict(counts),'source_differences':differences,'nonmatching_source_difference_kinds':dict(normalized),'clean_worktree_asset_availability':assets,
                       'meaning':'availability/byte-integrity audit only; no inference/test/raw-prompt/final access','boundary':'Clean tracked checkout may regenerate aggregate figures; exact inference additionally requires retained ignored assets and historical source bytes. Differences include byte-level newline changes where present; no semantic drift is inferred from hash alone.'})
    print(dict(counts))

if __name__=='__main__':main()
