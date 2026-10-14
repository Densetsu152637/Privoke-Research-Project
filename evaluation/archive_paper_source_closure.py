"""Retain byte-exact historical source closure locally, with immutable hash names."""
import argparse
from pathlib import Path, PurePosixPath
import hashlib
from paper_evidence_audit import PIPE_PROTOCOL, read_bound, require, retained, sha

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--evidence-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();protocol=read_bound(a.evidence_root/'evaluation/results/pipeline_v1_v3_20261014/runs/cpu-01/protocol.json',PIPE_PROTOCOL)
    a.output.mkdir(parents=True,exist_ok=False);files={}
    for relative,expected in protocol['source_files'].items():
        parts=PurePosixPath(relative);require(not parts.is_absolute() and '..' not in parts.parts,'Unsafe source path')
        content=(a.evidence_root/relative).read_bytes();require(hashlib.sha256(content).hexdigest()==expected,'Historical source closure changed')
        destination=a.output/(expected+'.source')
        if destination.exists():require(destination.read_bytes()==content,'Hash-addressed source collision')
        else:
            with destination.open('xb') as f:f.write(content)
        files[relative]={'sha256':expected,'blob':destination.name,'bytes':len(content)}
    manifest={'schema':1,'protocol_sha256':PIPE_PROTOCOL,'source_closure':protocol['source_closure'],'files':files,
              'role':'local exact historical source bytes; no raw prompts/final data/weights; model assets reused at pinned existing directories',
              'reconstruction':'Verify each blob digest then recreate each relative path in a new empty checkout, preserving exact bytes. Install verified dependencies and point at frozen model/tokenizer assets. This archive was hash-verified but independent inference from reconstruction remains unrun.'}
    retained(a.output/'manifest.json',manifest);print({'files':len(files),'manifest_sha256':sha(a.output/'manifest.json')})

if __name__=='__main__':main()
