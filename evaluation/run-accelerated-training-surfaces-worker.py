"""Internal pinned Linux worker; fitting never receives assessment mounts."""
from pathlib import Path
import os
import sys
from privoke_eval.accelerated_training_surfaces_study import read,write,sha
from privoke_eval.accelerated_training_surfaces_offline import fit_cell,evaluate_cell_snapshot
request_path,output=map(Path,sys.argv[1:]);request=read(request_path)
if sys.platform!="linux" or request["schema_version"]!="accelerated-offline-worker-v1":raise ValueError("Pinned Linux worker required")
source=Path(__file__).parent/"privoke_eval/accelerated_training_surfaces_offline.py"
if sha(source)!=request["adapter_sha256"] or os.environ.get("AS_SOURCE_REVISION")!=request["source_revision"]:raise ValueError("Worker source attestation differs")
inputs=request["inputs"]
if request["operation"]=="fit":
    if set(inputs)-{"train","assets","source_revision","base_artifact"}:raise ValueError("TRAIN-only fit contract violated")
    result=fit_cell(request["cell"],inputs,output/"fit")
elif request["operation"]=="score":
    result=evaluate_cell_snapshot(Path(inputs["snapshot"]["path"]),inputs["rows"],["DETECTION_LAYER_SEMANTIC"],assets=inputs.get("assets"))
else:raise ValueError("Unknown worker operation")
write(output/"result.json",{"image_source_revision":request["source_revision"],"request_sha256":sha(request_path),"result":result},immutable=True)
