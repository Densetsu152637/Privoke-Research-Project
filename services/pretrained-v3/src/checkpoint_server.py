from __future__ import annotations
import os
from common import pb, rpc, chunks, serve, MAX_BLOB_BYTES, CHUNK_BYTES
from checkpoint_store import CheckpointStore

class CheckpointServer(rpc.CheckpointServiceServicer):
    def __init__(self, store): self.store = store
    def ResolveCurrent(self, request, context):
        return pb.Ref(sha256=self.store.resolve(request.model_id))
    def FetchBlob(self, request, context):
        yield from chunks(self.store.read(request.sha256))
    def StageCheckpoint(self, request_iterator, context):
        data, offset, identity, total, manifest = [], 0, None, None, b""
        for part in request_iterator:
            if (not part.data or len(part.data) > CHUNK_BYTES or part.offset != offset or not 0 < part.total_bytes <= MAX_BLOB_BYTES
                    or (identity is not None and (part.sha256 != identity or part.total_bytes != total))
                    or (offset != 0 and part.manifest_json)):
                raise ValueError("Invalid bounded ordered checkpoint upload.")
            if offset == 0: identity, total, manifest = part.sha256, part.total_bytes, part.manifest_json
            offset += len(part.data)
            if offset > total: raise ValueError("Upload exceeds declared byte count.")
            data.append(part.data)
        from privoke_model.v3_contract import digest
        payload = b"".join(data)
        if offset != total or digest(payload) != identity: raise ValueError("Incomplete/corrupt checkpoint upload.")
        return pb.Ref(sha256=self.store.stage(payload, manifest))
    def CommitCandidate(self, request, context):
        return pb.Receipt(**self.store.commit(request))
    def GetCommitStatus(self, request, context):
        return pb.Receipt(**self.store.status(request.request_id))
    def Health(self, request, context):
        return pb.HealthResponse(ready=True, role="checkpoint", capabilities={"schema": "1", "publication": "sqlite_atomic_cas_v1"})

if __name__ == "__main__":
    store = CheckpointStore(os.environ["V3_STORE"], os.getenv("V3_INITIAL"))
    serve(CheckpointServer(store), rpc.add_CheckpointServiceServicer_to_server, int(os.getenv("V3_PORT", "50173")))
