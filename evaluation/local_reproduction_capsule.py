"""Build and replay a local source/model capsule using synthetic prompts only.

This does not evaluate the protected final set or install a clean-room environment.
"""
from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
from types import ModuleType

FREEZE_SHA = '655798df22d0dd817873b0554d5b4de084dec669354ae2c616f7dd06eaceda00'
PROBE_SHA = 'a7fb790f0c30d8db2e125ccd07d778c1098e521916e2041d48c0f905d77ecab7'
SYNTHETIC = (
    'A fictional story describes a quiet meadow.',
    'My diagnosis is cancer and this is private.',
    'My name is Jane Example and I live in Exampletown.',
    'This imaginary password is abc-def-123.',
)
IDENTITIES = ('model_id', 'model_version', 'artifact_checksum', 'parameter_fingerprint')
IMPORT_DIRS = ('evaluation', 'shared/python', 'extension/client-runtime/generated',
               'extension/client-runtime', 'services/pretrained-v3/src', 'services/privoke-fuzzer/src')
THREAD_KEYS = ('OMP_NUM_THREADS', 'MKL_NUM_THREADS', 'OPENBLAS_NUM_THREADS', 'NUMEXPR_NUM_THREADS', 'BLIS_NUM_THREADS')
ENV = {**{key: '4' for key in THREAD_KEYS}, 'MODEL_STREAMING_CACHE_TTL_SECONDS': '604800',
       'PRIVOKE_LLM_CHOICE': 'streamed', 'LLM_CHOICE': 'streamed', 'PRIVOKE_MODEL_DEVICE': 'cpu',
       'HF_HUB_OFFLINE': '1', 'TRANSFORMERS_OFFLINE': '1', 'PYTHONDONTWRITEBYTECODE': '1'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False) + '\n').encode()


def sha(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def retain(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = value if isinstance(value, bytes) else canonical(value)
    with path.open('xb') as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def contained(path, root):
    return Path(path).resolve().is_relative_to(Path(root).resolve())


def copy_pin(original, target, expected=None):
    original, target = Path(original).resolve(), Path(target)
    actual = sha(original)
    require(expected is None or actual == expected, 'Input pin differs: ' + str(original))
    target.parent.mkdir(parents=True, exist_ok=True)
    require(not target.exists(), 'Refusing to overwrite capsule asset: ' + str(target))
    shutil.copyfile(original, target)
    require(sha(target) == actual, 'Copy differs: ' + str(target))
    return {'original': str(original), 'sha256': actual, 'bytes': target.stat().st_size}


def versions():
    return {d.metadata['Name']: d.version for d in sorted(importlib.metadata.distributions(), key=lambda d: d.metadata['Name'].lower())}


def prepare(source, helpers, freeze_path, probe, capsule):
    source, helpers, probe, capsule = map(lambda p: Path(p).resolve(), (source, helpers, probe, capsule))
    require(not capsule.exists(), 'Capsule already exists; preserve it and choose an explicit new capsule path')
    require(sha(freeze_path) == FREEZE_SHA and sha(probe / 'analysis.json') == PROBE_SHA, 'Historical commitment differs')
    freeze, analysis = read(freeze_path), read(probe / 'analysis.json')
    require(analysis['synthetic_only'] is True and analysis['rows_per_arm'] == 4, 'Synthetic-only baseline required')
    pins = {}
    for relative, expected in sorted(freeze['runtime_source_files'].items()):
        pins['source/' + relative] = copy_pin(source / relative, capsule / 'source' / relative, expected)
    for relative, expected in sorted(freeze['new_executable_sources'].items()):
        require('source/' + relative not in pins, 'Duplicate source path')
        pins['source/' + relative] = copy_pin(helpers / relative, capsule / 'source' / relative, expected)
    # Package initializers and setup/requirement files are outside the historical
    # closure but needed to preserve import and environment preparation context.
    extras = {'evaluation/setup-host.py', 'evaluation/requirements-host.txt'}
    for folder in ('evaluation/privoke_eval', 'extension/client-runtime/src', 'extension/client-runtime/generated', 'shared/python'):
        extras.update(p.relative_to(source).as_posix() for p in (source / folder).rglob('__init__.py'))
    for relative in sorted(extras):
        if (source / relative).is_file() and 'source/' + relative not in pins:
            pins['source/' + relative] = copy_pin(source / relative, capsule / 'source' / relative)
    own = 'source/evaluation/local_reproduction_capsule.py'
    pins[own] = copy_pin(Path(__file__), capsule / own)
    test_relative = 'source/evaluation/tests/test_local_reproduction_capsule.py'
    pins[test_relative] = copy_pin(Path(__file__).parent / 'tests/test_local_reproduction_capsule.py', capsule / test_relative)
    packages = {}
    for name, entry in sorted(freeze['packages'].items()):
        assets = {}
        for filename, asset in sorted(entry['assets'].items()):
            key = 'models/ORIGINAL/' + name + '/' + filename
            pins[key] = copy_pin(asset['path'], capsule / key, asset['sha256'])
            assets[filename] = asset['sha256']
        packages[name] = {**{k: entry[k] for k in ('family', 'identity', 'native_cap')},
                          'directory': 'models/ORIGINAL/' + name, 'assets': assets}
    for name in sorted(packages):
        raw = probe / name / 'raw.jsonl'
        require(sha(raw) == analysis['raw_commitments'][name], 'Historical synthetic wire pin differs')
        pins['receipts/original/' + name + '/raw.jsonl'] = copy_pin(raw, capsule / 'receipts/original' / name / 'raw.jsonl')
    pins['receipts/original/analysis.json'] = copy_pin(probe / 'analysis.json', capsule / 'receipts/original/analysis.json', PROBE_SHA)
    deps = versions()
    retain(capsule / 'environment/versions.json', {'python': sys.version, 'executable': sys.executable, 'prefix': sys.prefix, 'packages': deps})
    retain(capsule / 'environment/requirements-versions.txt', ''.join(k + '==' + v + '\n' for k, v in sorted(deps.items())).encode())
    for relative in ('environment/versions.json', 'environment/requirements-versions.txt'):
        pins[relative] = {'original': 'maintained host environment metadata', 'sha256': sha(capsule / relative), 'bytes': (capsule / relative).stat().st_size}
    source_map = {key: item['sha256'] for key, item in pins.items() if key.startswith('source/')}
    source_digest = hashlib.sha256(canonical(source_map)).hexdigest()
    manifest = {'schema': 1, 'study_id': 'RP14-local-reproduction-20261014', 'synthetic_only': True,
                'historical_freeze_sha256': FREEZE_SHA, 'historical_probe_sha256': PROBE_SHA,
                'historical_runtime_files': len(freeze['runtime_source_files']), 'source_files': len(source_map),
                'full_source_sha256': source_digest, 'pins': pins, 'packages': packages,
                'synthetic_texts': list(SYNTHETIC), 'requested_and_actual_layers': [4],
                'environment_scope': 'Existing maintained host Python environment, no fresh installation or public clean-room claim',
                'limitations': ['Local ignored capsule; public Git checkout does not contain original model assets.',
                                'Dependency versions retained without cached wheel or package hash completeness.',
                                'Four invented prompts per package establish bounded output replay, not accuracy, safety, generalization, or latency parity.',
                                'No training, tuning, promotion, protected final data, or redistribution/license completeness.']}
    retain(capsule / 'manifest.json', manifest)
    print(json.dumps({'manifest_sha256': sha(capsule / 'manifest.json'), 'full_source_sha256': source_digest, 'source_files': len(source_map), 'pins': len(pins)}))


def verify(capsule):
    capsule = Path(capsule).resolve()
    manifest = read(capsule / 'manifest.json')
    require(manifest['synthetic_only'] is True and manifest['synthetic_texts'] == list(SYNTHETIC), 'Wrong capsule purpose')
    for relative, pin in manifest['pins'].items():
        require(contained(capsule / relative, capsule), 'Pin escapes capsule')
        require(sha(capsule / relative) == pin['sha256'], 'Capsule pin differs: ' + relative)
    source_map = {key: pin['sha256'] for key, pin in manifest['pins'].items() if key.startswith('source/')}
    require(hashlib.sha256(canonical(source_map)).hexdigest() == manifest['full_source_sha256'], 'Source root commitment differs')
    return manifest


def configure(capsule):
    os.environ.update(ENV)
    root = Path(capsule).resolve() / 'source'
    # -I excludes PYTHONPATH/user site and the launching worktree. Strip residual
    # site paths outside the actual interpreter roots before adding capsule paths.
    sys.path[:] = [p for p in sys.path if p and (contained(p, sys.prefix) or contained(p, sys.base_prefix))]
    sys.path[:0] = [str(root / relative) for relative in IMPORT_DIRS]
    import torch
    torch.set_num_threads(4)
    torch.use_deterministic_algorithms(True)
    import grpc
    from privoke.v1 import runtime_pb2, runtime_pb2_grpc
    from privoke_eval.pipeline_v1_v3_serving import load_semantic
    from src.config import GLOBAL_CONFIG
    from src.LLM.privoke.parameter_stream import ModelParameterStreamer
    from src.LLM.privoke.streamed_model import GLOBAL_STREAMED_MODEL_CACHE, _CachedModel
    from src.hosting.grpc_server import PrivokeRuntimeService
    return root


def module_file_origin(name, module):
    if not isinstance(module, ModuleType):
        return None, None
    filename = module.__dict__.get('__file__')
    if filename is None:
        return None, None
    virtual = {'torch.classes': '_classes.py', 'torch.ops': '_ops.py'}
    if (name in virtual and filename == virtual[name] and module.__dict__.get('__spec__') is None
            and type(module).__module__ in ('torch._classes', 'torch._ops')):
        return None, filename
    path = Path(filename).resolve()
    require(path.is_file(), 'Unexpected nonexistent module origin: ' + name + '=' + filename)
    return path, None


def attest(capsule):
    root = Path(capsule).resolve() / 'source'
    origins, virtual_origins, namespace_paths = {}, {}, {}
    pins = read(Path(capsule) / 'manifest.json')['pins']
    for name, module in sorted(sys.modules.copy().items()):
        if not isinstance(module, ModuleType):
            continue
        for location in module.__dict__.get('__path__', ()):
            require(contained(location, root) or contained(location, sys.prefix) or contained(location, sys.base_prefix),
                    'Package search path outside capsule/environment: ' + name + '=' + str(location))
            if contained(location, root):
                namespace_paths.setdefault(name, []).append(str(location))
        path, virtual = module_file_origin(name, module)
        if virtual:
            virtual_origins[name] = virtual
        if path is None:
            continue
        require(contained(path, root) or contained(path, sys.prefix) or contained(path, sys.base_prefix),
                'Import outside capsule/interpreter environment: ' + name + '=' + str(path))
        if contained(path, root):
            relative = path.relative_to(Path(capsule).resolve()).as_posix()
            require(relative in pins, 'Unpinned imported source: ' + relative)
            origins[name] = {'path': relative, 'sha256': sha(path)}
    require('src.hosting.grpc_server' in origins and 'privoke.v1.runtime_pb2' in origins, 'Required capsule imports absent')
    return {'passed': True, 'cwd': str(Path.cwd()), 'source_root': str(root), 'sys_path': list(sys.path),
            'executable': sys.executable, 'prefix': sys.prefix, 'base_prefix': sys.base_prefix,
            'source_modules': origins, 'capsule_package_paths': namespace_paths, 'recorded_torch_virtual_filenames': virtual_origins, 'interpreter_environment_reused': True}


def normalize(response, request, entry):
    require(response.request_id == request.request_id, 'Request identity mismatch')
    require([layer.layer for layer in response.layers] == [4], 'Actual layers not sole semantic')
    require(not response.error and response.layers[0].status == 'ok' and not response.layers[0].error, 'Runtime semantic error')
    require(all(response.metadata.get('privoke.semantic.' + key) == entry['identity'][key] for key in IDENTITIES), 'Returned model identity differs')
    from privoke_contracts.classification import Classification
    classification = Classification(response.classification.packed).to_dict()
    require(classification == {'sensitivity': response.classification.sensitivity, 'visibility': response.classification.visibility,
                               'categories': list(response.classification.categories)}, 'Packed/named classification differs')
    return {'classification': classification, 'action': response.action, 'actual_layers': [4],
            'identity': {key: entry['identity'][key] for key in IDENTITIES}}


def capture_terminal(stub, request, entry, expected_response):
    terminal = {'valid': False}
    try:
        response = stub.AnalyzePrompt(request, timeout=120)
        wire = response.SerializeToString(deterministic=True)
        terminal.update(response_pb=base64.b64encode(wire).decode(), response_sha256=hashlib.sha256(wire).hexdigest())
        normalized = normalize(response, request, entry)
        expected = normalize(expected_response, request, entry)
        terminal.update(valid=True, normalized=normalized, matches_historical_normalized=normalized == expected)
    except Exception as exc:
        terminal['error'] = type(exc).__name__ + ': ' + str(exc)
    return terminal


def serve(capsule, name, ready, port):
    capsule = Path(capsule).resolve()
    manifest = verify(capsule)
    root = configure(capsule)
    require(Path.cwd().resolve() == root, 'Server cwd must be isolated source root')
    import grpc
    from privoke.v1 import runtime_pb2_grpc
    from privoke_eval.pipeline_v1_v3_serving import load_semantic
    from src.config import GLOBAL_CONFIG
    from src.LLM.privoke.parameter_stream import ModelParameterStreamer
    from src.LLM.privoke.streamed_model import GLOBAL_STREAMED_MODEL_CACHE, _CachedModel
    from src.hosting.grpc_server import PrivokeRuntimeService
    entry = {**manifest['packages'][name], 'directory': str(capsule / manifest['packages'][name]['directory'])}
    semantic = load_semantic(entry)
    GLOBAL_CONFIG.llm_choice = 'streamed'
    streamer = ModelParameterStreamer(model_id=entry['identity']['model_id'])
    cache_key = (streamer.target, streamer.model_id)
    GLOBAL_STREAMED_MODEL_CACHE.clear()
    GLOBAL_STREAMED_MODEL_CACHE._models[cache_key] = _CachedModel(entry['identity']['parameter_fingerprint'], semantic, time.monotonic())
    require(GLOBAL_STREAMED_MODEL_CACHE.refresh_interval_seconds == 604800, 'Cache TTL differs')
    class ReadOnlySemantic(PrivokeRuntimeService):
        def AnalyzePrompt(self, request, context):
            if (list(request.layers) != [4] or request.semantic_model_id != entry['identity']['model_id']
                    or request.visibility_hint or request.HasField('semantic_presence_gate') or request.text not in SYNTHETIC):
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'Only fixed invented sole-semantic probes admitted')
            cached = GLOBAL_STREAMED_MODEL_CACHE._models.get(cache_key)
            if cached is None or cached.model is not semantic or time.monotonic() - cached.refreshed_at >= 604680:
                context.abort(grpc.StatusCode.FAILED_PRECONDITION, 'Pinned cache unavailable; remote fallback prohibited')
            return super().AnalyzePrompt(request, context)
        def deny(self, request, context):
            context.abort(grpc.StatusCode.UNIMPLEMENTED, 'Inference only')
        ComputeSemanticGradients = deny
        ComputeUnderlyingModelGradients = deny
        ComputePresenceGradients = deny
        DetectAnnotationPresence = deny
    server = grpc.server(ThreadPoolExecutor(max_workers=1))
    runtime_pb2_grpc.add_PrivokeRuntimeServiceServicer_to_server(ReadOnlySemantic(), server)
    token = sha(capsule / 'manifest.json').encode()
    def stop(request, context):
        if request != token:
            context.abort(grpc.StatusCode.PERMISSION_DENIED, 'Wrong capsule commitment')
        threading.Timer(.1, lambda: server.stop(2)).start()
        return b'stopping'
    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler('privoke.research.LocalCapsule', {
        'Stop': grpc.unary_unary_rpc_method_handler(stop)}),))
    require(port in (50211, 50212), 'Only reserved local capsule ports permitted')
    require(server.add_insecure_port('127.0.0.1:' + str(port)), 'Loopback port unavailable')
    server.start()
    retain(ready, {'pid': os.getpid(), 'name': name, 'manifest_sha256': sha(capsule / 'manifest.json'),
                   'identity': entry['identity'], 'training_disabled': True, 'remote_fallback_disabled': True,
                   'attestation': attest(capsule)})
    try:
        server.wait_for_termination()
    finally:
        server.stop(2).wait()
        retain(Path(ready).with_suffix('.stopped.json'), {'pid': os.getpid(), 'name': name, 'attestation': attest(capsule)})


def replay(capsule, output):
    capsule, output = Path(capsule).resolve(), Path(output).resolve()
    manifest = verify(capsule)
    root = configure(capsule)
    require(contained(output, capsule / 'attempts') and not output.exists(), 'New capsule attempt directory required')
    retain(output / 'reservation.json', {'manifest_sha256': sha(capsule / 'manifest.json'), 'synthetic_only': True, 'rpc_budget': 24})
    import grpc
    from privoke.v1 import runtime_pb2 as pb, runtime_pb2_grpc
    comparison = {}
    for name, entry in sorted(manifest['packages'].items()):
        arm = output / name
        arm.mkdir()
        ready = arm / 'ready.json'
        log = (arm / 'server.log').open('xb')
        port = 50211 if entry['family'] == 'v1' else 50212
        target = '127.0.0.1:' + str(port)
        command = [sys.executable, '-I', '-B', '-u', str(capsule / 'source/evaluation/local_reproduction_capsule.py'),
                   'serve', '--capsule', str(capsule), '--name', name, '--output', str(ready), '--port', str(port)]
        proc = subprocess.Popen(command, cwd=root, env={**os.environ, **ENV}, stdout=log, stderr=subprocess.STDOUT)
        channel, completed, failure = None, 0, None
        try:
            deadline = time.monotonic() + 300
            while not ready.exists():
                require(proc.poll() is None, 'Server failed: ' + str(arm / 'server.log'))
                require(time.monotonic() < deadline, 'Server readiness exceeded 300 seconds')
                time.sleep(.1)
            require(read(ready)['manifest_sha256'] == sha(capsule / 'manifest.json'), 'Server manifest differs')
            original = [json.loads(line) for line in (capsule / 'receipts/original' / name / 'raw.jsonl').read_bytes().splitlines()]
            reserves = {r['index']: r for r in original if r['kind'] == 'reserve'}
            terminals = {r['index']: r for r in original if r['kind'] == 'terminal'}
            require(set(reserves) == set(terminals) == set(range(4)), 'Expected four historical synthetic receipts')
            channel = grpc.insecure_channel(target)
            grpc.channel_ready_future(channel).result(timeout=15)
            stub = runtime_pb2_grpc.PrivokeRuntimeServiceStub(channel)
            matches = []
            with (arm / 'raw.jsonl').open('xb') as journal:
                for index, text in enumerate(SYNTHETIC):
                    request = pb.AnalyzePromptRequest.FromString(base64.b64decode(reserves[index]['request_pb']))
                    require(request.text == text and list(request.layers) == [4] and request.semantic_model_id == entry['identity']['model_id'], 'Historical request not fixed synthetic')
                    require(not request.visibility_hint and not request.HasField('semantic_presence_gate'), 'Historical hints/gate prohibited')
                    wire = request.SerializeToString(deterministic=True)
                    journal.write(canonical({'kind': 'reserve', 'index': index, 'request_pb': base64.b64encode(wire).decode(), 'request_sha256': hashlib.sha256(wire).hexdigest()}))
                    journal.flush()
                    expected_response = pb.AnalyzePromptResponse.FromString(base64.b64decode(terminals[index]['response_pb']))
                    terminal = capture_terminal(stub, request, entry, expected_response)
                    journal.write(canonical({'kind': 'terminal', 'index': index, **terminal}))
                    journal.flush()
                    require(terminal['valid'], terminal.get('error', 'Invalid semantic response'))
                    completed += 1
                    matches.append(terminal['matches_historical_normalized'])
            comparison[name] = {'rows': completed, 'matches': sum(matches), 'all_match': all(matches), 'raw_sha256': sha(arm / 'raw.jsonl')}
        except BaseException as exc:
            failure = type(exc).__name__ + ': ' + str(exc)
            raise
        finally:
            if channel is not None:
                try:
                    channel.unary_unary('/privoke.research.LocalCapsule/Stop')(sha(capsule / 'manifest.json').encode(), timeout=5)
                except Exception:
                    pass
                channel.close()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.wait(timeout=10)
            log.close()
            retain(arm / 'terminal.json', {'pid': proc.pid, 'exit_code': proc.returncode, 'rows': completed, 'failure': failure})
        print(name + ': ' + str(completed) + ' synthetic responses; all normalized outputs match=' + str(comparison[name]['all_match']), flush=True)
    verify(capsule)
    require(all(c['rows'] == 4 and c['all_match'] for c in comparison.values()), 'Synthetic replay mismatch')
    result = {'status': 'passed', 'synthetic_only': True, 'rows': 24, 'matches': 24, 'packages': comparison,
              'manifest_sha256': sha(capsule / 'manifest.json'), 'full_source_sha256': manifest['full_source_sha256'],
              'comparison': 'classification categories/sensitivity/visibility, action, sole actual layer, four model identity fields; excludes latency/wire timestamps',
              'client_attestation': attest(capsule), 'limitations': manifest['limitations']}
    retain(output / 'analysis.json', result)
    print(json.dumps({'output': str(output), 'analysis_sha256': sha(output / 'analysis.json'), 'status': 'passed'}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'attest', 'serve', 'replay', 'verify'))
    parser.add_argument('--capsule', type=Path, required=True)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--helpers', type=Path)
    parser.add_argument('--freeze', type=Path)
    parser.add_argument('--probe', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--name')
    parser.add_argument('--port', type=int)
    args = parser.parse_args()
    if args.action == 'prepare':
        prepare(args.source, args.helpers, args.freeze, args.probe, args.capsule)
    elif args.action == 'verify':
        verify(args.capsule)
        print('All capsule pins verified')
    elif args.action == 'attest':
        verify(args.capsule)
        configure(args.capsule)
        retain(args.output, attest(args.capsule))
        print(json.dumps({'attestation': str(args.output), 'sha256': sha(args.output)}))
    elif args.action == 'serve':
        serve(args.capsule, args.name, args.output, args.port)
    else:
        replay(args.capsule, args.output)


if __name__ == '__main__':
    main()
