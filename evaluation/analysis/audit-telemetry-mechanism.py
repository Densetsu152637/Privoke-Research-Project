"""Reproducible finite-kernel audit and explicitly synthetic telemetry experiments."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal, localcontext
from fractions import Fraction
import hashlib
import importlib.util
import inspect
import json
import math
from pathlib import Path
import platform
import queue
import random
import sqlite3
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
for path in (ROOT / 'shared/python', ROOT / 'extension/client-runtime',
             ROOT / 'extension/client-runtime/generated', ROOT / 'services/telemetry-service/app'):
    sys.path.insert(0, str(path))
SPEC = importlib.util.spec_from_file_location('audited_privacy', ROOT / 'extension/client-runtime/src/telemetry/privacy.py')
privacy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(privacy)
EPSILONS = (0.5, 1.0, 2.0)
SIZES = (8, 80, 800, 8000)
SEED = 20261014
REPETITIONS = 10000


def fraction_json(value):
    return {'numerator': str(value.numerator), 'denominator': str(value.denominator)}


def finite_probability(threshold):
    """Exact count of 53-bit grid points strictly below a binary64 threshold."""
    value = Fraction.from_float(threshold) * (1 << 53)
    count = -(-value.numerator // value.denominator)
    if not 0 < count < (1 << 53):
        raise ValueError('threshold has degenerate finite support')
    return Fraction(count, 1 << 53)


def log_enclosure(value, precision=100):
    # Decimal.ln is correctly rounded ROUND_HALF_EVEN. Division is rounded too;
    # bracket the rational first, then enclose monotone ln of both endpoints.
    with localcontext() as context:
        context.prec = precision
        ratio = Decimal(value.numerator) / Decimal(value.denominator)
        lower = ratio.next_minus().ln().next_minus()
        upper = ratio.next_plus().ln().next_plus()
        return str(lower), str(upper)


def kernel(epsilon, size):
    e = math.exp(epsilon / len(privacy.DIMENSIONS))
    nominal_p = e / (e + size - 1)
    nominal_q = 1.0 / (e + size - 1)
    p = finite_probability(nominal_p)
    q = (1-p) / (size-1)
    matrix = [[p if left == output else q for output in range(size)] for left in range(size)]
    assert all(sum(row) == 1 and all(probability > 0 for probability in row) for row in matrix)
    maximum = max(matrix[a][y] / matrix[b][y] for a in range(size) for b in range(size) for y in range(size))
    assert maximum == p/q
    return p, q, nominal_p, nominal_q, maximum


def finite_audit():
    results = []
    for epsilon in EPSILONS:
        product = Fraction(1)
        fields = []
        for name, domain in privacy.DOMAINS.items():
            p, q, nominal_p, nominal_q, maximum = kernel(epsilon, len(domain))
            product *= maximum
            m = int(p * (1 << 53))
            assert Fraction(m-1, 1 << 53) < Fraction.from_float(nominal_p) <= Fraction(m, 1 << 53)
            fields.append({'dimension': name, 'K': len(domain), 'threshold_hex': nominal_p.hex(),
                           'threshold': repr(nominal_p), 'P': fraction_json(p), 'Q': fraction_json(q),
                           'maximum_ratio': fraction_json(maximum), 'log_ratio_enclosure': log_enclosure(maximum)})
        lower, upper = log_enclosure(product)
        with localcontext() as context:
            context.prec = 100
            excess = [str(Decimal(lower)-Decimal(str(epsilon))), str(Decimal(upper)-Decimal(str(epsilon)))]
        results.append({'event_epsilon': epsilon, 'fields': fields, 'joint_ratio': fraction_json(product),
                        'actual_epsilon_enclosure': [lower, upper], 'signed_excess_enclosure': excess,
                        'nominal_bound_holds': Decimal(upper) <= Decimal(str(epsilon))})
    return results


def truth_counts(n, size, workload):
    if workload == 'point_mass':
        return [n] + [0]*(size-1)
    first = n//size if workload == 'uniform' else max(1, n//100)
    remaining = n-first
    base, remainder = divmod(remaining, size-1)
    return [first] + [base + (i < remainder) for i in range(size-1)]


def binomial_probabilities(n, p):
    return [math.comb(n, k)*p**k*(1-p)**(n-k) for k in range(n+1)]


def clipped_exact_small(n, truth, p, q, nominal_p, nominal_q):
    """Full finite-support expectation; floating numerical summation, no MC."""
    left = binomial_probabilities(truth, p)
    right = binomial_probabilities(n-truth, q)
    expectation = math.fsum(a*b*min(n, max(0, (i+j-n*nominal_q)/(nominal_p-nominal_q)))
                            for i, a in enumerate(left) for j, b in enumerate(right))
    return expectation-truth


def simulations(output, repetitions):
    import numpy as np
    rng = np.random.default_rng(SEED)
    compact, detail = [], []
    raw = output / 'trials'
    raw.mkdir()
    for epsilon in EPSILONS:
        for n in SIZES:
            for workload in ('uniform', 'point_mass', 'rare_first'):
                for dimension, domain in privacy.DOMAINS.items():
                    k = len(domain)
                    truth = np.asarray(truth_counts(n, k, workload), dtype=np.int64)
                    p, q, nominal_p, nominal_q, _ = kernel(epsilon, k)
                    observations = np.zeros((repetitions, k), dtype=np.int64)
                    for category, count in enumerate(truth):
                        probabilities = np.full(k, float(q))
                        probabilities[category] = float(p)
                        observations += rng.multinomial(int(count), probabilities, size=repetitions)
                    untruncated = (observations-n*nominal_q)/(nominal_p-nominal_q)
                    clipped = np.clip(untruncated, 0, n)
                    key = f'e{epsilon:g}-n{n}-{workload}-{dimension}'
                    np.savez_compressed(raw / (key+'.npz'), truth=truth, observed=observations)
                    fields = []
                    for value in range(k):
                        err = untruncated[:,value]-truth[value]
                        cerr = clipped[:,value]-truth[value]
                        analytic_bias = (truth[value]*float(p)+(n-truth[value])*float(q)-n*nominal_q)/(nominal_p-nominal_q)-truth[value]
                        analytic_variance = (truth[value]*float(p)*(1-float(p))+(n-truth[value])*float(q)*(1-float(q)))/(nominal_p-nominal_q)**2
                        item = {'value': domain[value], 'truth_count': int(truth[value]),
                                'raw_bias': float(err.mean()), 'raw_bias_mcse': float(err.std(ddof=1)/math.sqrt(repetitions)),
                                'analytic_raw_bias': float(analytic_bias), 'analytic_raw_variance': float(analytic_variance),
                                'raw_variance': float(err.var(ddof=1)), 'raw_rmse': float(np.sqrt(np.mean(err**2))),
                                'clipped_bias': float(cerr.mean()), 'clipped_bias_mcse': float(cerr.std(ddof=1)/math.sqrt(repetitions)),
                                'clipped_rmse': float(np.sqrt(np.mean(cerr**2))), 'clipped_mae': float(np.abs(cerr).mean()),
                                'clipped_error_q025_q975': np.quantile(cerr,[.025,.975]).tolist(),
                                'clipping_fraction': float(np.mean((untruncated[:,value]<0)|(untruncated[:,value]>n)))}
                        if n == 8:
                            item['enumerated_clipped_bias'] = clipped_exact_small(n,int(truth[value]),float(p),float(q),nominal_p,nominal_q)
                        fields.append(item)
                    row = {'id': key,'epsilon': epsilon,'n':n,'workload':workload,'dimension':dimension,'K':k,
                           'repetitions':repetitions,'truth_counts':truth.tolist(),'values':fields,
                           'clipped_sum_absolute_error_mean':float(np.abs(clipped.sum(axis=1)-n).mean()),
                           'clipped_sum_not_n_fraction':float(np.mean(np.abs(clipped.sum(axis=1)-n)>1e-9))}
                    detail.append(row)
                    compact.append({key: value for key,value in row.items() if key != 'values'} | {'first_value':fields[0]})
    (output/'simulation-cells.json').write_text(json.dumps(detail,indent=2)+'\n',encoding='utf-8')
    return compact


def ledger_and_selection(output):
    scratch=output/'ledger-tests'
    scratch.mkdir()
    day=datetime(2026,10,14,12,tzinfo=timezone.utc)
    path=scratch/'budget.sqlite3'
    budget=privacy.DailyPrivacyBudget(path,8)
    accepted=[budget.reserve(1,now=day) for _ in range(9)]
    assert accepted == [True]*8+[False]
    child = "import importlib.util,sys; from datetime import datetime,timezone; s=importlib.util.spec_from_file_location('p',sys.argv[1]); p=importlib.util.module_from_spec(s); s.loader.exec_module(p); print(p.DailyPrivacyBudget(sys.argv[2],8).reserve(1,now=datetime(2026,10,14,12,tzinfo=timezone.utc)))"
    reopened=subprocess.run([sys.executable,'-c',child,str(ROOT/'extension/client-runtime/src/telemetry/privacy.py'),str(path)],capture_output=True,text=True,check=True)
    assert reopened.stdout.strip() == 'False'
    assert budget.reserve(1,now=day+timedelta(days=1))
    rollback=False
    try:
        budget.reserve(1,now=day)
    except RuntimeError:
        rollback=True
    assert rollback
    corrupt=scratch/'corrupt.sqlite3'
    corrupt.write_bytes(b'not a database')
    corruption=False
    try:
        privacy.DailyPrivacyBudget(corrupt).reserve(1,now=day)
    except RuntimeError:
        corruption=True
    assert corruption
    concurrent=scratch/'concurrent.sqlite3'
    with ThreadPoolExecutor(max_workers=12) as pool:
        answers=list(pool.map(lambda _:privacy.DailyPrivacyBudget(concurrent).reserve(.5,now=day),range(40)))
    assert sum(answers)==16
    from src.telemetry import event_emitter
    failure_records=[]
    for failure in ('build','queue','delivery'):
        ledger=privacy.DailyPrivacyBudget(scratch/(failure+'.sqlite3'),.5)
        reporter=object.__new__(event_emitter.TelemetryReporter)
        reporter.event_epsilon=.5
        reporter._budget=ledger
        reporter.timeout_seconds=1
        reporter._queue=queue.Queue(maxsize=1 if failure=='queue' else 2)
        reporter.emitter=SimpleNamespace(build_packet=lambda *_:SimpleNamespace())
        if failure=='build':
            reporter.emitter.build_packet=lambda *_: (_ for _ in ()).throw(ValueError('synthetic failure'))
        if failure=='queue':
            reporter._queue.put('existing')
        reporter.report(SimpleNamespace())
        if failure=='delivery':
            class Channel:
                def __enter__(self): return self
                def __exit__(self,*_): return False
            reporter._channel=Channel()
            reporter._queue.put(reporter._STOP)
            def failing_rpc(*_,**__): raise RuntimeError('synthetic delivery failure')
            stub=SimpleNamespace(RecordTelemetry=failing_rpc)
            with patch.object(event_emitter.telemetry_pb2_grpc,'TelemetryServiceStub',return_value=stub):
                reporter._run()
        assert not ledger.reserve(.5)
        failure_records.append({'failure':failure,'budget_spent':.5,'next_reservation':False})
    # Fixed invented event histories: workload order controls first-eight selection.
    histories={'early_sensitive':['BLOCK']*8+['ALLOW']*24,'late_sensitive':['ALLOW']*24+['BLOCK']*8}
    selected={name:{'attempts':len(values),'reservations':8,'population_block_fraction':values.count('BLOCK')/32,
                     'contributor_block_fraction':values[:8].count('BLOCK')/8} for name,values in histories.items()}
    # Delivery weights common across inputs can still alter the conditional kernel:
    # retain output0 always and all others with probability1/10.
    p,q,_,_,_=kernel(1,3)
    w=[Fraction(1),Fraction(1,10),Fraction(1,10)]
    delivered=[]
    for x in range(3):
        values=[p if x==y else q for y in range(3)]
        z=sum(a*b for a,b in zip(values,w))
        delivered.append([a*b/z for a,b in zip(values,w)])
    maximum=max(delivered[a][y]/delivered[b][y] for a in range(3) for b in range(3) for y in range(3))
    return {'ledger':{'default_acceptances':accepted,'subprocess_reopen_stdout':reopened.stdout.strip(),
                      'next_day_first_reservation':True,'rollback_fails_closed':rollback,'corruption_fails_closed':corruption,
                      'concurrent_half_epsilon_acceptances':sum(answers),'failure_no_refund':failure_records},
            'selection':{'first_eight_histories':selected,'input_independent_half_loss':{'expected_contributor_fraction_unchanged':True,'expected_delivered_count':4},
                         'output_dependent_delivery':{'K':3,'field_epsilon':.2,'weights':['1','1/10','1/10'],
                             'conditional_max_ratio':fraction_json(maximum),'conditional_log_ratio_enclosure':log_enclosure(maximum),
                             'scope':'constructed excluded selection scenario; not observed deployed loss'}}}


def store_parity():
    from storage import TelemetryStore
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        store=TelemetryStore(Path(directory)/'counts.sqlite3')
        packets=[]
        for e in EPSILONS:
            for i in range(3):
                packet=SimpleNamespace(privacy_epsilon=e,**{d:v[i%len(v)] for d,v in privacy.DOMAINS.items()})
                packets.append(packet)
                store.record(packet)
        n,dimensions=store.summary()
        assert n==9
        comparisons=0
        for row in dimensions:
            dimension=row['dimension']
            k=len(privacy.DOMAINS[dimension])
            for value in row['values']:
                expected=0
                for e in EPSILONS:
                    _,_,p,q,_=kernel(e,k)
                    count=sum(getattr(packet,dimension)==value['value'] and packet.privacy_epsilon==e for packet in packets)
                    expected+=(count-3*q)/(p-q)
                expected=min(9,max(0,expected))
                assert math.isclose(expected,value['estimated_count'],rel_tol=1e-12,abs_tol=1e-12)
                comparisons+=1
        return {'sample_count':n,'mixed_strata':list(EPSILONS),'compared_estimates':comparisons,'status':'PASS'}


def fingerprint(path):
    payload=Path(path).read_bytes()
    return {'path':str(path),'sha256':hashlib.sha256(payload).hexdigest(),
            'canonical_lf_sha256':hashlib.sha256(payload.replace(b'\r\n',b'\n')).hexdigest()}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--repetitions',type=int,default=REPETITIONS)
    args=parser.parse_args()
    if args.output.exists(): raise SystemExit('refusing existing output; retain previous attempts')
    args.output.mkdir(parents=True)
    (args.output/'frozen-protocol.md').write_bytes((ROOT/'paper/research/telemetry-evidence-20261014.md').read_bytes())
    paths=[ROOT/'extension/client-runtime/src/telemetry/privacy.py',ROOT/'extension/client-runtime/src/telemetry/event_emitter.py',
           ROOT/'services/telemetry-service/app/storage.py',ROOT/'services/telemetry-service/app/validation.py',Path(__file__),
           ROOT/'paper/research/telemetry-evidence-20261014.md',Path(random.__file__),Path(sys.executable)]
    if getattr(math,'__file__',None):
        paths.append(Path(math.__file__))
    else:
        paths.extend(sorted(Path(sys.base_prefix).glob('python*.dll')))
    manifest={'scope':'conditional finite sampling audit and synthetic experiments; no deployment utility',
              'command':sys.argv,'source_revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
              'python':sys.version,'math_origin':math.__spec__.origin,'platform':platform.platform(),'seed':SEED,'repetitions':args.repetitions,
              'simulation':'fixed realized integer histograms; NumPy default_rng PCG64 multinomial finite kernel; pooled installations/days for large n',
              'fingerprints':[fingerprint(path) for path in paths],
              'random_methods':{name:inspect.getsource(getattr(random.SystemRandom,name)) for name in ('random','getrandbits','choice','_randbelow')}}
    (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    try:
        finite=finite_audit()
        (args.output/'finite-kernel.json').write_text(json.dumps(finite,indent=2)+'\n',encoding='utf-8')
        mechanics=ledger_and_selection(args.output)
        parity=store_parity()
        cells=simulations(args.output,args.repetitions)
        result={'scope':manifest['scope'],'status':'PASS','seed':SEED,'repetitions':args.repetitions,
                'finite_audit':finite,'mechanics':mechanics,'store_parity':parity,'synthetic_cells':cells}
        (args.output/'summary.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
        hashes={str(p.relative_to(args.output)):fingerprint(p)['sha256'] for p in sorted(args.output.rglob('*')) if p.is_file()}
        (args.output/'output-hashes.json').write_text(json.dumps(hashes,indent=2)+'\n',encoding='utf-8')
        print(json.dumps({'status':'PASS','output':str(args.output),'cells':len(cells),'finite_excess':[r['signed_excess_enclosure'] for r in finite]},indent=2))
    except Exception as exc:
        (args.output/'failure.json').write_text(json.dumps({'error':type(exc).__name__,'message':str(exc)},indent=2)+'\n',encoding='utf-8')
        raise

if __name__ == '__main__':
    main()
