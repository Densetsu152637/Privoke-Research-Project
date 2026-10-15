"""Independent reconciliation of saved synthetic noisy histograms and summaries."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import numpy as np


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    rows=json.loads((args.output/'simulation-cells.json').read_text())
    checks=0
    max_z=0.0
    max_variance_relative_error=0.0
    max_clipped_z=0.0
    for row in rows:
        data=np.load(args.output/'trials'/(row['id']+'.npz'))
        observed=data['observed']
        truth=data['truth']
        assert np.all(observed.sum(axis=1)==row['n'])
        assert int(truth.sum())==row['n']
        e=math.exp(row['epsilon']/5)
        q=1/(e+row['K']-1)
        p=e/(e+row['K']-1)
        estimates=(observed-row['n']*q)/(p-q)
        clipped=np.maximum(0,np.minimum(row['n'],estimates))
        for i,value in enumerate(row['values']):
            errors=estimates[:,i]-truth[i]
            clipped_errors=clipped[:,i]-truth[i]
            for actual,expected in ((errors.mean(),value['raw_bias']),
                                    (np.sqrt(np.mean(errors*errors)),value['raw_rmse']),
                                    (clipped_errors.mean(),value['clipped_bias']),
                                    (np.sqrt(np.mean(clipped_errors*clipped_errors)),value['clipped_rmse'])):
                assert math.isclose(actual,expected,abs_tol=1e-10,rel_tol=1e-12)
                checks+=1
            z=abs(value['raw_bias']-value['analytic_raw_bias'])/value['raw_bias_mcse']
            max_z=max(max_z,z)
            max_variance_relative_error=max(max_variance_relative_error,abs(value['raw_variance']/value['analytic_raw_variance']-1))
            if 'enumerated_clipped_bias' in value:
                max_clipped_z=max(max_clipped_z,abs(value['clipped_bias']-value['enumerated_clipped_bias'])/max(1e-15,value['clipped_bias_mcse']))
    assert max_z < 6, 'raw mean outside simultaneous six-MCSE envelope'
    assert max_clipped_z < 6, 'enumerated clipped mean outside six-MCSE envelope'
    result={'status':'PASS','numpy_version':np.__version__,'mean_validation_envelope_mcse':6,'cells':len(rows),'metric_reconciliations':checks,
            'maximum_raw_mean_z_against_analytic_mean':max_z,
            'maximum_raw_variance_relative_error':max_variance_relative_error,
            'maximum_n8_clipped_mean_z_against_enumeration':max_clipped_z,
            'scope':'raw synthetic histogram metric reconciliation; descriptive MC consistency, no utility acceptance threshold',
            'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (args.output/'independent-check.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
