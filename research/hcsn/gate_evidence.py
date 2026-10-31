"""Fail-closed HCSN P0--P6 acceptance manifest from local reproducible evidence.

Missing evidence never implies a pass. Scientific criteria are intentionally
stricter than a unit-test success. No production activation is implemented.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import sys


GATES={
'P0':('HX A7 / eq 8 / eq 12 / QVI numerical and boundary checks',
      'Global parameter admissibility, independent FP32 extremes, parameter-conditioned recurrent QVI'),
'P1':('Call, Put, margin, dual and ordinary-gate comparisons',
      'Matched local slopes, matched compute budget, real independent net benefit'),
'P2':('Selective Copy and MQAR unrolled BPTT plus exact stationary multiple reset sampler',
      'Long-time joint recall, trained multi-reset transitions, accurate MQAR, gradient stability'),
'P3':('No real text/audio/image/video encoder results',
      'Frozen real encoder weights, matched Transformer/Mamba/SpikingSSM comparisons'),
'P4':('No verified multimodal alignment results',
      'Unseen modality-pair and missing-modality benchmark plus negative transfer'),
'P5':('CPU eager feature-only p50/p99 and throughput observations',
      'Fused target kernels, end-to-end CPU/GPU/power/RSS/p99 measurement'),
'P6':('No medium-sized encoder scaling result',
      'Distillation/continued pretraining and pre-registered quality-cost frontier'),
}


def load_json(path:Path):
    if not path.exists():
        return None
    return json.loads(path.read_text())


def make_manifest(folder:Path,trust_root:Path|None=None):
    p1=load_json(folder/'p1_audit_results.json')
    p2=load_json(folder/'temporal_replicates.json')
    perf=load_json(folder/'perf_results.json')
    log=(folder/'test_output.log').read_text() if (folder/'test_output.log').exists() else ''
    m=re.search(r'Ran (\d+) tests',log)
    summary={}
    for name,(completed,blocked) in GATES.items():
        summary[name]={
            'status':'OPEN',
            'implemented_scope':completed,
            'blocking_acceptance_evidence':blocked,
            'production_ready':False}
    summary['P0']['unit_test_count']=int(m.group(1)) if m else None
    summary['P1']['audit_present']=p1 is not None
    summary['P2']['temporal_three_seed_present']=p2 is not None
    summary['P5']['cpu_probe_present']=perf is not None
    hashes={}
    for path in sorted(folder.glob('*.py')):
        hashes[path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
    try:
        from .independent_gate import verify as verify_independent
    except ImportError:
        from independent_gate import verify as verify_independent
    verified=verify_independent(folder,trust_root)
    for phase in GATES:
        if verified['gates'][phase]['status']=='INDEPENDENTLY_ATTESTED':
            summary[phase]['status']='INDEPENDENTLY_ATTESTED'
            summary[phase]['independent_attestation_verified']=True
    return {'schema':'hcsn.evidence.gates.v2',
            'repo_target':'TrillionniumFoundation/Hepta research/hcsn',
            'run_environment':{'python':sys.version.split()[0],
                               'platform':platform.platform()},
            'gates':summary,'source_sha256':hashes,
            'references':['https://www.princeton.edu/~wxiong/papers/rollover.pdf'],
            'full_closure':verified['full_closure'],'production_activation':False,
            'independent_gate_audit':verified,
            'no_false_positive_gate':'fail_closed',
            'evidence_files':{'p1':'p1_audit_results.json' if p1 else None,
                              'p2':'temporal_replicates.json' if p2 else None,
                              'p5':'perf_results.json' if perf else None}}


if __name__=='__main__':
    cli=argparse.ArgumentParser()
    cli.add_argument('--folder',type=Path,default=Path(__file__).parent)
    cli.add_argument('--output',type=Path)
    cli.add_argument('--strict',action='store_true')
    cli.add_argument('--trust-root',type=Path,default=None)
    args=cli.parse_args()
    manifest=make_manifest(args.folder,args.trust_root)
    if args.output:
        if args.output.exists():cli.error('Refusing overwrite')
        args.output.write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    else:
        print(json.dumps(manifest['gates'],indent=2,sort_keys=True))
    if args.strict and not manifest['full_closure']:
        print('HCSN P0-P6 FAIL CLOSED: scientific acceptance blockers remain.',file=sys.stderr)
        sys.exit(2)
