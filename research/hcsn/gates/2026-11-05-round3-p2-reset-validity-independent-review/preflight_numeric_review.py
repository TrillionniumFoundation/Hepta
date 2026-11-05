"""No-fit numeric counterexamples for learned reset validity.

Use --module original_reset_validity_before_review.py to reproduce the
pre-repair result, or omit it to inspect the current proposed implementation.
No training or heldout quality panel is constructed.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import torch


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--module', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError('refuse to overwrite numerical review')
    root = args.root.resolve(); sys.path.insert(0, str(root))
    import research.hcsn
    from research.hcsn.p2_round2_raw_tokens import gate_channels
    source = args.module or root / 'research/hcsn/p2_reset_validity.py'
    spec = importlib.util.spec_from_file_location('research.hcsn._independent_reset_review', source)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    Model, hard_event = module.RawResetValidityMemory, module.hard_event
    result = {'schema': 'hcsn.p2.no-fit-reset-numeric-review.v1',
              'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
              'reviewer_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'torch': str(torch.__version__), 'training_fits': 0,
              'heldout_quality_panels': 0, 'purpose': 'numeric edge cases and threshold semantics only'}
    torch.set_num_threads(1); torch.manual_seed(911)
    model = Model('hcsn_reset_validity')
    with torch.no_grad():
        model.control_logits.weight.zero_(); model.control_logits.bias.zero_()
        model.channel_bias[:] = 30.
        model.address.weight.fill_(1/16)
        initial = (torch.full((1, 8, 16), torch.finfo(torch.float32).max/2),
                   torch.full((1, 16), torch.finfo(torch.float32).max/2),
                   torch.ones(1, 16), torch.ones(1, 16))
        try:
            scores, state, trace = model(torch.tensor([[1]]), torch.ones(1, 1), initial,
                                         return_state=True, return_trace=True)
            result['finite_initial_reset'] = {
                'initial_finite': all(bool(torch.isfinite(x).all()) for x in initial),
                'events': trace['events'].tolist(),
                'output_finite': bool(torch.isfinite(scores).all()),
                'poststate_finite': [bool(torch.isfinite(x).all()) for x in state],
                'cleared': [bool((state[i] == 0).all()) for i in (0, 1, 3)],
            }
        except Exception as e:
            result['finite_initial_reset'] = {'exception': type(e).__name__, 'message': str(e)}
    for dtype in (torch.float16, torch.bfloat16):
        try:
            low = Model('hcsn_reset_validity').to(dtype)
            with torch.no_grad():
                scores, state, _ = low(torch.tensor([[1]]), torch.ones(1, 1, dtype=dtype),
                                        return_state=True, return_trace=True)
            result[str(dtype)] = {'output_finite': bool(torch.isfinite(scores).all()),
                                  'poststate_finite': [bool(torch.isfinite(x).all()) for x in state]}
        except Exception as e:
            result[str(dtype)] = {'exception': type(e).__name__, 'message': str(e)}
    u = torch.linspace(-1, 1, 4097)
    call, put = gate_channels(u, 'hcsn')
    linear, put2 = gate_channels(u, 'put_linear_equivalent')
    left, right = 6*call-6*put, 6*linear+(6-6)*put2
    bias = -left
    a = hard_event(torch.sigmoid(left+bias)); b = hard_event(torch.sigmoid(right+bias))
    different = a != b; indices = different.nonzero().flatten()
    i = int(indices[0]) if len(indices) else None
    result['threshold_mapping'] = {
        'states': len(u), 'different_events': int(different.sum()),
        'max_pre_sigmoid_difference': float((left-right).abs().max()),
        'bias_chosen_per_point': True, 'this_is_not_an_empirical_model_error_rate': True,
        'first': None if i is None else {'u': float(u[i]), 'bias': float(bias[i]),
            'hcsn_logit': float((left+bias)[i]), 'mapped_logit': float((right+bias)[i]),
            'hcsn_event': float(a[i]), 'mapped_event': float(b[i])},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as out:
        json.dump(result, out, indent=2, allow_nan=False); out.write('\n')
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == '__main__':
    main()
