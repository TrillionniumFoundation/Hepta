#!/usr/bin/env python3
"""Create new private synthetic maintenance tasks; never invoke a learner.

The mathematical oracle is independent of the Core interpreter/compiler.  The
private feasibility program is not part of public inputs or a provider prompt.
These generated tasks are not genuine user-repository requests.
"""
from __future__ import annotations

import argparse
import datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from tools.hia_agent_codex_transport import canonical


def mathematical_value(x, parameters):
    # Deliberately ordinary Python arithmetic, not HIA evaluation or lowering.
    a, b, k = (parameters[name] for name in ('a', 'b', 'k'))
    if parameters['family'] == 'affine_xor':
        return ((x * a + b) % 256) ^ k
    if parameters['family'] == 'xor_affine':
        return (((x ^ k) * a) + b) % 256
    raise ValueError('unregistered task family')


def program(parameters, *, redundant):
    params = [{'name': 'value', 'type': 'u8'}]
    operations = []

    def const(name, value):
        operations.append({'op': 'const', 'args': [], 'out': [{'name': name, 'type': 'u8'}],
                           'attrs': {'value': value}})

    def operation(op, arguments, name):
        operations.append({'op': op, 'args': arguments, 'out': [{'name': name, 'type': 'u8'}], 'attrs': {}})
        return name

    previous = 'value'
    if redundant:
        for index, neutral in enumerate(parameters['neutral_values']):
            literal = 'neutral_' + str(index)
            const(literal, neutral)
            added = operation('int.add.wrap', [previous, literal], 'temporary_' + str(index))
            previous = operation('int.sub.wrap', [added, literal], 'restored_' + str(index))
    for name in ('a', 'b', 'k'):
        const(name, parameters[name])
    if parameters['family'] == 'xor_affine':
        previous = operation('bit.xor', [previous, 'k'], 'masked')
    previous = operation('int.mul.wrap', [previous, 'a'], 'scaled')
    previous = operation('int.add.wrap', [previous, 'b'], 'offset')
    if parameters['family'] == 'affine_xor':
        previous = operation('bit.xor', [previous, 'k'], 'masked')
    return {'schema': 'hepta.hia.program.v6', 'module': parameters['module'],
        'functions': [{'name': 'transform', 'params': params, 'returns': ['u8'], 'effects': [],
            'entry': 'entry', 'blocks': [{'id': 'entry', 'params': params, 'ops': operations,
                'term': {'op': 'ret', 'values': [previous]}}]}]}


def task_documents(nonce, index, *, purpose):
    raw = sha256((nonce + ':' + purpose + ':' + str(index)).encode()).digest()
    family = ('affine_xor', 'xor_affine')[index % 2]
    tag = sha256(raw).hexdigest()[:16]
    # A shared ELF file changes size in aligned segments. Tiny bytecode changes
    # can leave the whole image at the same 13,720 bytes. This larger baseline
    # makes a strict file-size maintenance request feasible; native feasibility
    # still has to be checked for every new registration before learner launch.
    neutral_count = 96 + 8 * (index % 3)
    parameters = {'family': family, 'a': raw[0] | 1, 'b': raw[1], 'k': raw[2],
        'neutral_values': [raw[3 + (i % 29)] for i in range(neutral_count)],
        'module': 'private_' + tag}
    baseline, teacher = (verify_program(program(parameters, redundant=value)) for value in (True, False))
    oracle = [mathematical_value(x, parameters) for x in range(256)]
    for image in (baseline, teacher):
        actual = [execute_program(image, 'transform', [x])['values'][0] for x in range(256)]
        if actual != oracle:
            raise ValueError('baseline/feasibility control differs from independent oracle')
    identity = purpose + '_' + tag
    public = {'schema': 'hepta.hia.agent.private-maintenance-public.v2', 'id': identity,
        'provenance': {'kind': 'private_synthetic_maintenance', 'real_user_repository_task': False},
        'instruction': 'Maintain transform(value:u8)->u8: preserve every result for all 256 inputs and the scalar ABI, and deliver a strictly smaller canonical shared artifact. Use the published HIA contract and actual receipts. Do not change the task, baseline, objective, context or budget.',
        'specification': {'domain': 'every u8 value 0..255', 'formula':
            '((value * a + b) mod 256) XOR k' if family == 'affine_xor' else
            '(((value XOR k) * a) + b) mod 256',
            'a': parameters['a'], 'b': parameters['b'], 'k': parameters['k'],
            'function': 'transform', 'params': ['u8'], 'returns': ['u8']},
        'baseline': baseline.as_dict(), 'baseline_sha256': baseline.sha256,
        'baseline_assembly': render_assembly(baseline),
        'objective': {'metric': 'artifact_bytes', 'strictly_smaller': True,
                      'correctness_domain_size': 256, 'canonical_codegen_only': True}}
    private = {'schema': 'hepta.hia.agent.private-maintenance-hidden.v2', 'id': identity,
        'parameters': parameters, 'oracle': oracle, 'oracle_method': 'independent Python mathematical expression modulo 256',
        'cases': [{'function': 'transform', 'arguments': [x],
            'expected': {'status': 'returned', 'values': [value]}} for x, value in enumerate(oracle)],
        'feasibility_core': teacher.as_dict(), 'feasibility_assembly': render_assembly(teacher),
        'feasibility_core_sha256': teacher.sha256,
        'control': {'interpreter_baseline_cases': 256, 'interpreter_teacher_cases': 256,
                    'native_executed': False, 'model_executed': False, 'learner_success': False}}
    return public, private


def prepare(output):
    output = Path(output).absolute()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name in ('public', 'hidden'):
        (output / name).mkdir(mode=0o700)
    nonce = secrets.token_hex(24)
    registration = {'schema': 'hepta.hia.agent.followup-preregistration.v2',
        'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'nonce': nonce,
        'source': {'kind': 'private_synthetic_maintenance', 'real_user_repository_task': False,
            'generator_sha256': sha256(Path(__file__).read_bytes()).hexdigest()},
        'tasks': [], 'provider_started': False, 'remote_mutations': 0,
        'p1_budget': {'max_hia_calls': 24, 'max_candidates': 8, 'max_wall_seconds': 1800,
            'max_input_plus_output_tokens_terminal_review': 500000, 'hard_mid_turn_token_cap': False},
        'p2_budget_per_cell': {'wall_ns': 180_000_000_000, 'model_tokens': 32768,
            'max_provider_turns': 3, 'max_candidates': 3,
            'token_convention': 'input+output+reasoning conservative overlap-unknown sum',
            'hard_mid_turn_token_cap': False},
        'p2_matrix': {'calibration_tasks': 2, 'heldout_tasks': 4,
            'arms': ['fixed', 'greedy', 'ordinary', 'ndu'], 'max_cells': 24,
            'max_cli_sessions': 72, 'cell_wall_allowances_sum_seconds': 4320,
            'outer_setup_and_export_are_additional_measured_cost': True},
        'learning_boundary': 'Learner sees one public task, exact tool contract and actual feedback only. Hidden oracle and feasibility source never enter prompts. New generation is not proof of global model non-exposure.',
        'execution_admission': 'Requires coordinator review, integrated source/provider/isolation freeze and explicit execution authorization. This command only creates tasks and interpreter controls.'}

    def write(name, document):
        raw = canonical(document) + b'\n'
        descriptor = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
        return {'path': name, 'sha256': sha256(raw).hexdigest(), 'bytes': len(raw)}

    for index in range(7):
        purpose = 'firstuse' if index == 6 else 'calibration' if index < 2 else 'heldout'
        public, hidden = task_documents(nonce, index, purpose=purpose)
        registration['tasks'].append({'id': public['id'], 'purpose': purpose,
            'namespace': 'hia-followup/' + nonce[:16] + '/' + public['id'],
            'public': write('public/' + public['id'] + '.json', public),
            'hidden': write('hidden/' + public['id'] + '.json', hidden)})
    write('REGISTRATION.json', registration)
    return registration


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    result = prepare(args.output)
    print(json.dumps({'output': args.output, 'task_ids': [t['id'] for t in result['tasks']],
                      'model_calls': 0, 'native_executions': 0, 'status': 'PREPARED_ONLY'}))


if __name__ == '__main__':
    main()
