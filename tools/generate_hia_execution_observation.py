"""Render the exact execution-result ledger policy as bounded HIA continuations."""
from __future__ import annotations

import json
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_lowering import (
    CHUNK, SLOTS, MAGIC, POOL_MAGIC, document, pool_wire, pool_source, unit_source)
from tools.hia_execution_observation_ir import compile_policy

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'tools/hia_execution_observation_policy.py'


def generated():
    literals, functions, entries, instructions = compile_policy(POLICY.read_text())
    if CHUNK != 64 or not instructions:
        raise ValueError('execution-observation requires the original 64-instruction unit route')
    maximum_slots = max(function.slot_count for function in functions)
    workspace = (SLOTS + maximum_slots * 8 + 63) & -64
    maximum_vector = max((len(item.get('vector', ())) for item in instructions), default=0)
    output = (128 + maximum_vector * 8 + 63) & -64
    wire = pool_wire(literals.values)
    sources = [('execution_observation_pool', pool_source(wire))]
    units = []
    for unit, at in enumerate(range(0, len(instructions), CHUNK)):
        name = 'execution_observation_' + f'{unit:03d}'
        units.append(name)
        sources.append((name, unit_source(unit, instructions[at:at + CHUNK], entries,
                                         len(instructions), workspace, output)))
    abi = dict(schema='hepta.hia.execution-observation-abi.v1', protocol_magic=MAGIC,
               pool_magic=POOL_MAGIC, packet_bytes=128, workspace_bytes=workspace,
               output_bytes=output, pool_bytes=len(wire), literal_count=len(literals.values),
               units=units, modes={name: dict(number=e['mode'], arity=len(e['parameters']))
                                   for name, e in entries.items()})
    return sources, abi


def write(output, metadata):
    sources, abi = generated()
    output.mkdir(parents=True, exist_ok=True)
    for name, source in sources:
        (output / (name + '.hepta')).write_text(render_assembly(document(source, name)))
    metadata.write_text(json.dumps(abi, indent=2, sort_keys=True) + '\n')
    return [str(output / (name + '.hepta')) for name, _ in sources]


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'examples/hia_bootstrap')
    parser.add_argument('--metadata', type=Path, default=ROOT / 'docs/HIA_EXECUTION_OBSERVATION_ABI.json')
    arguments = parser.parse_args()
    for path in write(arguments.output, arguments.metadata):
        print(path)
