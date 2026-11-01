#!/usr/bin/env python3
"""Check the unbounded CFG renaming model with the pinned Lean kernel.

This does not prove the Python implementation's correspondence. Its separate
executable controls call the production boundary. Keep these claims distinct.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
NAMES = {"HiaCapabilityRenaming." + name for name in (
    "name_preserved", "kind_preserved", "external_preserved", "origin_preserved",
    "name_equal_iff", "root_equal_iff", "parent_map_iff", "child_of_iff",
    "exclusive_alias_iff", "suspended_iff", "closed_preserved", "number_preserved",
    "rename_composes", "identity_rename")}
MUTATIONS = {
    "root_rebound_to_name": ("root := f c.root", "root := f c.name", "root_equal_iff"),
    "parent_discarded": ("parent := c.parent.map f", "parent := none", "child_of_iff"),
    "kind_changed": ("kind := c.kind", "kind := 0", "kind_preserved"),
    "origin_discarded": ("origin := c.origin", "origin := none", "origin_preserved"),
}


def digest(data):
    return sha256(data).hexdigest()


def theorem_dependencies(log, *, broken=False):
    rows = re.findall(r"^'([^']+)' depends on axioms: \[([^\]]*)\]$", log, re.M)
    rows += [(name, "") for name in re.findall(r"^'([^']+)' does not depend on any axioms$", log, re.M)]
    if len(rows) != len(NAMES) or {row[0] for row in rows} != NAMES:
        raise ValueError("missing or duplicate theorem dependency output")
    allowed = {"propext", "Quot.sound", "Classical.choice"} | ({"sorryAx"} if broken else set())
    result = {name: [x.strip() for x in values.split(',') if x.strip()] for name, values in rows}
    if any(set(values) - allowed for values in result.values()):
        raise ValueError("unexpected proof axiom")
    return result


def verify(lean, output):
    output = Path(output)
    if output.exists():
        raise ValueError("proof output already exists")
    executable = Path(lean).resolve(strict=True)
    lock = json.loads((ROOT/'formal/toolchain-lock.json').read_text())
    executable_hash = digest(executable.read_bytes())
    if executable_hash != lock['lean_binary_sha256']:
        raise ValueError("Lean executable differs from pinned identity")
    source_path = ROOT/'formal/HiaCapabilityRenaming.lean'
    source = source_path.read_text()
    if re.search(r'(?m)^\s*(axiom|unsafe|opaque)\s|\bsorry\b', source):
        raise ValueError("untrusted declaration or placeholder in proof")
    declared = {'HiaCapabilityRenaming.'+x for x in re.findall(r'^theorem (\w+)', source, re.M)}
    if declared != NAMES:
        raise ValueError("theorem inventory changed")
    bound = {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in (
        source_path, ROOT/'formal/toolchain-lock.json', ROOT/'hepta/hia_capability_flow.py',
        ROOT/'hepta/hia_program.py', ROOT/'tests/test_hia_capability_flow.py', Path(__file__))}
    version = subprocess.run([str(executable), '--version'], capture_output=True, text=True, timeout=20)
    if version.returncode or 'version 4.19.0,' not in version.stdout:
        raise ValueError("pinned Lean could not execute")
    checks = '\n' + '\n'.join('#print axioms '+name for name in sorted(NAMES)) + '\n'
    with tempfile.TemporaryDirectory(prefix='hia-capability-proofs-') as tmp:
        proof = Path(tmp)/'Check.lean'
        proof.write_text(source+checks)
        good = subprocess.run([str(executable), str(proof)], capture_output=True, text=True, timeout=60)
        log = good.stdout+good.stderr
        if good.returncode or 'error:' in log or 'sorryAx' in log:
            raise ValueError('Lean rejected the positive proof:\n'+log)
        dependencies = theorem_dependencies(log)
        negative = []
        for name, (old, new, expected) in MUTATIONS.items():
            if source.count(old) != 1:
                raise ValueError('mutation site is not unique: '+name)
            changed = source.replace(old, new, 1)
            proof.write_text(changed+checks)
            bad = subprocess.run([str(executable), str(proof)], capture_output=True, text=True, timeout=60)
            bad_log = bad.stdout+bad.stderr
            if bad.returncode == 0 or 'error:' not in bad_log:
                raise ValueError('semantic mutation unexpectedly passed: '+name)
            bad_dependencies = theorem_dependencies(bad_log, broken=True)
            if 'sorryAx' not in bad_dependencies['HiaCapabilityRenaming.'+expected]:
                raise ValueError('mutation did not invalidate intended theorem: '+name)
            negative.append({'name': name, 'returncode': bad.returncode,
                             'expected_invalid_theorem': 'HiaCapabilityRenaming.'+expected,
                             'source_sha256': digest(changed.encode()), 'kernel_output': bad_log,
                             'kernel_output_sha256': digest(bad_log.encode())})
    if any(digest((ROOT/p).read_bytes()) != value for p, value in bound.items()):
        raise ValueError('source changed during proof qualification')
    if digest(executable.read_bytes()) != executable_hash:
        raise ValueError('proof checker changed during qualification')
    result = {
        'schema': 'hepta.hia.capability-renaming.proof.v1', 'passed': True,
        'source_sha256': bound, 'lean_version': version.stdout.strip(),
        'lean_binary_sha256': executable_hash, 'theorems': dependencies,
        'checked_input_sha256': digest((source+checks).encode()),
        'kernel_output': log, 'kernel_output_sha256': digest(log.encode()),
        'negative_mutations': negative,
        'scope': {'all_finite_capability_lists_and_injective_name_maps': True,
                  'execution_length_bound': None, 'names': 'unbounded mathematical naturals',
                  'properties': ['root identity relation', 'parent relation and suspension',
                                 'exclusive alias relation', 'graph closure', 'selected capability count',
                                 'type/external/origin fields', 'composition and identity'],
                  'selected_domain': 'the closed set carried across one CFG edge, before renaming',
                  'external_forgetting_and_projection_proved': False,
                  'python_correspondence_formally_proved': False,
                  'instruction_preservation_proved': False,
                  'complete_core_type_soundness_proved': False,
                  'complete_lowering_refinement_proved': False,
                  'concurrent_or_external_memory_proved': False},
        'safety_certificate': False}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x') as stream:
        json.dump(result, stream, indent=2, sort_keys=True); stream.write('\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lean', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = verify(args.lean, args.output)
    print(json.dumps({'passed': report['passed'], 'theorems': len(report['theorems']),
                      'negative_mutations': len(report['negative_mutations']), 'scope': report['scope']}, indent=2))
