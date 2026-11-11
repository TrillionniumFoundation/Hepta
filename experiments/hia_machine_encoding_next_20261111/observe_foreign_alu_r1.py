"""Retain exact foreign ALU truth and bound-emit observations; never hide mismatch."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from hepta.hia_machine_x64 import Code
from hepta.hia_json_preflight_native import _installed_json_image
HERE = Path(__file__).resolve().parent


def load_bridge():
    spec = importlib.util.spec_from_file_location('foreign_alu_encoding_bridge', HERE / 'native_encoding_bridge.py')
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    return bridge


def observe(factory, values, immediate, rebind):
    code = factory()
    events = []
    class Truth:
        def __init__(self):
            self.count = 0
        def __bool__(self):
            self.count += 1
            answer = values[min(self.count - 1, len(values) - 1)]
            events.append(['truth', self.count, answer])
            if rebind and self.count == 3:
                def replacement(value):
                    events.append(['replacement_emit', value.hex()])
                code.emit = replacement
                events.append(['emit_rebound'])
            return answer
    truth = Truth()
    class Option:
        def __eq__(self, other):
            events.append(['option_equality', other])
            return truth
    code.alu_immediate = Option()
    error = None
    try:
        code.alu_imm('add', 'r10', immediate)
    except BaseException as exc:
        error = {'type': type(exc).__name__, 'message': str(exc)}
    return {'data_hex': code.data.hex(), 'events': events, 'exception': error,
            'labels': code.labels, 'fixups': code.fixups, 'relocations': code.relocations}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    bridge_path = HERE / 'native_encoding_bridge.py'
    paths = [Path(__file__), bridge_path, args.source, args.manifest]
    manifest = json.loads(args.manifest.read_bytes())
    image = args.manifest.parent / manifest['image_path']
    paths.append(image)
    def pins():
        return {str(path.resolve()): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    before = pins()
    report = {'schema': 'hepta.hia.machine-encoding.foreign-alu-observation.v1',
              'scope': 'DEVELOPMENT_FIELD_MUTATION_OBSERVATION_NOT_RELEASE', 'before': before,
              'status': 'STARTED', 'cases': []}
    (output / 'native_encoding_bridge.py').write_bytes(bridge_path.read_bytes())
    start = time.monotonic()
    try:
        bridge = load_bridge()
        encoding = _installed_json_image(str(args.manifest.resolve()), args.source.resolve(),
                                         manifest['schema'], bridge.NativeMachineEncoding)
        candidate = bridge.selected_code_class(encoding)
        cases = [
            ('all-false-observation-count', [False, False, False], 7, False),
            ('short-word-long-opcode', [False, True, False], 7, False),
            ('long-word-short-opcode', [False, False, True], 7, False),
            ('byte-pack-refusal-precedes-third-truth', [False, True, False], 128, False),
            ('emit-binding-precedes-third-truth', [False, False, False], 7, True),
        ]
        for name, values, value, rebind in cases:
            original = observe(Code, values, value, rebind)
            actual = observe(candidate, values, value, rebind)
            report['cases'].append({'id': name, 'truth_sequence': values, 'value': value,
                'rebind_emit_on_third_truth': rebind, 'reference': original, 'candidate': actual,
                'equal': original == actual})
        report['native_calls'] = dict(encoding.calls)
        report['mismatches'] = [row['id'] for row in report['cases'] if not row['equal']]
        report['status'] = 'MATCHED' if not report['mismatches'] else 'DIFFERENCES_OBSERVED'
    except BaseException:
        report['status'] = 'CONTROLLER_ERROR'
        report['exception'] = traceback.format_exc()
    report['after'] = pins()
    report['pins_stable'] = report['after'] == before
    report['seconds'] = time.monotonic() - start
    (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in ('schema', 'status', 'pins_stable', 'seconds')} |
                     {'mismatches': report.get('mismatches'), 'exception': report.get('exception')}))
    return 0 if report['pins_stable'] and report['status'] in {'MATCHED', 'DIFFERENCES_OBSERVED'} else 1


if __name__ == '__main__':
    raise SystemExit(main())
