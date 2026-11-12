"""Original callers, exact module bytes and old-body exclusions per real profile."""
from __future__ import annotations
import argparse
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'source'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--profile', choices=('default', 'core', 'assembly', 'both'), required=True)
parser.add_argument('--group', choices=('program-composite', 'assembly', 'all'), required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
OUT = args.output.absolute()
OUT.mkdir(exist_ok=False)
base = json.loads((ROOT / 'BASE.json').read_bytes())['files']
build = json.loads((ROOT / 'native-build-r1/RESULT.json').read_bytes())
assert build['status'] == 'DEVELOPMENT_TWO_IMAGES_BUILT'
for name in tuple(os.environ):
    if name.startswith('HEPTA_HIA_') and name.endswith('_MANIFEST'):
        os.environ.pop(name)
selected = {'core_verification': args.profile in ('core', 'both'),
            'assembly_front': args.profile in ('assembly', 'both')}
selectors = {'core_verification': 'HEPTA_HIA_CORE_VERIFICATION_MANIFEST',
             'assembly_front': 'HEPTA_HIA_ASSEMBLY_FRONT_MANIFEST'}
for stem, enabled in selected.items():
    if enabled:
        os.environ[selectors[stem]] = build['images'][stem]['manifest_path']
sys.path.insert(0, str(SOURCE))
from hepta import hia_program as program, hia_agent_assembly as assembly

owners = {}
traces = {}
trace_streams = {}
counts = {stem: Counter() for stem in selected}
mode_counts = {stem: Counter() for stem in selected}
input_bytes = {}

for stem, enabled in selected.items():
    item = build['images'][stem]
    path = Path(item['manifest_path'])
    image_path = path.parent / item['manifest']['image_path']
    input_bytes[path] = path.read_bytes()
    input_bytes[image_path] = image_path.read_bytes()
    if not enabled:
        continue
    if stem == 'core_verification':
        from hepta.hia_core_verification_selection import installed_core_verification
        owner = installed_core_verification(path)
    else:
        from hepta.hia_assembly_front_selection import installed_assembly_front
        owner = installed_assembly_front(path)
    owners[stem] = owner
    original_entry = owner._entry
    trace_path = OUT / (stem + '-request6Q-resultQ.bin')
    stream = trace_path.open('xb')
    trace_streams[stem] = stream
    traces[stem] = trace_path
    def observed(source, size, out, out_size, state, state_size,
                 _entry=original_entry, _stem=stem, _stream=stream):
        assert state_size >= 48
        words = struct.unpack_from('<6Q', state)
        result = _entry(source, size, out, out_size, state, state_size)
        _stream.write(struct.pack('<7Q', *words, result))
        counts[_stem][words[0]] += 1
        if words[0] == 0:
            mode_counts[_stem][words[3]] += 1
        return result
    owner._entry = observed

POISON = []
def forbidden(*unused, **keywords):
    POISON.append('selected original policy entered')
    raise AssertionError('selected original front policy entered')

saved = []
globals_saved = []
for stem, module in (('core_verification', program), ('assembly_front', assembly)):
    if not selected[stem]:
        continue
    namespace = vars(module)
    assert 'POISON' not in namespace
    namespace['POISON'] = POISON
    globals_saved.append(namespace)
    for name in owners[stem].ARITIES:
        function = getattr(module, '_' + stem + '_reference' + name)
        saved.append((function, function.__code__))
        function.__code__ = forbidden.__code__

modules = []
if args.group in ('program-composite', 'all'):
    modules += [('tests.test_hia_program', 21), ('tests.test_hia_program_composite', 25)]
if args.group in ('assembly', 'all'):
    modules.append(('tests.test_hia_agent_assembly', 18))

def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test.id()

def source_snapshot():
    return {p.relative_to(SOURCE).as_posix(): {
        'sha256': sha256(p.read_bytes()).hexdigest(), 'mode': p.stat().st_mode & 0o777}
        for p in SOURCE.rglob('*') if p.is_file() and '__pycache__' not in p.parts}

loader = unittest.TestLoader()
suite = unittest.TestSuite()
loaded = []
original_sources = {}
for name, expected in modules:
    filename = '/'.join(name.split('.')) + '.py'
    raw = (SOURCE / filename).read_bytes()
    assert sha256(raw).hexdigest() == base[filename]['sha256']
    group = loader.loadTestsFromName(name)
    ids = list(flatten(group))
    assert len(ids) == expected and not loader.errors
    loaded.extend(ids)
    suite.addTests(group)
    original_sources[filename] = {'sha256': sha256(raw).hexdigest(), 'bytes': len(raw), 'ordered_ids': ids}

executed = []
class Result(unittest.TextTestResult):
    def startTest(self, test):
        executed.append(test.id())
        super().startTest(test)

before = source_snapshot()
started = time.monotonic()
try:
    with (OUT / 'tests.log').open('w') as log:
        result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=Result).run(suite)
finally:
    for function, code in saved:
        function.__code__ = code
    for namespace in globals_saved:
        assert namespace.pop('POISON') is POISON
    for stream in trace_streams.values():
        stream.close()
after = source_snapshot()
trace_meta = {}
for stem, path in traces.items():
    raw = path.read_bytes()
    assert len(raw) == sum(counts[stem].values()) * 56
    trace_meta[stem] = {'file': path.name, 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
unchanged = before == after and all(path.read_bytes() == raw for path, raw in input_bytes.items())
anomalies = any((result.failures, result.errors, result.skipped,
                 result.expectedFailures, result.unexpectedSuccesses))
passed = (unchanged and not anomalies and not POISON and loaded == executed
          and result.testsRun == sum(n for _, n in modules)
          and all(sum(counts[stem].values()) > 0 for stem, enabled in selected.items() if enabled))
report = {'schema': 'hia.front.original-callers.v81.r1', 'status': 'PASS' if passed else 'FAIL',
          'scope': 'DEVELOPMENT_ONLY_NEW_TWO_IMAGE_ARCHITECTURE', 'python': sys.version,
          'profile': args.profile, 'group': args.group,
          'original_sources': original_sources, 'loaded': loaded, 'executed': executed,
          'tests_run': result.testsRun, 'old_body_calls': POISON,
          'failures': [(str(t), text) for t, text in result.failures],
          'errors': [(str(t), text) for t, text in result.errors],
          'skipped': result.skipped,
          'expected_failures': [(str(t), text) for t, text in result.expectedFailures],
          'unexpected_successes': list(map(str, result.unexpectedSuccesses)),
          'actual_commands': {k: dict(v) for k, v in counts.items()},
          'actual_mode_initializations': {k: dict(v) for k, v in mode_counts.items()},
          'actual_traces': trace_meta, 'source_before': before, 'source_after': after,
          'inputs_unchanged': unchanged, 'seconds': time.monotonic() - started,
          'old_thirteen_root_results_inherited': False, 'cold': False, 'whole_normalization': False}
(OUT / 'REPORT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps({key: report[key] for key in ('status', 'profile', 'group', 'tests_run',
                                             'seconds', 'actual_commands', 'actual_mode_initializations')}, sort_keys=True))
raise SystemExit(0 if passed else 1)
