"""Observe the exact retained Core.label call with fresh receiver/argument values.

This is a private-method lifecycle differential. It does not claim that a
locally observed interpreter profile proves a different CPython profile.
"""
from __future__ import annotations
from hashlib import sha256
import json
from pathlib import Path
import sys
import time
import weakref

HERE = Path(__file__).resolve().parent
SOURCE_ROOT = Path(sys.argv[1]).resolve()
MANIFEST = Path(sys.argv[2]).resolve()
OUT = Path(sys.argv[3]).resolve()
OUT.mkdir(parents=True, exist_ok=False)
sys.path.insert(0, str(SOURCE_ROOT))

from hepta import hia_program_native as backend
from hepta.hia_core_lowering_selection import installed_core_lowering

def identity(path):
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}

manifest = json.loads(MANIFEST.read_bytes())
image_path = (MANIFEST.parent / manifest['image_path']).resolve()
paths = [MANIFEST, image_path,
         SOURCE_ROOT / 'hepta/hia_machine_plan_control_native.py',
         SOURCE_ROOT / 'tools/hia_machine_plan_control.py',
         SOURCE_ROOT / 'hepta/hia_core_lowering_native.py',
         SOURCE_ROOT / 'hepta/hia_program_native.py',
         SOURCE_ROOT / 'examples/hia_bootstrap/core_lowering.hiaasm',
         Path(__file__)]
before = {str(path): identity(path) for path in paths}
owner = installed_core_lowering(str(MANIFEST), vars(backend))
native_class = owner.function_class(backend._Function)

class ProbeError(Exception):
    pass

def observe(kind, fails, outer):
    events, refs = [], []

    def mark(event):
        active = sys.exception()
        events.append([event, None if active is None else type(active).__name__])

    class Name:
        def __init__(self):
            mark('name-created')
            refs.append(('name', weakref.ref(self)))
        def __del__(self):
            mark('name-del')

    class Suffix:
        def __radd__(self, prefix):
            if prefix != 'fn0_':
                raise AssertionError('retained Core label prefix changed')
            return Name()

    class Receiver:
        def __init__(self):
            mark('receiver-created')
            refs.append(('receiver', weakref.ref(self)))
        def label(self, name):
            if type(name) is not Name:
                raise AssertionError('original temporary argument not delivered')
            mark('callee-entered')
            if fails:
                raise ProbeError('actual original bound-method failure')
            return 37
        def __del__(self):
            mark('receiver-del')

    class Parent:
        @property
        def label(self):
            return Receiver().label

    instance = object.__new__(kind)
    instance.parent, instance.index = Parent(), 0

    def invoke():
        try:
            return True, instance.label(Suffix())
        except BaseException as error:
            return False, error

    def run():
        observed = invoke()
        result = (['value', observed[1]] if observed[0] else
                  ['error', type(observed[1]).__name__, list(observed[1].args)])
        alive_while_error_held = {name: ref() is not None for name, ref in refs}
        while_held = list(events)
        # No traceback is cleared and no GC is invoked. The invoke() handler
        # has already exited, so dropping this result drops its final holder.
        observed = None
        return {'outcome': result, 'while_held': while_held,
                'alive_while_held': alive_while_error_held,
                'after_release': list(events),
                'alive_after_release': {name: ref() is not None for name, ref in refs}}

    if outer:
        try:
            raise LookupError('actual outer handler')
        except LookupError:
            return run()
    return run()

started = time.monotonic()
cases = []
for fails in (False, True):
    for outer in (False, True):
        expected = observe(backend._Function, fails, outer)
        entry_before = owner.entries
        actual = observe(native_class, fails, outer)
        entry_after = owner.entries
        assert entry_after > entry_before
        assert not any(expected['alive_after_release'].values())
        cases.append({'fails': fails, 'outer': outer,
                      'expected': expected, 'actual': actual,
                      'native_entries': entry_after - entry_before,
                      'equal': expected == actual})
after = {str(path): identity(path) for path in paths}
assert before == after
report = {'schema': 'hia.shared-frame-r4-original-core-call-witness.v1',
          'scope': 'ACTUAL_CORE_LABEL_REFERENCE_AND_SELECTED_R3_PRIVATE_METHOD',
          'python': sys.version, 'runtime_profile': owner.runtime_profile,
          'cases': cases, 'count': len(cases),
          'matches': sum(case['equal'] for case in cases),
          'native_entries': sum(case['native_entries'] for case in cases),
          'input_before': before, 'input_after': after,
          'seconds': time.monotonic() - started,
          'status': 'PASS' if all(case['equal'] for case in cases) else 'DIFFERENCE_OBSERVED',
          'current_cold': False, 'cross_version_qualification': False,
          'no_traceback_detach_or_gc_cleanup': True}
(OUT / 'REPORT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps({k: report[k] for k in ('status', 'runtime_profile', 'count', 'matches', 'native_entries', 'seconds')}))
