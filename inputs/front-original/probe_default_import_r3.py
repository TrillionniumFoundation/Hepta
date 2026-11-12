"""Observe the actual interpreter's default front imports in a fresh process."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
source = args.source.resolve(strict=True)
args.output.mkdir(parents=True, exist_ok=False)
for key in tuple(os.environ):
    if key.startswith('HEPTA_HIA_'):
        del os.environ[key]
sys.path.insert(0, str(source))
events = []
def trace(frame, event, arg):
    if event == 'call' and frame.f_code.co_name in ('_profile', '_runtime_profile'):
        filename = frame.f_code.co_filename
        if '/hia_front_' in filename or filename.endswith(('_verification_ports.py', '_assembly_front_ports.py')):
            events.append({'file': filename, 'function': frame.f_code.co_name,
                           'caller': frame.f_back.f_code.co_name if frame.f_back else None})
    return trace

sys.settrace(trace)
try:
    from hepta import hia_program as program
    from hepta import hia_agent_assembly as assembly
finally:
    sys.settrace(None)
ports = sorted(n for n in sys.modules if n in (
    'hepta.hia_core_verification_ports', 'hepta.hia_assembly_front_ports'))
report = {'schema': 'hia.front.default-import.actual-interpreter.v81.r3',
          'python': sys.version, 'version_info': list(sys.version_info),
          'implementation': sys.implementation.name,
          'events': events, 'ports_loaded': ports,
          'default_public_functions': [program.verify_program.__qualname__,
                                       assembly.assemble_program.__qualname__],
          'actual_python311': sys.version_info[:2] == (3, 11),
          'status': 'PASS' if not events and not ports else 'FAIL',
          'source': {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                     for name in ('hepta/hia_core_verification_native.py',
                                  'hepta/hia_assembly_front_native.py')},
          'whole_normalization': False, 'current_cold': False}
(args.output / 'REPORT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps(report, sort_keys=True))
raise SystemExit(0 if report['status'] == 'PASS' else 1)
