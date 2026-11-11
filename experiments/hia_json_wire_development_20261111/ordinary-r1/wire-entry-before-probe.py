"""Original standalone wire profile/observation-order controls before ordinary selection."""
from hashlib import sha256
import json
from pathlib import Path
import sys
from hepta.hia_json_wire_native import SOURCE, installed_json_wire
from hepta.hia_program_tools import bounded_json_wire

root = Path('/workspace/scratch/e26ed3e2edcf')
image = installed_json_wire(root / 'json-wire-development-r1/manifest.json')


def run(native, name):
    events = []
    class Flag:
        def __bool__(self):
            events.append('flag-truthiness')
            raise RuntimeError('foreign flag observed')
    options, maximum, value = {'ensure_ascii': False, 'sort_keys': True}, 128, None
    if name == 'invalid-maximum-ascii':
        maximum, options['ensure_ascii'] = -1, Flag()
    elif name == 'invalid-maximum-sort':
        maximum, options['sort_keys'] = True, Flag()
    elif name == 'zero-budget-before-flags':
        maximum, options['ensure_ascii'] = 0, Flag()
    elif name == 'invalid-graph-before-flags':
        value, options['sort_keys'] = object(), Flag()
    else:
        value = 1.25
        def renderer(number):
            events.append(['render', number])
            return 'x' * 33 if name == 'arbitrary-renderer-wide' else '雪'
        options['float_renderer'] = renderer
    try:
        wire = image.encode(value, maximum, **options) if native else bounded_json_wire(value, maximum, **options)
        result = {'status': 'ok', 'wire_hex': wire.hex()}
    except BaseException as exc:
        result = {'status': 'error', 'type': type(exc).__name__, 'message': str(exc)}
    return {'result': result, 'events': events}


cases = []
for name in ('invalid-maximum-ascii', 'invalid-maximum-sort', 'zero-budget-before-flags',
             'invalid-graph-before-flags', 'arbitrary-renderer-wide', 'arbitrary-renderer-unicode'):
    old, new = run(False, name), run(True, name)
    cases.append({'case': name, 'same': old == new, 'retained': old, 'native': new})
report = {'schema': 'hia.ordinary-wire-preintegration-observation.v1',
          'source_commit': '6f92eca18aa4447d2f7eb920d680adcc546c41f8',
          'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(),
          'python': sys.version, 'executable': sys.executable,
          'scope': 'DEVELOPMENT_PROFILE_BOUNDARIES_NOT_FULL_API_EQUIVALENCE',
          'cases': cases}
target = root / 'wire-entry-before-observations.json'
target.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
print(json.dumps({'cases': len(cases), 'mismatches': sum(not x['same'] for x in cases), 'path': str(target)}))
