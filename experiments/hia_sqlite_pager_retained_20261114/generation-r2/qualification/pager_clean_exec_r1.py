"""Clear the launcher environment and exec the fixed interpreter in this PID."""
from pathlib import Path
import json
import os
import sys

ROOT = Path(__file__).resolve().parent.parent
FIXED_ROOT = Path('/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2')
PYTHON = '/usr/bin/python3.14'
sys.path.insert(0, str(ROOT/'qualification'))
import pager_common_r1 as common

def main():
    common.require(ROOT == FIXED_ROOT and sys.executable == PYTHON
        and len(sys.argv) == 2 and len(sys.argv[1]) == 64
        and all(value in '0123456789abcdef' for value in sys.argv[1]),
        'fixed generation entry and request SHA')
    pin, raw = common.read(ROOT/'REQUEST.json', 1 << 20)
    common.require(pin['sha256'] == sys.argv[1], 'whole frozen request SHA')
    request = json.loads(raw)
    environment = {
        'LANG': 'C', 'LC_ALL': 'C', 'PATH': '',
        'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONHASHSEED': '0', 'TZ': 'UTC',
        'TMPDIR': str(ROOT.parent/'pager-retained-generation-r2-actual/tmp')}
    common.require(request['root'] == str(ROOT)
        and request['output'] == str(ROOT.parent/'pager-retained-generation-r2-actual')
        and request['environment'] == environment,
        'only the fixed clean environment')
    for name in ('pager_clean_exec_r1.py', 'pager_common_r1.py', 'pager_launch_r1.py'):
        relative = 'qualification/'+name
        actual, _ = common.read(ROOT/relative, 1 << 20)
        common.require(actual == request['inputs'][relative],
                       'entry/control complete frozen pin: '+name)
    os.execve(PYTHON, [PYTHON, '-I', '-S', '-B',
        str(ROOT/'qualification/pager_launch_r1.py'),
        str(ROOT/'REQUEST.json'), sys.argv[1]], environment)

if __name__ == '__main__':
    main()
