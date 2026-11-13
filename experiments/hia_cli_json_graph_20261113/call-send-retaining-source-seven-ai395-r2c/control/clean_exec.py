"""Enter the frozen source guardian with only its declared environment."""
import os
import sys

ROOT = '/home/qq/hia-rewrite-20261113-e26e-r1/cli-source-seven-r2c'
PYTHON = '/usr/bin/python3.14'
if len(sys.argv) != 2:
    raise SystemExit('one frozen guardian request SHA256 is required')
digest = sys.argv[1]
if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
    raise SystemExit('invalid guardian request SHA256')
if os.path.realpath(sys.executable) != PYTHON:
    raise SystemExit('source-only Python executable differs')
command = [PYTHON, '-I', '-S', '-B', ROOT + '/control/guardian.py',
           '--config', ROOT + '/guardian/REQUEST.json',
           '--config-sha256', digest,
           '--implementation', ROOT + '/control/process_owner_impl.py']
os.chdir(ROOT + '/source')
os.execve(PYTHON, command,
          {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PATH': '/usr/bin:/bin'})
