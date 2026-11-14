"""Exact existing runtime bridge; only fixed CLI launches occur in this gate."""
from pathlib import Path
import hashlib
import json
import threading
import time
import traceback
import sys
import entry_support as support
from entry_support import SOURCE, PLAN, identity, dump, require

def read_regular(path):
    raw, mode, _ = support.read_regular(path)
    return raw, mode


def read_owner_return(receipt_path, returned):
    raw, _ = read_regular(Path(receipt_path))
    expected = json.loads(raw)
    expected.update(supervisor_returncode=returned.get('supervisor_returncode'),
                    receipt_sha256=hashlib.sha256(raw).hexdigest())
    if expected['supervisor_returncode'] != 0 and expected['status'] == 'OWNED_PROCESS_COMPLETED':
        expected['status'] = 'OWNER_EXIT_MISMATCH_HOLD'
    require(returned == expected, 'complete owner raw plus actual wrapper fields differ')
    return expected



class RuntimeBridge:
    """Only the two retained 15-second owned Python launch sites gain libpython.

    The original argument list, five environment keys, child request schema,
    deadlines, owner receipt, status and return object are retained. Unrelated
    owner calls are delegated without adding an environment keyword.
    """
    def __init__(self, module, directory):
        self.module, self.original = module, module.run_owned
        self.directory = Path(directory)
        self.count = 0
        self.records = []
        self.lock = threading.Lock()

    def __enter__(self):
        self.directory.mkdir(parents=True, exist_ok=False)
        self.module.run_owned = self.call
        return self

    def __exit__(self, *exception):
        self.module.run_owned = self.original
        dump(self.directory / 'INDEX.json', {'calls': self.records, 'calls_started': self.count,
            'original_run_owned_restored': self.module.run_owned is self.original,
            'scope': 'only two fixed Python launch sites; original 15+3 retained'})

    def call(self, command, **kwargs):
        known = {str(SOURCE / 'tools/hia_selfhost_exports_child.py'),
                 str(SOURCE / 'tools/hia_selfhost_cli_child.py')}
        if not (type(command) in (list, tuple) and len(command) >= 5 and command[4] in known):
            return self.original(command, **kwargs)
        require(list(command[:4]) == [sys.executable, '-I', '-S', '-B'], 'fixed nested interpreter changed')
        require(len(command) == 9 and command[5] == '--request' and command[7] == '--sha256',
                'fixed nested Python request shape differs')
        require(kwargs.get('qualification_seconds') == 15 and kwargs.get('cleanup_seconds', 3) == 3
                and 'supervisor_env' not in kwargs, 'retained nested owner budget or caller changed')
        initial = kwargs.get('env')
        require(type(initial) is dict and initial == {'PATH': '/usr/bin:/bin',
            'HOME': str(Path(kwargs['cwd']).resolve()), 'LANG': 'C.UTF-8',
            'LC_ALL': 'C.UTF-8', 'TZ': 'UTC'}, 'retained nested environment changed')
        original_environment = dict(initial)
        library = PLAN['runtime']['library']
        require(identity(Path(library['path'])) == library['identity'], 'loaded library bytes changed')
        effective = dict(initial)
        effective['LD_LIBRARY_PATH'] = str(Path(library['path']).parent)
        with self.lock:
            index = self.count
            self.count += 1
        folder = self.directory / ('call-%04d' % index)
        folder.mkdir()
        row = {'command': list(command), 'cwd': str(kwargs['cwd']), 'original_environment': dict(initial),
            'effective_child_environment': effective, 'effective_supervisor_environment': effective,
            'qualification_seconds': 15, 'cleanup_seconds': 3,
            'runtime_executable': PLAN['runtime']['executable'], 'runtime_library': library,
            'original_owner_source': PLAN['owner_source'], 'status': 'STARTED',
            'monotonic_before': time.monotonic_ns()}
        dump(folder / 'REQUEST.json', row)
        try:
            changed = dict(kwargs, env=effective, supervisor_env=effective)
            returned = self.original(command, **changed)
            dump(folder / 'RETURNED.json', returned)
            if Path(kwargs['receipt_path']).is_file():
                read_owner_return(kwargs['receipt_path'], returned)
            # A missing/invalid receipt is retained by the original owner and
            # returned to the unchanged original family assertion.
            row.update(status='RETURNED', returned_status=returned.get('status'))
            return returned
        except BaseException as error:
            row.update(status='EXCEPTION', error_type=type(error).__name__, error=str(error),
                       traceback=traceback.format_exc())
            raise
        finally:
            row['monotonic_after'] = time.monotonic_ns()
            row['original_environment_unchanged'] = kwargs['env'] == original_environment
            require(row['original_environment_unchanged'], 'nested caller environment was mutated')
            dump(folder / 'RESULT.json', row)
            with self.lock:
                self.records.append({'index': index, 'path': str(folder), 'status': row['status']})

