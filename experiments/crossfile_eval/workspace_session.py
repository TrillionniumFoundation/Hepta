"""The fourth arm: actual production v4 in a persistent, isolated capsule.

No production validator executes in the parent. Prepare and commit use the same
request/profile; private task validation happens before publication. The final
candidate is read from a fresh production pin, never from a speculative cache.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import tempfile
import time

import hepta
from hepta.backend import find_rustc
from hepta.pipeline import compiler_hash
from experiments.agent_eval.harness import EvalError
from experiments.agent_eval.sandbox import run_bounded

from .runner import FileStudySession
from .scoring import check_candidate, python_read_only
from .tasks import ROOT, canonical, digest, snapshot_id, validate_files


class ProductionWorkspaceSession(FileStudySession):
    def __init__(self, request, *, rustc=None, fixture=False, timeout=30.0):
        self.request, self.arm = request, 'hepta_protocol'
        self.rustc = str(Path(find_rustc(rustc)).resolve())
        self.fixture = fixture
        self.files, self.version = dict(request['files']), request['base_sha256']
        self.validation_seconds = 0.0
        self.events = []
        self.profile = None
        self.publication_state = 'not_initialized'
        self.initialized = self.inspected = self.committed = self.recovered = self.final_pinned = False
        self.prepared_version = self.committed_version = self.initial_version = None
        self.expected_compiler = compiler_hash()
        self._temporary = tempfile.TemporaryDirectory(prefix='hepta-crossfile-workspace-')
        self.directory = Path(self._temporary.name)
        deadline = time.monotonic() + timeout
        try:
            shutil.copytree(Path(hepta.__file__).parent, self.directory / 'hepta',
                            ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            shutil.copyfile(ROOT / '_workspace_frontend.py', self.directory / 'workspace_frontend.py')
            for name, source in request['files'].items():
                path = self.directory / 'bundle' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source)
            result = self._rpc('initialize', self._remaining(deadline), entry=request['entry'])
            if not result.get('ok') or result.get('applied') is not True:
                raise EvalError('E_WORKSPACE_INITIALIZE', 'Production initialization failed: ' + str(result.get('diagnostics', result.get('validation'))))
            self._accept(result['current_snapshot'])
            self.initial_version = self.version
            self.initialized = True
            self.publication_state = 'initialized'
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _remaining(deadline):
        left = deadline - time.monotonic()
        if left <= 0: raise EvalError('E_WALL_BUDGET', 'shared workspace/tool deadline exhausted')
        return left

    def close(self):
        if getattr(self, '_temporary', None) is not None:
            self._temporary.cleanup()
            self._temporary = None

    def _rpc(self, operation, timeout, **payload):
        started = time.monotonic()
        try:
            process = run_bounded([sys.executable, str(self.directory / 'workspace_frontend.py')],
                                  cwd=self.directory, input_bytes=canonical({'operation': operation, 'rustc': self.rustc, **payload}),
                                  timeout=timeout, fixture=self.fixture,
                                  read_only=[str(Path(self.rustc).parent.parent), *python_read_only()], max_output=2 * 1024 * 1024)
        except (ValueError, OSError) as exc:
            self.publication_state = 'unverified_after_' + operation
            raise EvalError('E_WORKSPACE_TRANSPORT', 'Workspace transport failed; attempt stopped with unverified publication state') from exc
        elapsed = time.monotonic() - started
        if operation in {'prepare', 'commit'}: self.validation_seconds += elapsed
        event = {'operation': operation, 'elapsed_seconds': round(elapsed, 6),
                 'namespace_required': not self.fixture,
                 'process_status': process['status'], 'process_returncode': process['returncode'],
                 'response_sha256': digest(process['stdout'].encode())}
        if 'patch' in payload:
            event['patch_sha256'] = digest(canonical(payload['patch']))
            event['patch_preconditions'] = {key: payload['patch'][key] for key in
                ('schema', 'expected_version', 'expected_interface_sha256', 'interface_policy')}
        self.events.append(event)
        if process['status'] != 'exited' or process['returncode']:
            self.publication_state = 'unverified_after_' + operation
            raise EvalError('E_WORKSPACE_TRANSPORT', 'Workspace child did not finish; publication state is unverified and this attempt must stop')
        try:
            result = json.loads(process['stdout'])
        except ValueError as exc:
            self.publication_state = 'unverified_after_' + operation
            raise EvalError('E_WORKSPACE_TRANSPORT', 'Invalid workspace response; publication state is unverified') from exc
        if not isinstance(result, dict):
            raise EvalError('E_WORKSPACE_TRANSPORT', 'Workspace response must be an object')
        event.update({key: result[key] for key in ('api', 'schema', 'ok', 'applied', 'status', 'before', 'after',
                                                  'interface_changed', 'recovery', 'publication') if key in result})
        for key in ('snapshot', 'current_snapshot'):
            if key in result:
                event[key] = {k: v for k, v in result[key].items() if k != 'files'}
        if result.get('operation') == 'rpc_error':
            self.publication_state = 'unverified_after_' + operation
            raise EvalError('E_WORKSPACE_RPC', 'Production workspace RPC failed with unverified publication state: ' + str(result.get('diagnostics')))
        return result

    def _verify_snapshot(self, value):
        files = validate_files(self.request, value['files'])
        if value['source_sha256'] != snapshot_id(files):
            raise EvalError('E_WORKSPACE_IDENTITY', 'Pinned source identity differs from its actual bytes')
        if value['file_sha256'] != {p: digest(source.encode()) for p, source in files.items()}:
            raise EvalError('E_WORKSPACE_IDENTITY', 'Pinned file identities differ')
        if (value['compiler_sha256'] != self.expected_compiler or value['validation']['ok'] is not True
                or value['validation']['backend_ok'] is not True
                or value['profile']['compiler_sha256'] != self.expected_compiler
                or value['profile']['rustc_sha256'] != value['validation']['rustc_sha256']):
            raise EvalError('E_WORKSPACE_PROFILE', 'Production snapshot lacks matching complete native validation')
        if self.profile is not None and value['profile'] != self.profile:
            raise EvalError('E_WORKSPACE_PROFILE', 'Workspace native profile changed during the sample')
        return files

    def _accept(self, value, expected=None):
        files = self._verify_snapshot(value)
        if expected is not None and value['version'] != expected:
            raise EvalError('E_WORKSPACE_IDENTITY', 'Published/pinned version differs from the expected transaction')
        self.files, self.version = files, value['version']
        self.interface_sha256, self.profile = value['interface_sha256'], value['profile']
        self.pinned_metadata = {k: v for k, v in value.items() if k != 'files'}

    def _inspect(self, timeout):
        result = self._rpc('inspect', timeout)
        if not result.get('ok'): raise EvalError('E_WORKSPACE_INSPECT', 'Production workspace inspection failed')
        self._accept(result['current_snapshot'], self.version)
        self.inspected = True
        return result

    def _recover(self, timeout, expected=None):
        result = self._rpc('recover', timeout)
        if not result.get('ok'): raise EvalError('E_WORKSPACE_RECOVERY', 'Production workspace recovery failed')
        self._accept(result['current_snapshot'], expected)
        self.recovered = True
        self.publication_state = 'recovered_' + result.get('recovery', 'unknown')
        return result

    def execute(self, operation, arguments, timeout):
        deadline = time.monotonic() + timeout
        if operation not in self.tools: raise ValueError('E_TOOL: unavailable in the assigned arm')
        if not isinstance(arguments, dict): raise ValueError('E_TOOL_SCHEMA: arguments must be an object')
        if operation in {'read_file', 'check', 'public_test'}:
            # Refresh even reads: a session cache is not a production pin.
            pinned = self._rpc('pin', self._remaining(deadline))
            self._accept(pinned['current_snapshot'], self.version)
            return super().execute(operation, arguments, self._remaining(deadline))
        if operation == 'query_nodes':
            if arguments: raise ValueError('E_TOOL_SCHEMA: query_nodes takes no arguments')
            inspected = self._inspect(self._remaining(deadline))
            return {'ok': True, 'version': self.version, 'interface_sha256': self.interface_sha256,
                    'interface_policy': self.request['interface_policy'],
                    'coverage': 'production_hepta_workspace_v4_function_body_declaration_intersection',
                    'nodes': {p: inspected['nodes'][p] for p in self.request['editable']},
                    'operations': ['replace_function', 'replace_body', 'replace_declaration'],
                    'protocol_backend': 'hepta.workspace/hepta.patch.v4'}
        if set(arguments) != {'expected_version', 'edits'} or arguments['expected_version'] != self.version:
            raise ValueError('E_STALE_SNAPSHOT: exact current production version is required')
        edits = arguments['edits']
        if not isinstance(edits, list) or not 1 <= len(edits) <= 128:
            raise ValueError('E_PATCH_SCHEMA: require 1..128 semantic edits')
        inspected = self._inspect(self._remaining(deadline))
        mapped = []
        for edit in edits:
            if (not isinstance(edit, dict) or set(edit) != {'op', 'target', 'node', 'replacement'}
                    or any(not isinstance(v, str) for v in edit.values())
                    or edit['op'] not in {'replace_function', 'replace_body', 'replace_declaration'}):
                raise ValueError('E_PATCH_SCHEMA: malformed common semantic edit')
            if edit['target'] not in self.request['editable']: raise ValueError('E_PATCH_SCOPE: target is not editable')
            kind = edit['op'].removeprefix('replace_')
            matches = [n for n in inspected['nodes'][edit['target']] if n['id'] == edit['node'] and n['kind'] == kind]
            if len(matches) != 1: raise ValueError('E_PATCH_NODE: stale or incorrect production node')
            mapped.append({**edit, 'op': 'replace_' + matches[0]['native_kind']})
        before = self.version
        patch = {'schema': 'hepta.patch.v4', 'expected_version': before,
                 'expected_interface_sha256': self.interface_sha256,
                 'interface_policy': self.request['interface_policy'], 'edits': mapped}
        prepared = self._rpc('prepare', self._remaining(deadline), patch=patch)
        if not prepared.get('ok'):
            self._accept(prepared['current_snapshot'], before)
            return {'ok': False, 'applied': False, 'version': before, 'validation': prepared,
                    'protocol_backend': 'hepta.workspace/hepta.patch.v4'}
        if prepared.get('applied') is not False:
            raise EvalError('E_WORKSPACE_PREPARE', 'Production preview unexpectedly published a version')
        self._accept(prepared['current_snapshot'], before)
        candidate = self._verify_snapshot(prepared['snapshot'])
        prepared_version = prepared['after']
        started = time.monotonic()
        checked = check_candidate(self.request, candidate, rustc=self.rustc, fixture=self.fixture,
                                  timeout=self._remaining(deadline))
        self.validation_seconds += time.monotonic() - started
        if not checked['ok']:
            return {'ok': False, 'applied': False, 'version': before, 'validation': checked,
                    'prepared_workspace_version': prepared_version,
                    'protocol_backend': 'hepta.workspace/hepta.patch.v4'}
        if checked['source_sha256'] != prepared['snapshot']['source_sha256']:
            raise EvalError('E_WORKSPACE_IDENTITY', 'Native task gate checked a different candidate')
        # Reuse the identical request: never repin a new expected head/interface
        # to make an already stale transaction appear current.
        committed = self._rpc('commit', self._remaining(deadline), patch=patch)
        if not committed.get('ok') or committed.get('applied') is not True:
            self.publication_state = 'unverified_after_commit'
            try: self._recover(self._remaining(deadline))
            except (EvalError, OSError, ValueError): pass
            raise EvalError('E_WORKSPACE_COMMIT', 'Production commit did not finish normally; attempt stopped, publication state: ' + self.publication_state)
        if committed.get('after') != prepared_version:
            raise EvalError('E_WORKSPACE_IDENTITY', 'Commit differs from the native-checked prepared version')
        self._accept(committed['current_snapshot'], prepared_version)
        if snapshot_id(self.files) != checked['source_sha256']:
            raise EvalError('E_WORKSPACE_IDENTITY', 'Published source differs from the task-checked candidate')
        self.committed_version = self.version
        self.prepared_version = prepared_version
        self.committed = True
        recovered = self._recover(self._remaining(deadline), self.committed_version)
        return {'ok': True, 'applied': True, 'before': before, 'version': self.version,
                'source_sha256': snapshot_id(self.files), 'validation': checked,
                'interface_changed': committed['interface_changed'],
                'workspace': {'schema': committed['schema'], 'prepared': prepared['after'], 'committed': committed['after'],
                              'recovery': recovered['recovery'], 'publication': recovered['publication'], 'profile': self.profile},
                'persistence': 'production_current_reference_fsync_across_worker_processes',
                'protocol_backend': 'hepta.workspace/hepta.patch.v4'}

    def finalize(self, timeout):
        pinned = self._rpc('pin', timeout)
        self._accept(pinned['current_snapshot'], self.version)
        self.final_pinned = True
        return self.files

    def evidence(self):
        exercised = self.initialized and self.inspected and self.committed and self.recovered and self.final_pinned
        return {'backend': 'hepta.workspace/hepta.patch.v4', 'production_workspace_v4_exercised': exercised,
                'namespace_required': not self.fixture,
                'initialized': self.initialized, 'inspected': self.inspected, 'committed': self.committed,
                'recovered': self.recovered, 'final_pinned': self.final_pinned,
                'initial_workspace_version': self.initial_version, 'prepared_workspace_version': self.prepared_version,
                'committed_workspace_version': self.committed_version, 'workspace_version': self.version,
                'source_sha256': snapshot_id(self.files), 'profile': self.profile,
                'publication_state': self.publication_state, 'events': self.events,
                'validation_seconds': round(self.validation_seconds, 6),
                'capability_scope': ['initialize', 'function_body_declaration_edits', 'interface_policy',
                                     'whole_graph_native_validation', 'durable_current_publication', 'recover', 'final_pin'],
                'not_claimed': ['expression_edits', 'statement_edits', 'crash_injection_during_task_runs',
                                'persistent_user_project_after_experiment_cleanup']}
