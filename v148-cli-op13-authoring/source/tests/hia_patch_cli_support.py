"""Actual eight-image observation support for the explicit CLI op13 gate.

Importing maps no image. An authorized owned executor must bind the complete
source, two original observer modules and eight actual component manifests.
No positive control supplies a policy result or constructs a mock owner.
"""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import ctypes
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import stat
import struct
import sys
import traceback
from unittest.mock import patch

import inspect_cli_control_support as retained
import inspect_exec_support as original_observer
from tests.hia_patch_result_support import (
    FrameJournal, FRAME_KEYS, exception_value, observed_admission, pin, publish, require,
)

CONTEXT = None
NEW_PRODUCTION = ('hepta/hia_patch_cli_records.py', 'hepta/hia_cli_patch_result_native.py')


def configure(value):
    global CONTEXT
    require(CONTEXT is None and type(value) is dict, 'one explicit op13 context required')
    require(value.get('schema') == 'hepta.hia.patch-cli.control-context.v3', 'control schema differs')
    require(value.get('phase') in ('source', 'native'), 'explicit source or native phase required')
    for key in ('source', 'controls_output'):
        require(type(value.get(key)) is str and Path(value[key]).is_absolute(), 'absolute input required: ' + key)
    if value['phase'] == 'native':
        for key in ('report_manifest', 'inspect_manifest', 'patch_manifest'):
            require(type(value.get(key)) is str and Path(value[key]).is_absolute(),
                    'absolute actual Native manifest required: ' + key)
        require(type(value.get('signature_native')) is bool, 'explicit signature admission choice required')
    else:
        require(not any(key in value for key in
                ('report_manifest', 'inspect_manifest', 'patch_manifest', 'signature_native')),
                'Source phase must not smuggle a Native invocation context')
    for module, key in ((retained, 'retained_support'), (original_observer, 'original_observer')):
        row = value[key]
        require(Path(module.__file__).absolute() == Path(row['path'])
                and pin(Path(row['path']).read_bytes()) ==
                    {name: row['pin'][name] for name in ('bytes', 'git_blob', 'sha256')}
                and stat.S_IMODE(Path(row['path']).lstat().st_mode) == row['posix_mode'],
                'frozen original observer differs')
    CONTEXT = value
    if value['phase'] == 'native':
        retained.configure({key: value[key] for key in
            ('source', 'report_manifest', 'inspect_manifest', 'controls_output', 'adapter_files')})


def context():
    require(type(CONTEXT) is dict, 'explicit actual-manifest execution context required')
    return CONTEXT


class LostPatchReturn(BaseException):
    pass


class StablePatchEntry:
    """Stable before issuance; an armed loss follows a real claim return.

Full after buffers precede the loss. No native result or ACK is invented.
"""
    def __init__(self, journal):
        self.journal, self.entry = journal, journal.entry
        self.armed, self.losses = False, []

    def __call__(self, source, source_size, output, output_size, workspace, workspace_size):
        command = struct.unpack('<Q', ctypes.string_at(workspace, 8))[0]
        result = self.entry(source, source_size, output, output_size, workspace, workspace_size)
        if self.armed and command == 2 and result == 4:
            self.armed = False
            self.losses.append({'frame': self.journal.rows[-1]['index'], 'command': command,
                                'actual_return': result})
            raise LostPatchReturn('lost actual patch claim return')
        return result


def plain(value):
    from hepta.hia_program import VerifiedProgram
    if type(value) is VerifiedProgram:
        return {'VerifiedProgram': {'canonical_bytes_hex': value.canonical_bytes.hex(),
            'structured_bytes_hex': None if value.structured_bytes is None else value.structured_bytes.hex()}}
    if type(value) is dict:
        return {'dict': [[plain(key), plain(item)] for key, item in value.items()]}
    if type(value) in (list, tuple):
        return {type(value).__name__: [plain(item) for item in value]}
    if type(value) in (str, int, bool, type(None)):
        return {'type': type(value).__name__, 'value': value}
    raise AssertionError('unobserved control return protocol: ' + type(value).__name__)


def comparable(row):
    return {key: row.get(key) for key in ('kind', 'value', 'error', 'stdout', 'stderr')}


class ActualPatchCli:
    """Original seven real owners plus an independently admitted Patch owner.

Patch is not mapping-cached. The qualification-only source-binder hook calls
the original once and installs the real journal before the issuer capture.
"""
    def __init__(self, directory):
        cfg = context()
        require(cfg['phase'] == 'native', 'actual component construction requires the Native phase')
        self.directory = Path(directory).absolute()
        self.directory.mkdir(mode=0o700)
        self.rows, self.sessions, self.issuance = [], [], []
        self.closed = False
        self.base = self.patch_journal = self.patch_owner = self.gate = None
        publish(self.directory / 'SETUP-INTENT.json', {
            'source': cfg['source'], 'manifests': {name: cfg[name + '_manifest']
                for name in ('report', 'inspect', 'patch')},
            'new_production': cfg['new_production'], 'signature_native': cfg['signature_native'],
            'setup_failure_is_not_a_positive': True, 'native_result_substitution': False})
        try:
            self.base = retained.ActualComponents(self.directory / 'retained-seven')
            from hepta import hia_cli_patch_result_native as adapter
            from hepta import hia_patch_cli_records as records
            from hepta.hia_patch_result_native import NativePatchResult
            self.adapter, self.records = adapter, records
            self.cli, self.tools, self.program = self.base.cli, self.base.tools, self.base.program
            self.module = self.base.module
            loaded = {}
            for relative in NEW_PRODUCTION:
                name = relative[:-3].replace('/', '.')
                module = sys.modules.get(name)
                path = Path(cfg['source']) / relative
                raw = path.read_bytes()
                require(module is not None and Path(module.__file__).absolute() == path
                        and pin(raw) == cfg['new_production'][relative],
                        'new module is not in the bound complete source view')
                loaded[name] = {'path': str(path), **pin(raw)}
            original_bind = NativePatchResult._bind_manifest_source
            original_code = original_bind.__code__
            def bind_actual(owner, source_sha):
                result = original_bind(owner, source_sha)
                require(not self.issuance, 'unexpected second Patch mapping during issuance')
                image_path = Path(cfg['patch_manifest']).parent / 'patch-result.image.bin'
                image_raw = image_path.read_bytes()
                require(isinstance(owner._entry, ctypes._CFuncPtr)
                        and 0 < len(image_raw) <= 1048576
                        and owner._mapping[:len(image_raw)] == image_raw
                        and sha256(image_raw).hexdigest() == owner.image_sha256,
                        'journal is not attached to the actual Patch image')
                address = ctypes.cast(owner._entry, ctypes.c_void_p).value
                mapping = ctypes.addressof(ctypes.c_ubyte.from_buffer(owner._mapping))
                require(address == mapping, 'Patch entry differs from actual image start')
                self.patch_owner = owner
                self.patch_journal = FrameJournal(owner, self.directory / 'machine-patch')
                self.gate = StablePatchEntry(self.patch_journal)
                owner._entry = self.gate
                self.issuance.append({'entry_address': address, 'mapping_address': mapping,
                    'image_path': str(image_path), **pin(image_raw), 'source_binder_calls': 1,
                    'journal_before_independent_record': True})
                return result
            signature = cfg['inspect_manifest'] if cfg['signature_native'] else None
            with patch.object(NativePatchResult, '_bind_manifest_source', bind_actual):
                self.record = observed_admission(NativePatchResult, self.directory / 'patch-admission',
                    records.issue_preselected_patch_record, cfg['patch_manifest'], inspect_manifest=signature)
            require(NativePatchResult._bind_manifest_source is original_bind
                    and original_bind.__code__ is original_code, 'original binder was not restored')
            state = records._state(self.record)
            require(state is not None and state.admission.owner is self.patch_owner
                    and state.entry is self.gate and state.mapping is self.patch_owner._mapping
                    and isinstance(self.patch_journal.original, ctypes._CFuncPtr)
                    and state.current(), 'actual issuer/journal/owner identities differ')
            if cfg['signature_native']:
                require(self.patch_owner._signature is not None
                        and self.patch_owner._signature.admission.owner is self.base.owner
                        and self.patch_owner._signature.entry is self.base.gate,
                        'signature lacks independent real Inspect admission')
            else:
                require(self.patch_owner._signature is None, 'implicit signature admission')
            self.selected = adapter.select_patch_inspect_cli(self.base.selected, self.record)
            require(type(self.selected) is adapter.NativePatchInspectReportCli,
                    'positive control received a foreign/default CLI')
            for name in retained.COMPONENTS:
                attr = 'formatter' if name == 'format' else name
                require(getattr(self.selected, attr) is self.base.owners[name], 'six-image chain substituted')
            self.old_codes = {state.apply.code: 'apply_program_patch', state.interface.code: '_check_patch_interface',
                              **self.base.old_codes}
            publish(self.directory / 'ADMISSION.json', {
                'new_modules': loaded, 'record': records.record_receipt(self.record),
                'eight_real_images': {**self.base.native_origins, 'patch': self.issuance[0]},
                'actual_new_owner_not_assumed_cached': True, 'original_bind_restored': True,
                'outer_complete_source_binding_required': True,
                'current_cold': False, 'default': False, 'whole': False})
        except BaseException:
            failure = traceback.format_exc()
            cleanup_errors = []
            try:
                publish(self.directory / 'SETUP-FAILURE.json', {'traceback': failure,
                    'issuance': self.issuance, 'positive_control': False})
            except BaseException:
                cleanup_errors.append(traceback.format_exc())
            try:
                self.close()
            except BaseException:
                cleanup_errors.append(traceback.format_exc())
            if cleanup_errors:
                try:
                    sys.stderr.write(json.dumps({'op13_setup_failure': failure,
                        'evidence_or_cleanup_failures': cleanup_errors}) + '\n')
                    sys.stderr.flush()
                except BaseException:
                    pass
            # Preserve the actual primary error after attempting both sinks
            # and cleanup. No failed setup can become a successful control.
            raise

    def counts(self):
        result = {} if self.base is None else self.base.counts()
        result['patch'] = 0 if self.patch_journal is None else self.patch_journal.started
        return result

    def tag(self, value):
        if self.base is not None:
            self.base.tag(value)
        if self.patch_journal is not None:
            self.patch_journal.tag = value

    def fixture(self):
        from tests.test_hia_program_tools import scalar_program, add_two_patch
        data = scalar_program()
        return data, add_two_patch(data)

    def patch_files(self, *, v2=False):
        data, request = self.fixture()
        if v2:
            request.update(schema='hepta.hia.patch.v2', interface_policy='preserve')
        suffix = 'v2' if v2 else 'v1'
        source, patch_path, output = (self.directory / (suffix + name)
            for name in ('-source.json', '-patch.json', '-output.json'))
        for path, value in ((source, data), (patch_path, request)):
            if not path.exists():
                with path.open('x') as stream:
                    json.dump(value, stream, ensure_ascii=False)
        return ['patch', str(source), '--request', str(patch_path), '-o', str(output)], output

    def session(self, *, selected=True, owner=None, imports=True):
        chosen = owner if owner is not None else self.selected if selected else self.base.selected
        argv, _ = self.patch_files()
        session = chosen.prepare(argv, self.cli)
        require(session.kind == 0 and session.discovery_permission is None, 'real patch argv refused')
        self.sessions.append(session)
        if imports:
            session._effect(35, 0, 0, 0, 0)
        return session

    def call13(self, session, document, request, *, consume_request=False):
        a, b = session.register(document), session.register(request)
        session.consume_mask = 2 if consume_request else 0
        first, second, zero = session._effect(13, a, b, 0, 0)
        require(zero == 0, 'original op13 return envelope differs')
        return session.value(first), session.value(second)

    def retain_output_and_remove(self, output, label):
        """Keep the actual test-created publication before a same-path oracle.

        The two full CLI runs need identical output arguments. Only this
        context's newly published regular output can be removed, after its
        complete bytes and mode have been preserved and reread. No source or
        machine/evidence input is a deletion target.
        """
        output = Path(output).absolute()
        require(output.parent == self.directory and output.name in
                ('v1-output.json', 'v2-output.json'), 'not this test publication')
        before = output.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                'test output is not a unique regular publication')
        raw = output.read_bytes()
        after = output.lstat()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
        require(tuple(getattr(before, key) for key in fields) ==
                tuple(getattr(after, key) for key in fields) and len(raw) == before.st_size,
                'test output changed during capture')
        target = self.directory / (label + '.output.bin')
        with target.open('xb') as stream:
            stream.write(raw)
        require(target.read_bytes() == raw, 'full output copy differs')
        row = {'output': str(output), 'saved': str(target), 'pin': pin(raw),
               'posix_mode': stat.S_IMODE(before.st_mode),
               'stat': {key: getattr(before, key) for key in fields}}
        publish(self.directory / (label + '.output.json'), row)
        require(tuple(getattr(output.lstat(), key) for key in fields) ==
                tuple(getattr(before, key) for key in fields), 'test output changed before unlink')
        os.unlink(output)
        require(not output.exists() and not output.is_symlink(), 'test output was not removed')
        return raw, row['posix_mode']

    def observe(self, label, call):
        self.tag(label)
        before, old = self.counts(), sys.getprofile()
        require(old is None, 'unexpected preexisting profile hook')
        calls, out, err = [], io.StringIO(), io.StringIO()
        row = {'label': label, 'before_calls': before}
        result = error = None
        def profile(frame, event, argument):
            if event == 'call' and frame.f_code in self.old_codes:
                calls.append(self.old_codes[frame.f_code])
        try:
            sys.setprofile(profile)
            with redirect_stdout(out), redirect_stderr(err):
                try:
                    result = call()
                    row.update(kind='return', value=plain(result))
                except BaseException as caught:
                    error = caught
                    row.update(kind='exception', error=exception_value(caught),
                               traceback=''.join(traceback.format_exception(caught)))
        finally:
            sys.setprofile(old)
            row.update(stdout=out.getvalue(), stderr=err.getvalue(), old_policy_calls=calls,
                       after_calls=self.counts())
            row['call_delta'] = {name: row['after_calls'][name] - before[name] for name in before}
            self.rows.append(row)
            publish(self.directory / ('OBSERVATION-%04d.json' % len(self.rows)), row)
        return row, result, error

    def close(self):
        require(not self.closed, 'op13 context closed twice')
        self.closed = True
        errors = []
        if self.patch_journal is not None:
            try:
                # Detach observation only. Never advance/retire/ACK a frame.
                if self.patch_owner._entry is self.gate:
                    self.patch_owner._entry = self.patch_journal.entry
                self.patch_journal.close()
            except BaseException:
                errors.append(traceback.format_exc())
            for row in self.patch_journal.rows:
                for name in FRAME_KEYS:
                    try:
                        # Every actual reference is read/decompressed anew.
                        self.patch_journal.buffers.get(row[name])
                    except BaseException:
                        errors.append(traceback.format_exc())
        if self.base is not None:
            try:
                self.base.close()
            except BaseException:
                errors.append(traceback.format_exc())
            # Retain the original close call, then independently attempt all
            # original six spans even if one of its publications failed.
            for journal in self.base.journals.values():
                for row in journal.rows:
                    for name in FRAME_KEYS:
                        try:
                            journal.buffers.get(row[name])
                        except BaseException:
                            errors.append(traceback.format_exc())
        publish(self.directory / 'FINAL.json', {'observations': self.rows, 'actual_counts': self.counts(),
            'fault_losses': [] if self.gate is None else self.gate.losses, 'cleanup_errors': errors,
            'all_buffer_references_fully_read': not errors,
            'quarantine_preserved_until_owned_child_exit': True,
            'current_cold': False, 'default': False, 'whole': False})
        require(not errors, 'complete op13 evidence cleanup/readback failed')
