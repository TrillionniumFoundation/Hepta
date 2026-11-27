"""Execution support for the explicit op10 domain; importing does not map images.

Only the separately frozen executor may call configure/ActualComponents.
FrameJournal is the unchanged original actual-machine observer.
"""
from __future__ import annotations

from contextlib import contextmanager, redirect_stderr, redirect_stdout
import ctypes
import gc
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import traceback

from inspect_exec_support import FrameJournal, error_value, pin, publish, require

CONTEXT = None
COMPONENTS = ('control', 'format', 'discovery', 'routing', 'parser_context', 'verified_report')
ADAPTER_FILES = (
    'hepta/hia_inspect_cli_records.py',
    'hepta/hia_inspect_cli_operand.py',
    'hepta/hia_cli_inspect_native.py',
)


def configure(value):
    global CONTEXT
    require(CONTEXT is None and type(value) is dict, 'one exact context per fresh child')
    CONTEXT = value


class LostActualReturn(BaseException):
    pass


class ActualReturnGate:
    """Stable pre-issuance entry: always call the journal's original native path.

    A test may arm one explicit post-return loss. No image, argument, return
    value or frame is fabricated. The callable object itself never changes
    after record issuance. The full after-frame precedes the injected error.
    """
    def __init__(self, journal):
        self.journal = journal
        self.entry = journal.owner._entry
        self.armed = None
        self.losses = []

    def __call__(self, source, source_size, output, output_size, workspace, workspace_size):
        command = struct.unpack('<Q', ctypes.string_at(workspace, 8))[0]
        result = self.entry(source, source_size, output, output_size, workspace, workspace_size)
        if self.armed == 'first-real-claim' and command == 2 and result == 4:
            self.armed = None
            self.losses.append({'frame': self.journal.rows[-1]['index'],
                                'command': command, 'actual_return': result})
            raise LostActualReturn('lost actual inspect claim return')
        return result


def plain(value):
    if type(value) is dict:
        return {'dict': [[plain(k), plain(v)] for k, v in value.items()]}
    if type(value) in (tuple, list):
        return {type(value).__name__: [plain(v) for v in value]}
    if type(value) in (str, int, bool, type(None)):
        return {'type': type(value).__name__, 'value': value}
    raise AssertionError('unobserved result protocol: ' + type(value).__name__)


class ActualComponents:
    def __init__(self, directory):
        require(type(CONTEXT) is dict, 'explicit request required')
        require(sys.version_info[:3] == (3, 14, 4), 'actual 3.14.4 required')
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)
        self.rows, self.journals = [], {}
        self.sessions = []
        self.closed = False
        publish(self.directory / 'SETUP-INTENT.json', {
            'source': CONTEXT['source'], 'report_manifest': CONTEXT['report_manifest'],
            'inspect_manifest': CONTEXT['inspect_manifest'], 'adapter_files': CONTEXT['adapter_files'],
            'setup_native_metadata_precedes_control_journal': True,
            'no_setup_failure_may_be_reported_as_a_positive_control': True})
        from hepta import cli, hia_program_tools, hia_program
        from hepta import hia_cli_inspect_native as adapter
        from hepta import hia_inspect_cli_records as records
        from hepta.hia_cli_verified_report_native import installed_bundle, NativeReportCli
        from hepta.hia_inspect_program_native import admit_inspect_program, NativeInspectProgram
        self.cli, self.tools, self.program = cli, hia_program_tools, hia_program
        self.adapter, self.records = adapter, records
        self.original_effect = adapter._EFFECT
        # All three new modules must really be loaded from the frozen view.
        loaded = {}
        for relative in ADAPTER_FILES:
            name = relative.removesuffix('.py').replace('/', '.')
            module = sys.modules.get(name)
            path = Path(CONTEXT['source']) / relative
            require(module is not None and Path(module.__file__).absolute() == path,
                    'adapter module came from outside actual complete source')
            raw = path.read_bytes()
            require(pin(raw) == CONTEXT['adapter_files'][relative], 'adapter bytes differ')
            loaded[name] = {'path': str(path), **pin(raw)}
        manifest_path = Path(CONTEXT['report_manifest'])
        manifest_raw = manifest_path.read_bytes()
        manifest = json.loads(manifest_raw)
        self.report = installed_bundle(manifest_path, manifest_raw, manifest, strict=True)
        require(type(self.report) is NativeReportCli, 'real strict six-image report owner required')
        admission = admit_inspect_program(CONTEXT['inspect_manifest'])
        require(type(admission.owner) is NativeInspectProgram, 'real Inspect owner required')
        self.admission, self.owner = admission, admission.owner
        self.owners = {name: getattr(self.report, 'formatter' if name == 'format' else name)
                       for name in COMPONENTS}
        self.owners['inspect'] = self.owner
        self.native_origins = {}
        for name, owner in self.owners.items():
            if name == 'inspect':
                image_raw = admission.image_raw
                image_path = Path(CONTEXT['inspect_manifest']).parent / 'inspect-program.image.bin'
            else:
                child = manifest_path.parent / manifest[name + '_manifest']
                metadata = json.loads(child.read_bytes())
                image_path = child.parent / metadata['image_path']
                image_raw = image_path.read_bytes()
            require(0 < len(image_raw) <= 1048576 and isinstance(owner._entry, ctypes._CFuncPtr),
                    'actual raw six-register machine entry required before instrumentation')
            address = ctypes.cast(owner._entry, ctypes.c_void_p).value
            mapping_address = ctypes.addressof(ctypes.c_ubyte.from_buffer(owner._mapping))
            require(address == mapping_address and owner._mapping[:len(image_raw)] == image_raw
                    and hashlib.sha256(image_raw).hexdigest() == owner.image_sha256,
                    'actual entry/mapping/image identity differs')
            self.native_origins[name] = {'image_path': str(image_path), **pin(image_raw),
                'entry_address': address, 'mapping_address': mapping_address,
                'entry_identity': id(owner._entry), 'mapping_identity': id(owner._mapping)}
            self.journals[name] = FrameJournal(owner, self.directory / ('machine-' + name))
        # Issuance must capture this stable wrapper, not a later replacement.
        self.gate = ActualReturnGate(self.journals['inspect'])
        self.owner._entry = self.gate
        self.record = records.issue_preselected_inspect_record(CONTEXT['inspect_manifest'])
        state = records._state(self.record)
        require(state is not None and state.admission.owner is self.owner
                and state.entry is self.gate and state.mapping is self.owner._mapping
                and self.journals['inspect'].original is not self.gate
                and isinstance(self.journals['inspect'].original, ctypes._CFuncPtr)
                and state.current(), 'cache/issuer/current/journal identity is not established')
        self.selected = adapter.select_inspect_report_cli(self.report, self.record)
        require(type(self.selected) is adapter.NativeInspectReportCli,
                'positive selection must not be an original/fallback CLI')
        for name in COMPONENTS:
            attr = 'formatter' if name == 'format' else name
            require(getattr(self.selected, attr) is self.owners[name], 'six-image owner substituted')
        self.old_codes = {state.inspect.code: 'inspect_program', state.signature.code: 'function_signature'}
        self.module = state.module
        publish(self.directory / 'ADMISSION.json', {
            'loaded_adapter_modules': loaded, 'record': records.record_receipt(self.record),
            'native_origins': self.native_origins, 'cache_second_admission_same_owner': True,
            'journal_installed_before_issuance': True,
            'initial_admission_metadata_calls_precede_journal': True,
            'scope': 'explicit development definition domain; not current cold/default/whole'})

    def counts(self):
        return {name: journal.next_index for name, journal in self.journals.items()}

    def tag(self, label):
        for journal in self.journals.values():
            journal.tag = label

    def fixture(self):
        from tests.test_hia_program import m, f, b, c, ret
        return m(f('calculate', [], ['u32'], [], [
            b('entry', [], [c('answer', 'u32', 7)], ret('answer'))]))

    def source_file(self):
        path = self.directory / 'input.core.json'
        if not path.exists():
            path.write_text(json.dumps(self.fixture(), ensure_ascii=False), encoding='utf-8')
        return path

    def session(self, *, selected=True, owner=None):
        chosen = owner if owner is not None else self.selected if selected else self.report
        session = chosen.prepare(['inspect', str(self.source_file())], self.cli)
        require(session.kind == 0 and session.discovery_permission is None,
                'actual valid inspect argument preparation failed')
        self.sessions.append(session)
        return session

    def ports(self, session, *, canonical=True):
        if canonical:
            session._effect(35, 0, 0, 0, 0)
        return session

    def call10(self, session, document):
        handle = session.register(document)
        result, b, c = session._effect(10, handle, 0, 0, 0)
        require((b, c) == (0, 0), 'original op10 return envelope differs')
        return session.value(result)

    def observe(self, label, call):
        self.tag(label)
        before = self.counts()
        policy = []
        old_profile = sys.getprofile()
        require(old_profile is None, 'an explicit profile observer is already installed')
        def profile(frame, event, argument):
            if event == 'call' and frame.f_code in self.old_codes:
                policy.append(self.old_codes[frame.f_code])
        out, err = io.StringIO(), io.StringIO()
        row = {'label': label, 'before_calls': before}
        result = exception = None
        try:
            sys.setprofile(profile)
            with redirect_stdout(out), redirect_stderr(err):
                try:
                    result = call()
                    row.update(kind='return', value=plain(result))
                except BaseException as caught:
                    exception = caught
                    row.update(kind='exception', error=error_value(caught),
                               traceback=''.join(traceback.format_exception(caught)))
        finally:
            sys.setprofile(old_profile)
            row.update(stdout=out.getvalue(), stderr=err.getvalue(), old_policy_calls=policy,
                       after_calls=self.counts())
            row['call_delta'] = {name: row['after_calls'][name] - before[name] for name in before}
            self.rows.append(row)
            publish(self.directory / ('OBSERVATION-%04d.json' % len(self.rows)), row)
        return row, result, exception

    def close(self):
        if self.closed:
            raise AssertionError('control context closed twice')
        self.closed = True
        # No terminal/ACK or quarantine is invented by this observer cleanup.
        for journal in self.journals.values():
            journal.close()
            require(journal.next_index == len(journal.rows), 'actual machine call lacks an after observation')
            for row in journal.rows:
                for span in ('source', 'output', 'workspace'):
                    for side in ('before', 'after'):
                        journal.buffers.get(row[span + '_' + side])
        publish(self.directory / 'CONTROL-OBSERVATIONS.json', {
            'scope': 'explicit same-process private selection', 'observations': self.rows,
            'actual_counts': self.counts(), 'fault_losses': self.gate.losses,
            'complete_frames_read_back': True, 'cold': False, 'default': False, 'whole': False})


def comparable(row):
    return {name: row.get(name) for name in ('kind', 'value', 'error', 'stdout', 'stderr')}


@contextmanager
def changed_attr(target, name, value):
    old = getattr(target, name)
    setattr(target, name, value)
    try:
        yield old
    finally:
        setattr(target, name, old)
