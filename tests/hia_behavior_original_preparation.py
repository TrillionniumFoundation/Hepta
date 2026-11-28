"""Run the frozen predecessor's unchanged methods in its explicit source view."""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.hia_behavior_source_history import original_view

ROOT = Path(__file__).resolve().parents[1]
_PREPARATION = Path(__file__).resolve()
_IMPORTED_PREPARATION = _PREPARATION.read_bytes()


def _same_preparation():
    if _PREPARATION.read_bytes() != _IMPORTED_PREPARATION:
        raise ValueError('loaded behavior preparation differs from its physical source')


def _run(case, identifier, *, compiler=None):
    _same_preparation()
    # Preserve the original supervisor's 600 s original / 1800 s candidate
    # child limits and its complete process-group cleanup. No replacement
    # per-method timeout is introduced by this source-view preparation.
    evidence = os.environ.get('HEPTA_HIA_SERVICE_VERIFICATION_SOURCE_EVIDENCE')
    parent = None if evidence is None else Path(evidence)
    if parent is not None:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix='behavior-predecessor-', dir=parent))
    env = {key: value for key, value in os.environ.items()
           if not key.startswith('HEPTA_HIA_')}
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    env['HEPTA_HIA_SERVICE_VERIFICATION_SOURCE_EVIDENCE'] = str(output / 'observations')
    if compiler is not None:
        # This intentionally qualifies the predecessor as a development
        # component. It never transfers the current cold source's qualification.
        env['HEPTA_HIA_SERVICE_VERIFICATION_DEVELOPMENT_COMPILER'] = str(compiler)
        env['HEPTA_HIA_SERVICE_VERIFICATION_EVIDENCE'] = str(output / 'historical-native')
    with original_view(ROOT, output / 'source') as (source, report, history):
        command = [sys.executable, '-m', 'unittest', '-v', identifier]
        with (output / 'stdout').open('xb') as stdout, (output / 'stderr').open('xb') as stderr:
            process = subprocess.run(command, cwd=source, env=env, stdout=stdout, stderr=stderr,
                                     timeout=None)
        report['original_method_id'] = identifier
        report['returncode'] = process.returncode
        report['stdout_sha256'] = sha256((output / 'stdout').read_bytes()).hexdigest()
        report['stderr_sha256'] = sha256((output / 'stderr').read_bytes()).hexdigest()
    _same_preparation()
    (output / 'preparation.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    case.assertEqual(process.returncode, 0, (output / 'stderr').read_text()[-16000:])


def bind_original_verification_tests(namespace):
    original = namespace['ServiceVerificationSourceTests']
    methods = {}
    for name in unittest.defaultTestLoader.getTestCaseNames(original):
        identifier = original.__module__ + '.' + original.__name__ + '.' + name
        def invoke(self, identifier=identifier):
            _run(self, identifier)
        invoke.__name__ = name
        methods[name] = invoke
    methods['__module__'] = original.__module__
    methods['__doc__'] = 'Explicit predecessor Source domain; not current graph qualification.'
    namespace['ServiceVerificationSourceTests'] = type(original.__name__, (unittest.TestCase,), methods)
    native = namespace['ServiceVerificationNativeTests']
    name = 'test_01_complete_original_first_base_and_every_declared_fault_native'
    identifier = native.__module__ + '.' + native.__name__ + '.' + name
    def historical_native(self):
        _run(self, identifier, compiler=self.compiler)
    historical_native.__name__ = name
    setattr(native, name, historical_native)


def bind_original_import_tests(namespace):
    """Preserve all three original methods and their complete 308-control domain."""
    original = namespace['ServiceVerificationImportSourceTests']
    methods = {}
    for name in unittest.defaultTestLoader.getTestCaseNames(original):
        identifier = original.__module__ + '.' + original.__name__ + '.' + name
        def invoke(self, identifier=identifier):
            _run(self, identifier)
        invoke.__name__ = name
        methods[name] = invoke
    methods['__module__'] = original.__module__
    methods['__doc__'] = 'Explicit predecessor seven imports; not current eight-capsule qualification.'
    namespace['ServiceVerificationImportSourceTests'] = type(
        original.__name__, (unittest.TestCase,), methods)
