"""Exercise the native Core verifier through a matching installed package."""
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from tests.hia_core_diagnostic_cases import closure_before_join, opcode_documents, structured_mutations
from tests.test_hia_core_admission_native import VALID
from tests.test_hia_program import resource_program

INSTALLED = os.environ.get('HEPTA_HIA_TEST_INSTALLED_CORE_ADMISSION_SITE')

CHECK = r"""
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

site = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(site))
from hepta import hia_program as core, hia_default_native as default
from hepta.hia_core_admission_native import NativeCoreAdmission, SELECTOR

assert Path(core.__file__).is_relative_to(site)
cases, simple = json.loads(Path(sys.argv[2]).read_bytes())
mode = sys.argv[3]
records, calls = [], []
original = NativeCoreAdmission.admit

def observed(image, raw):
    assert image._default_package_binding
    calls.append(image.image_sha256)
    return original(image, raw)

def forbidden(*args, **kwargs):
    raise AssertionError('the admitted whole-program verifier used a host policy')

def observe(doc):
    try:
        value = core.verify_program(doc)
    except core.HIAProgramRejected as error:
        return [error.code, str(error)]
    return ['accepted', sha256(value.canonical_bytes).hexdigest()]

if mode == 'custody':
    folder = site / 'hepta' / Path(default.ADMISSION_BUNDLE_RESOURCE).parent
    manifest = folder / 'core-admission/manifest.json'
    from hepta.hia_core_admission_native import SOURCE
    members = [folder / 'core-admission-bundle.json', manifest,
               manifest.parent / json.loads(manifest.read_bytes())['image_path'], SOURCE]
    def replace(path, raw):
        pending = path.with_name(path.name + '.pending')
        pending.write_bytes(raw)
        pending.replace(path)
    for path in members:
        data = path.read_bytes()
        changed = data[:-1] + bytes([data[-1] ^ 1])
        for early in (True, False):
            def after_admit(self, raw):
                original(self, raw)
                replace(path, changed)
            try:
                with ExitStack() as scope:
                    scope.enter_context(patch.object(core, '_primitive_structure', forbidden))
                    if early:
                        replace(path, changed)
                    else:
                        scope.enter_context(patch.object(NativeCoreAdmission, 'admit', after_admit))
                    try:
                        core.verify_program(simple)
                    except ValueError:
                        pass
                    else:
                        raise AssertionError('accepted changed source-bound Core verifier: ' + str(path))
            finally:
                replace(path, data)
else:
    with ExitStack() as scope:
        if mode == 'native':
            scope.enter_context(patch.object(NativeCoreAdmission, 'admit', observed))
            for name in ('_primitive_structure', '_reference_function_shape', '_verify_function',
                         'check_instruction', 'rename_capabilities'):
                scope.enter_context(patch.object(core, name, forbidden))
        for doc in cases:
            records.append(observe(doc))
    if mode == 'native':
        assert len(calls) == len(cases) and len(set(calls)) == 1
    # Submission decoding and the public type/diagnostic order precede whole-program policy.
    for bad in (b'\xff', '{"schema":1,"schema":2}', b'{}{}'):
        with patch.object(NativeCoreAdmission, 'admit', forbidden):
            records.append(observe(bad))
    from hepta.hia_capability_renaming_native import SELECTOR as rename
    from hepta.hia_function_shape_native import SELECTOR as function
    from hepta.hia_instruction_policy_native import SELECTOR as instruction
    from hepta.hia_program_shape_native import SELECTOR as declaration
    for selector in (rename, function, instruction, declaration, SELECTOR):
        for value in ('', '/no-selected-core-image'):
            # Empty and missing explicit values have different historical policies.
            with patch.dict(os.environ, {selector: value}):
                try:
                    records.append(observe(simple))
                except (ValueError, OSError) as error:
                    records.append([type(error).__name__, str(error)])
print(json.dumps(records))
"""


@unittest.skipUnless(INSTALLED, 'requires a pip-installed matching-source native wheel')
class InstalledCoreAdmissionTests(unittest.TestCase):
    def test_complete_core_diagnostics_ownership_and_explicit_policies(self):
        programs = [VALID, resource_program(), closure_before_join()]
        programs.extend(doc for index, (_, doc) in enumerate(opcode_documents()) if index % 4 == 0)
        programs.extend(doc for index, (_, doc) in enumerate(structured_mutations(resource_program()))
                        if index % 23 == 0)
        invalid = deepcopy(VALID)
        invalid['functions'][0]['blocks'][0]['term']['values'] = ['missing']
        programs.append(invalid)
        with TemporaryDirectory() as temp:
            folder = Path(temp)
            inputs = folder / 'cases.json'
            inputs.write_text(json.dumps((programs, resource_program())))
            private = folder / 'installed'
            shutil.copytree(INSTALLED, private)
            outputs = []
            for name, site in (('portable', Path(__file__).resolve().parents[1]),
                               ('native', INSTALLED), ('custody', private)):
                command = [sys.executable, '-I', '-B', '-c', CHECK, str(site), str(inputs), name]
                result = subprocess.run(command, cwd=folder, env={'PATH': ''}, capture_output=True,
                                        text=True, timeout=120)
                self.assertEqual(result.returncode, 0, result.stderr)
                outputs.append(json.loads(result.stdout))
            self.assertEqual(outputs[0], outputs[1])
            self.assertEqual(outputs[2], [])
