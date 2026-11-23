"""Exercise the ordinary installed HIA graph projector, executor and owned process."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from tests.test_hia_agent_buffer_lifecycle import trap_program
from tests.test_hia_program import resource_program
from tests.test_hia_program_native import scalar_document

INSTALLED = os.environ.get('HEPTA_HIA_TEST_INSTALLED_GRAPH_SITE')

PROBE = r"""
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
import fcntl
import json
import os
import sys

site = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(site))
from hepta import hia_default_native as defaults, hia_program_runtime as vm
from hepta import hia_scalar_reference_wire as wire
from hepta.hia_agent_buffers import reference_observation
from hepta.hia_evaluate_reference_wire_native import NativeEvaluateReferenceWire
from hepta.hia_scalar_reference_native import NativeScalarReference, _StandaloneReference

assert Path(vm.__file__).resolve().is_relative_to(site)
scalar, owned, external = json.loads(Path(sys.argv[2]).read_bytes())
mode = sys.argv[3]

def observations():
    rows = []
    for document, fn, args, options in (
            (scalar, 'edge_swap', [13, 27, 11], {}),
            (scalar, 'edge_swap', [13, 27, 11], {'max_steps': 3}),
            (scalar, 'explicit_trap', [], {}),
            (owned, 'owned', [4, 255], {}),
            (owned, 'owned', [4, 201], {'max_heap_bytes': 3}),
            (owned, 'owned', [4, 201], {'allocation_fail_at': 1})):
        try:
            result = vm.execute_program(document, fn, args, **options)
        except (vm.HIAProgramTrap, vm.HIAProgramBudgetExceeded) as error:
            result = error.report
        rows.append(result)
    rows.append(reference_observation(external,
        {'function': 'write_then_trap', 'arguments': [{'bytes_hex': '102030'}]},
        (('write_then_trap', 3),), steps=100000, heap=0))
    return rows

def forbidden(*args, **kwargs):
    raise AssertionError('ordinary installed VM left its source-bound execution path')

if mode == 'portable':
    rows = observations()
elif mode == 'native':
    package = site / 'hepta'
    projector = defaults.default_reference_graph()
    integer = defaults.default_integer_image()
    manifest = projector._default_package_binding.selections[defaults.GRAPH_OWNER[0]]
    expected_projector = json.loads(Path(manifest).read_bytes())['image_sha256']
    expected_owned = sha256((package / defaults.OWNED_VM_RESOURCE).read_bytes()).hexdigest()
    counts = dict(project=0, graph=0, owned=0)
    project = NativeEvaluateReferenceWire.project
    execute = NativeScalarReference._projected_program
    invoke = _StandaloneReference.run
    def observe_project(self, *args, **kwargs):
        assert self._default_package_binding and self.image_sha256 == expected_projector
        counts['project'] += 1
        return project(self, *args, **kwargs)
    def observe_execute(self, *args, **kwargs):
        assert self._default_package_binding and self.image_sha256 == integer.image_sha256
        counts['graph'] += 1
        return execute(self, *args, **kwargs)
    def observe_owned(self, request):
        assert fcntl.fcntl(self.fd, fcntl.F_GET_SEALS) & 15 == 15
        assert sha256(os.pread(self.fd, os.fstat(self.fd).st_size, 0)).hexdigest() == self.digest == expected_owned
        counts['owned'] += 1
        return invoke(self, request)
    with ExitStack() as scope:
        scope.enter_context(patch.object(vm._Machine, 'invoke', forbidden))
        scope.enter_context(patch.object(wire, 'program_wire', forbidden))
        scope.enter_context(patch.object(vm._ReferenceResources, '__init__', forbidden))
        scope.enter_context(patch.object(NativeEvaluateReferenceWire, 'project', observe_project))
        scope.enter_context(patch.object(NativeScalarReference, '_projected_program', observe_execute))
        scope.enter_context(patch.object(_StandaloneReference, 'run', observe_owned))
        rows = observations()
    assert counts == {'project': 7, 'graph': 7, 'owned': 4}, counts

    checked = vm.verify_program(external)
    machine = vm._Machine(checked, 100, 0, None, 20)
    root = vm._Owner(-1, bytearray(wire.MAX_PACKET_BYTES))
    borrowed = vm._View(root, True)
    # A legitimate external view can exceed the qualified pipe capacity; its
    # admitted graph still executes, borrowing the existing physical storage.
    short, external_views = integer._owned_arguments(('mutbuf',), (borrowed,), machine, wire.MAX_PACKET_BYTES)
    assert short is None and external_views[0][0] is root.data
    with patch.object(vm._Machine, 'invoke', forbidden), patch.object(_StandaloneReference, 'run', forbidden):
        try:
            machine.execute(machine.functions['write_then_trap'], [borrowed])
        except vm.HIAProgramTrap as error:
            assert error.code == 'bounds' and root.data[0] == 91 and root.data[-1] == 0
        else:
            raise AssertionError('external trap and its preceding write were lost')
else:
    package = site / 'hepta'
    resources = [package / defaults.GRAPH_BUNDLE_RESOURCE, package / defaults.OWNED_VM_RESOURCE]
    leaf = resources[0].parent / 'evaluate-reference-wire'
    manifest = leaf / 'manifest.json'
    resources.extend((manifest, leaf / json.loads(manifest.read_bytes())['image_path']))
    def replace(path, data):
        pending = path.with_name(path.name + '.pending')
        pending.write_bytes(data)
        pending.replace(path)
    for member in resources:
        source = member.read_bytes()
        changed = source[:-1] + bytes([source[-1] ^ 1])
        for during in (False, True):
            def after_project(self, *args, **kwargs):
                result = original(self, *args, **kwargs)
                replace(member, changed)
                return result
            original = NativeEvaluateReferenceWire.project
            try:
                with ExitStack() as stack:
                    stack.enter_context(patch.object(vm._Machine, 'invoke', forbidden))
                    if during:
                        stack.enter_context(patch.object(NativeEvaluateReferenceWire, 'project', after_project))
                    else:
                        replace(member, changed)
                    try:
                        vm.execute_program(scalar, 'edge_swap', [1, 2, 3])
                    except ValueError:
                        pass
                    else:
                        raise AssertionError('changed graph input accepted: ' + str(member))
            finally:
                replace(member, source)
    rows = observations()
print(json.dumps(rows))
"""


@unittest.skipUnless(INSTALLED, 'requires a pip-installed matching-source native wheel')
class InstalledGraphTests(unittest.TestCase):
    def test_complete_programs_borrowed_effects_and_physical_graph_owners(self):
        with TemporaryDirectory() as temp:
            work = Path(temp)
            inputs = work / 'programs.json'
            inputs.write_text(json.dumps((scalar_document(), resource_program(), trap_program())))
            # Members are replaced atomically only in this isolated copy.
            private = work / 'installed'
            shutil.copytree(INSTALLED, private)
            outputs = []
            for mode, site in (('portable', Path(__file__).resolve().parents[1]),
                               ('native', INSTALLED), ('custody', private)):
                result = subprocess.run([sys.executable, '-I', '-B', '-c', PROBE,
                                         str(site), str(inputs), mode], env={'PATH': ''},
                                        cwd=work, capture_output=True, text=True, timeout=120)
                self.assertEqual(result.returncode, 0, result.stderr)
                outputs.append(json.loads(result.stdout))
            self.assertEqual(outputs[0], outputs[1])
            self.assertEqual(outputs[0], outputs[2])
