"""Qualification construction of the disposable HIA shared-ELF observer.

Core VM observations precede B0. The fresh compiler then compiles the policy
and packer as ordinary HIA programs; the packer emits the complete executable.
The exact actual policy bytes are independently passed through the VM packer
as well. The fixed bridge retains the system dynamic loader and GNU ld payload.
This is a bounded foreign ABI adapter, not a general ELF implementation or a
security sandbox. Seed and specialized allocator controls remain independent.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT/'examples/hia_bootstrap/linked_observer_policy.hiaasm'
PACKER = ROOT/'examples/hia_bootstrap/linked_observer_packer.hiaasm'
SOURCE_PATHS = (POLICY, PACKER, ROOT/'tools/generate_hia_linked_observer.py',
                ROOT/'tools/hia_linked_observer_bridge.S')


def digest(value):
    return sha256(value).hexdigest()


def source_identity():
    return {p.relative_to(ROOT).as_posix(): digest(p.read_bytes()) for p in SOURCE_PATHS}


def _vm(checked, source, output, workspace):
    # Public admission precedes the actual finite Core interpreter. Its scalar
    # return wrapper cannot expose a complete ELF at once; observe the actual
    # three owned buffers, without replacing the program's writes by a hash.
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    owners = [_Owner(i+1, bytearray(raw)) for i, raw in enumerate((source, output, workspace))]
    machine = _Machine(checked, 30_000_000, 4 << 20, None, 128)
    values = machine.invoke(machine.functions['f0'],
                            [_View(owner, i != 0) for i, owner in enumerate(owners)])
    if bytes(owners[0].data) != source:
        raise AssertionError('linked observer VM changed immutable input')
    return values, bytes(owners[1].data), bytes(owners[2].data), machine.steps


def vm_packer(checked, policy):
    from tools.generate_hia_linked_observer import reference_image
    expected = reference_image(policy)
    result, output, workspace, steps = _vm(checked, policy, b'\xa5'*len(expected), b'')
    if result != [len(expected)] or output != expected or workspace:
        raise AssertionError('linked observer VM did not reproduce every actual ELF byte')
    return output, {'input_bytes':len(policy), 'input_sha256':digest(policy),
                    'output_bytes':len(output), 'output_sha256':digest(output),
                    'result':result, 'steps':steps, 'every_output_byte_compared':True}


def independent_reference():
    """Actual policy continuation and complete packer VM controls before B0."""
    from hepta.hia_agent_assembly import assemble_program
    from tools.hia_selfhost_native_observer import frame
    before = source_identity()
    policy = assemble_program(POLICY.read_bytes())
    packer = assemble_program(PACKER.read_bytes())
    packer_cases = []
    for data in (b'\xc3', bytes(range(256))*17):
        _, receipt = vm_packer(packer, data)
        packer_cases.append(receipt)
    workspace, control = bytearray(512), bytes(512)
    struct.pack_into('<Q', workspace, 8, 1)
    request = frame(b'actual ELF bytes are opaque to policy', b'source\x00\xff', 17, 40, 90)
    observations = []

    def step(source, expected, feedback=()):
        nonlocal workspace, control
        for at, value in feedback:
            struct.pack_into('<Q', workspace, at, value)
        result, control, updated, steps = _vm(policy, source, control, bytes(workspace))
        workspace = bytearray(updated)
        if result != [expected]:
            raise AssertionError('linked observer VM continuation differs')
        observations.append({'action':expected, 'output_hex':control.hex(),
                             'workspace_hex':updated.hex(), 'steps':steps})
        return control

    first = step(b'', 1)
    if struct.unpack_from('<8Q', first) != (5242937,10,256<<20,8<<20,16<<20,32,0,0):
        raise AssertionError('linked observer resource limits differ')
    step(request, 2, ((16,0),))
    path = step(request, 3, ((16,0),(24,7),(32,15)))
    if path[64:80] != b'/proc/self/fd/7\x00':
        raise AssertionError('linked observer descriptor path differs')
    symbol = step(request, 4, ((16,0x12340000),))
    if symbol[64:67] != b'f0\x00':
        raise AssertionError('linked observer symbol differs')
    step(request, 5, ((16,0),(32,0x12340100)))
    step(request, 6, ((16,0),))
    response = step(request, 7, ((16,0),(24,11),(32,999999990),(40,12),(48,10),(56,0xdeadbeef0000002a)))
    if response[128:152] != b'HIAOBR02'+struct.pack('<QQ',0xdeadbeef0000002a,20):
        raise AssertionError('linked observer result/time framing differs')
    step(request, 8, ((16,0),))
    final = step(request, 0, ((16,0),))
    if struct.unpack_from('<Q',final)[0] != 0:
        raise AssertionError('linked observer completion differs')
    if source_identity() != before:
        raise AssertionError('linked observer source changed during independent VM')
    return {'before_B0':True, 'source_sha256':before,
            'policy_core_sha256':policy.sha256, 'packer_core_sha256':packer.sha256,
            'policy_observations':observations, 'packer_observations':packer_cases,
            'actual_policy_bytes_checked_again_after_native_compilation':True,
            'whole_stack_rewritten_in_hia':False, 'all_input_equivalence_proved':False}


def build(directory, compiler, reference):
    from hepta.hia_agent_assembly import assemble_program
    from tools.qualify_hia_selfhost import compile_stage, invoke
    if not reference.get('before_B0') or reference['source_sha256'] != source_identity():
        raise ValueError('linked observer independent source identity differs')
    directory = Path(directory)
    policy, policy_receipt = compile_stage(directory, 'linked-observer-policy', compiler, POLICY.read_bytes())
    packer, packer_receipt = compile_stage(directory, 'linked-observer-packer', compiler, PACKER.read_bytes())
    actual_policy = policy.read_bytes()
    independent, vm_receipt = vm_packer(assemble_program(PACKER.read_bytes()), actual_policy)
    execution, raw = invoke(directory, 'linked-observer-emit', packer, actual_policy)
    if (execution.get('status') != 'returned' or execution.get('abi_status') != 0
            or execution.get('core_u32') != len(independent) or not execution.get('source_unchanged')
            or raw[:len(independent)] != independent):
        raise AssertionError('linked observer native ELF differs from actual Core VM output')
    if source_identity() != reference['source_sha256']:
        raise AssertionError('linked observer source changed during build')
    emitted = raw[:len(independent)]
    executable = directory/'linked-observer.elf'
    executable.write_bytes(emitted)
    executable.chmod(0o700)
    receipt = {'source_sha256':reference['source_sha256'],
               'compiler_sha256':digest(Path(compiler).read_bytes()),
               'executable_sha256':digest(emitted), 'executable_bytes':len(emitted),
               'policy_sha256':digest(actual_policy), 'native_policy_compilation':policy_receipt,
               'native_packer_compilation':packer_receipt, 'native_emission':execution,
               'independent_reference_before_B0':True, 'actual_policy_vm_packing':vm_receipt,
               'foreign_loader':'system ld-linux-x86-64.so.2, libdl.so.2 and libc.so.6',
               'production_activated':False, 'whole_stack_rewritten_in_hia':False}
    (directory/'linked-observer-build.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
    return executable, receipt
