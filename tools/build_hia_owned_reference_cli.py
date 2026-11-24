"""Cold-build the standalone Linux x86-64 HIA owned-buffer reference executor."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.generate_hia_native_filter import elf_header, read_adapter_binding, verify_adapter
from tools.generate_hia_owned_reference import (
    ADAPTER_PATH, PACKER_MAGIC, PACKER_PATH, ROOT, RUN_FUNCTION, SOURCE_PATH,
)
from tools.generate_hia_selfhost import CALL_BUDGET, FBASE, FSTRIDE
from tools.hia_selfhost_limits import MAX_CALL_DEPTH, MAX_CALL_STACK_BYTES
from tools.qualify_hia_selfhost import compile_stage, release_compiler_calls
from tools.qualify_hia_selfhost_cli import inspect_executable

DRIVER = 'tools/build_hia_owned_reference_cli.py'
RUN_RECORD = FBASE + FSTRIDE * RUN_FUNCTION
# Observe the original native compiler's directory, signature and frame size.
# The private entry takes one read buffer followed by six mutable buffers.
RUN_PARAMETER_TYPES = (6, 7, 7, 7, 7, 7, 7)
RUN_RECORD_OFFSETS = (
    240, 1024, RUN_RECORD, RUN_RECORD + 24, RUN_RECORD + 32, RUN_RECORD + 40,
    *(RUN_RECORD + 48 + index * 8 for index in range(len(RUN_PARAMETER_TYPES))),
    RUN_RECORD + 184, RUN_RECORD + 264,
)


def verify_owned_entry(image, workspace):
    """Admit the complete v95 guard at the observed function-table entry.

    The compiler records the guard before stack probes and before any callee
    effect. Never relocate the private call to the later bare rbp prologue.
    Both guard immediates derive from the observed frame record, using the
    compiler's packed depth/stack ABI and its unchanged public limits.
    """
    refusal = 'native compiler did not emit the expected owned reference entry'
    if type(image) is not bytes or type(workspace) is not dict:
        raise ValueError(refusal)
    words = {offset: workspace.get(str(offset)) for offset in RUN_RECORD_OFFSETS}
    if any(type(word) is not int or not 0 <= word < 1 << 64 for word in words.values()):
        raise ValueError(refusal)
    entry, variables = words[RUN_RECORD], words[RUN_RECORD + 40]
    if (not 0 < words[240] <= entry < len(image)
            or not RUN_FUNCTION < words[1024] <= 128
            or words[RUN_RECORD + 24] != len(RUN_PARAMETER_TYPES)
            or words[RUN_RECORD + 32] != 3
            or words[RUN_RECORD + 184] != 1
            or words[RUN_RECORD + 264] != 0
            or tuple(words[RUN_RECORD + 48 + index * 8]
                     for index in range(len(RUN_PARAMETER_TYPES))) != RUN_PARAMETER_TYPES
            or not len(RUN_PARAMETER_TYPES) <= variables <= 2048):
        raise ValueError(refusal)
    frame_bytes = (variables + 2) * 16 + 640
    frame_charge = ((frame_bytes + 16) << 9) | 1
    if (CALL_BUDGET != (MAX_CALL_STACK_BYTES << 9) | MAX_CALL_DEPTH
            or not 1 <= MAX_CALL_DEPTH < 512
            or not 0 < frame_bytes + 16 <= MAX_CALL_STACK_BYTES
            or not 0 < frame_charge <= 0xffffffff):
        raise ValueError(refusal)
    immediate = struct.pack('<I', frame_charge)
    # test edx,511; jz UD2; cmp rdx,charge; jae past UD2; sub rdx,charge.
    expected = (bytes.fromhex('f7c2ff01000074094881fa') + immediate
                + bytes.fromhex('73020f0b4881ea') + immediate
                + bytes.fromhex('554889e5'))
    remaining = frame_bytes
    while remaining:
        amount = min(remaining, 4096)
        expected += bytes.fromhex('4881ec') + struct.pack('<I', amount) + bytes.fromhex('488b0424')
        remaining -= amount
    # Preserve the remaining packed budget at rbp-16, then the result pointer.
    expected += bytes.fromhex('488955f0488975f8')
    if image[entry:entry + len(expected)] != expected:
        raise ValueError(refusal)
    return entry, {
        'schema': 'hepta.hia.owned-reference-private-entry.v95',
        'function_index': RUN_FUNCTION, 'function_record_offset': RUN_RECORD,
        'parameter_types': list(RUN_PARAMETER_TYPES), 'frame_variables': variables,
        'frame_bytes': frame_bytes, 'packed_frame_charge': frame_charge,
        'packed_call_budget': CALL_BUDGET, 'checked_entry_bytes': len(expected),
        'checked_entry_sha256': digest(expected),
    }


def verify_owned_call_budget(binary, binding):
    """Require the syscall adapter to initialize the exact private ABI budget."""
    private_call = len(elf_header()) + binding[2][1]
    expected = b'\xba' + struct.pack('<I', CALL_BUDGET) + b'\xe8'
    if (type(binary) is not bytes or not 6 <= private_call <= len(binary) - 4
            or binary[private_call - 6:private_call] != expected):
        raise ValueError('owned reference adapter private call budget differs')


def digest(raw):
    return sha256(raw).hexdigest()


def assemble(output, compiler, sources, binding):
    """Execute the admitted compiler and packer; independently verify placement."""
    image, image_receipt = compile_stage(output, 'owned-reference', compiler, sources[SOURCE_PATH],
                                        compiler_function_offsets=RUN_RECORD_OFFSETS)
    packer, packer_receipt = compile_stage(output, 'owned-reference-packer', compiler, sources[PACKER_PATH])
    image_bytes, packer_bytes = image.read_bytes(), packer.read_bytes()
    for raw, receipt in ((image_bytes, image_receipt), (packer_bytes, packer_receipt)):
        if digest(raw) != receipt['produced_sha256']:
            raise ValueError('compiled HIA owned reference input changed')
    entry, entry_receipt = verify_owned_entry(image_bytes, image_receipt['workspace_header'])
    payload = struct.pack('<3Q', PACKER_MAGIC, len(image_bytes), entry) + image_bytes
    exe, receipt = compile_stage(output, 'owned-reference-executable', packer, payload, output_extension='.elf')
    binary = exe.read_bytes()
    if digest(binary) != receipt['produced_sha256']:
        raise ValueError('compiled HIA owned reference executable changed')
    inspected = inspect_executable(binary)
    verify_adapter(binary, image_bytes, binding, entries=(0, entry))
    verify_owned_call_budget(binary, binding)
    if image.read_bytes() != image_bytes or packer.read_bytes() != packer_bytes or exe.read_bytes() != binary:
        raise ValueError('native packer altered the verified owned reference transport or image')
    return binary, {'executable': inspected, 'transport_adapter_sha256': binding[0].hex(),
                    'transport_assembled_during_build': False,
                    'private_entry_offset': entry, 'private_entry': entry_receipt,
                    'native_compile_receipt': image_receipt,
                    'native_packer_receipt': packer_receipt, 'native_pack_receipt': receipt}


def build(output, compiler, cold_report):
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_bytes, cold_bytes)
    paths = (SOURCE_PATH, ADAPTER_PATH, PACKER_PATH, DRIVER, 'tools/generate_hia_native_filter.py')
    sources = {name: (ROOT / name).read_bytes() for name in paths}
    if any(admitted.get(name) != digest(raw) for name, raw in sources.items()):
        raise ValueError('standalone HIA owned reference needs matching cold source')
    binding = read_adapter_binding(sources[PACKER_PATH], sources[ADAPTER_PATH], calls=2)
    with release_compiler_calls(cold_bytes):
        output.mkdir(mode=0o700)
        binary, report = assemble(output, compiler, sources, binding)
    if (current_sources() != admitted or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != cold_bytes):
        raise ValueError('owned reference inputs changed before publication')
    executable = output / 'hia-owned-reference-wire'
    with executable.open('xb') as stream:
        stream.write(binary)
    executable.chmod(0o500)
    report.update({'schema': 'hepta.hia.owned-reference-wire-build.v1',
                   'source_sha256': {name: digest(raw) for name, raw in sources.items()},
                   'compiler_sha256': digest(compiler_bytes), 'cold_report_sha256': digest(cold_bytes),
                   'executable_path': executable.name, 'executable_sha256': digest(binary)})
    with (output / 'build.json').open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output, args.compiler, args.cold_report))


if __name__ == '__main__':
    main()
