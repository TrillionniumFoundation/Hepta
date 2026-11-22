"""Cold-build the Descriptor-only HIA Worker carrier without a host linker."""

from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_source_build import _check_pack_output
from tools.generate_hia_native_filter import elf_header, read_adapter_binding, verify_adapter
from tools.generate_hia_readonly_worker_capsule import NATIVE_SOURCE
from tools.generate_hia_worker_flow_packer import (
    EMIT_PACK_LIMIT, FLOW, LAUNCHER, LAUNCHER_KIND, LAUNCHER_PACKER,
    MAGIC, PEERS, PEER_KINDS, PORTS, PROGRAMS, SECTIONS,
    adapter_source,
)
from tools.qualify_hia_selfhost import compile_stage, invoke
from tools.qualify_hia_selfhost_cli import inspect_executable

ROOT = Path(__file__).resolve().parents[1]
DRIVER = 'tools/build_hia_worker_flow.py'
AUTHOR = 'tools/generate_hia_worker_flow_packer.py'


def _adapter_binding(sources, kind, packer_source):
    adapter = adapter_source(sources[FLOW], sources[PORTS], kind=kind,
                             peers=sources.get(PEERS, b''), launcher=sources.get(LAUNCHER, b''))
    calls = 3 if kind in SECTIONS else 2 if kind == LAUNCHER_KIND else 1
    return read_adapter_binding(sources[packer_source], adapter, calls=calls)


def launcher_authority(binary):
    """Recover the separately compiled authority entry from the checked ELF."""
    sources = {name: (ROOT / name).read_bytes() for name in (FLOW, PORTS, PEERS, LAUNCHER, LAUNCHER_PACKER)}
    binding = _adapter_binding(sources, LAUNCHER_KIND, LAUNCHER_PACKER)
    header = len(elf_header())
    _, size, (_, authority_call) = binding
    hole = header + authority_call
    displacement, = struct.unpack_from('<i', binary, hole)
    start = hole + 4 + displacement
    end = header + size
    if not end < start < len(binary) <= 1 << 20:
        raise ValueError('installed Worker authority outside its checked ELF')
    verify_adapter(binary, binary[end:], binding, entries=(0, start - end))
    return binary[start:]


def build(output, compiler, cold_report, *, kind='describe'):
    policy_source, packer_source = PROGRAMS[kind]
    compiler_bytes, report_bytes = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_bytes, report_bytes)
    names = (FLOW, PORTS, packer_source, policy_source, DRIVER, AUTHOR)
    if kind in PEER_KINDS:
        names += (PEERS,)
    if kind == LAUNCHER_KIND:
        names += (LAUNCHER, NATIVE_SOURCE)
    names += SECTIONS.get(kind, ())
    sources = {name: (ROOT / name).read_bytes() for name in names}
    source_pins = {name: sha256(raw).hexdigest() for name, raw in sources.items()}
    if any(admitted.get(name) != wanted for name, wanted in source_pins.items()):
        raise ValueError('Worker descriptor flow differs from its exact cold-admitted source')
    binding = _adapter_binding(sources, kind, packer_source)
    output.mkdir(mode=0o700)
    policy, policy_receipt = compile_stage(output, kind + '-policy', compiler, sources[policy_source])
    packer, packer_receipt = compile_stage(output, kind + '-packer', compiler, sources[packer_source])
    compiled = [(policy, policy_receipt), (packer, packer_receipt)]
    if kind == LAUNCHER_KIND:
        compiled.append(compile_stage(output, 'native-capsule-authority', compiler, sources[NATIVE_SOURCE]))
    if kind in SECTIONS:
        compiled.extend(compile_stage(output, Path(path).stem, compiler, sources[path])
                        for path in SECTIONS[kind])
    images = {path: path.read_bytes() for path, _ in compiled}
    if any(sha256(images[path]).hexdigest() != receipt['produced_sha256'] for path, receipt in compiled):
        raise ValueError('Worker descriptor image was changed after native compilation')
    code, packer_bytes = images[policy], images[packer]
    entries = (0,)
    authority_metadata = {}
    if kind == LAUNCHER_KIND:
        authority, receipt = compiled[-1]
        authority_bytes = images[authority]
        frame = struct.pack('<3Q', MAGIC, len(code), len(authority_bytes)) + code + authority_bytes
        entries += (len(code),)
        code += authority_bytes
        authority_metadata['authority_compilation'] = receipt
    elif kind in SECTIONS:
        (product, product_receipt), (proof, proof_receipt) = compiled[-2:]
        product_bytes, proof_bytes = images[product], images[proof]
        frame = struct.pack('<4Q', MAGIC, len(code), len(product_bytes), len(proof_bytes))
        frame += code + product_bytes + proof_bytes
        entries += (len(code), len(code) + len(product_bytes))
        code += product_bytes + proof_bytes
        authority_metadata.update(product_compilation=product_receipt, proof_compilation=proof_receipt)
    else:
        frame = struct.pack('<2Q', MAGIC, len(code)) + code
    capacity = EMIT_PACK_LIMIT if kind in SECTIONS else 1 << 20
    pack_receipt, packed = invoke(output, 'native-' + kind + '-pack', packer, frame,
                                  capacity=capacity, worker_section_pack=kind in SECTIONS)
    executable = _check_pack_output(pack_receipt, packed, artifact=packer_bytes,
                                    source=frame, capacity=capacity)
    verify_adapter(executable, code, binding, entries=entries)
    geometry = inspect_executable(executable)
    if (current_sources() != admitted or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != report_bytes
            or any(path.read_bytes() != raw for path, raw in images.items())):
        raise ValueError('Worker descriptor flow source or build image changed before publication')
    suffix = '' if kind in ('input', 'discovery', 'discovery-bootstrap') else '-worker'
    filename = 'hia-agent-native-launcher' if kind == LAUNCHER_KIND else f'hia-agent-{kind}{suffix}-carrier'
    target = output / filename
    with target.open('xb') as stream:
        stream.write(executable)
    target.chmod(0o500)
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.agent-' + kind + '-worker-carrier-stdio-build.v2',
        'source_sha256': source_pins,
        'platform_sha256': binding[0].hex(),
        'executable_sha256': sha256(executable).hexdigest(),
        'policy_compilation': policy_receipt, 'packer_compilation': packer_receipt,
        'native_pack_receipt': pack_receipt, 'elf': geometry,
        **authority_metadata,
    }, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return target
