"""Cold-build the Descriptor-only HIA Worker carrier without a host linker."""

from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_source_build import _check_pack_output
from tools.generate_hia_native_filter import read_adapter_binding, verify_adapter
from tools.generate_hia_worker_flow_packer import (
    FLOW, MAGIC, PEERS, PEER_KINDS, PORTS, PROGRAMS, adapter_source,
)
from tools.qualify_hia_selfhost import compile_stage, invoke
from tools.qualify_hia_selfhost_cli import inspect_executable

ROOT = Path(__file__).resolve().parents[1]
DRIVER = 'tools/build_hia_worker_flow.py'
AUTHOR = 'tools/generate_hia_worker_flow_packer.py'


def build(output, compiler, cold_report, *, kind='describe'):
    policy_source, packer_source = PROGRAMS[kind]
    compiler_bytes, report_bytes = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_bytes, report_bytes)
    names = (FLOW, PORTS, packer_source, policy_source, DRIVER, AUTHOR)
    if kind in PEER_KINDS:
        names += (PEERS,)
    sources = {name: (ROOT / name).read_bytes() for name in names}
    source_pins = {name: sha256(raw).hexdigest() for name, raw in sources.items()}
    if any(admitted.get(name) != wanted for name, wanted in source_pins.items()):
        raise ValueError('Worker descriptor flow differs from its exact cold-admitted source')
    adapter = adapter_source(sources[FLOW], sources[PORTS], kind=kind, peers=sources.get(PEERS, b''))
    binding = read_adapter_binding(sources[packer_source], adapter, calls=1)
    output.mkdir(mode=0o700)
    policy, policy_receipt = compile_stage(output, kind + '-policy', compiler, sources[policy_source])
    packer, packer_receipt = compile_stage(output, kind + '-packer', compiler, sources[packer_source])
    policy_bytes, packer_bytes = policy.read_bytes(), packer.read_bytes()
    if (sha256(policy_bytes).hexdigest() != policy_receipt['produced_sha256']
            or sha256(packer_bytes).hexdigest() != packer_receipt['produced_sha256']):
        raise ValueError('Worker descriptor image was changed after native compilation')
    frame = struct.pack('<2Q', MAGIC, len(policy_bytes)) + policy_bytes
    pack_receipt, packed = invoke(output, 'native-' + kind + '-pack', packer, frame)
    executable = _check_pack_output(pack_receipt, packed, artifact=packer_bytes, source=frame)
    verify_adapter(executable, policy_bytes, binding, entries=(0,))
    geometry = inspect_executable(executable)
    if (current_sources() != admitted or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != report_bytes
            or policy.read_bytes() != policy_bytes or packer.read_bytes() != packer_bytes):
        raise ValueError('Worker descriptor flow source or build image changed before publication')
    filename = 'hia-agent-input-carrier' if kind == 'input' else f'hia-agent-{kind}-worker-carrier'
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
    }, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return target
