"""Cold-build the installed Read carrier from its four HIA entry images."""

from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.build_hia_agent_batch_commit import verify_placement
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_source_build import _check_pack_output
from tools.build_hia_worker_flow import build as build_flow
from tools.generate_hia_native_filter import elf_header, read_adapter_binding
from tools.generate_hia_worker_read_release import ADAPTER, ENTRIES, MAGIC, SOURCE
from tools.qualify_hia_selfhost import compile_stage, invoke
from tools.qualify_hia_selfhost_cli import inspect_executable

ROOT = Path(__file__).resolve().parents[1]
DRIVER = 'tools/build_hia_worker_read_release.py'
AUTHOR = 'tools/generate_hia_worker_read_release.py'


def build(output, compiler, cold_report):
    seed, report = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(seed, report)
    sources = {path: (ROOT / path).read_bytes() for path in (DRIVER, AUTHOR, ADAPTER, SOURCE)}
    pins = {path: sha256(raw).hexdigest() for path, raw in sources.items()}
    if any(admitted.get(path) != pin for path, pin in pins.items()):
        raise ValueError('Read carrier release differs from the cold-admitted sources')
    binding = read_adapter_binding(sources[SOURCE], sources[ADAPTER], calls=len(ENTRIES))
    output.mkdir(mode=0o700)
    members = {role: build_flow(output / role, compiler, cold_report, kind=role) for role in ENTRIES}
    snapshots = {role: member.read_bytes() for role, member in members.items()}
    reports = {role: json.loads(member.with_name('build.json').read_bytes()) for role, member in members.items()}
    header_extent = len(elf_header())
    parts = {}
    for role, raw in snapshots.items():
        facts = inspect_executable(raw)
        if (facts['entry'] != 0x400000 + header_extent or facts['dynamic_loader']
                or facts['sha256'] != reports[role]['executable_sha256']):
            raise ValueError('Read carrier entry differs from the independently cold-built native role')
        parts[role] = raw[header_extent:]
    frame = MAGIC + struct.pack(f'<{len(parts)}Q', *(len(raw) for raw in parts.values())) + b''.join(parts.values())
    image, compile_receipt = compile_stage(output, 'read-release-packer', compiler, sources[SOURCE])
    packer = image.read_bytes()
    if sha256(packer).hexdigest() != compile_receipt['produced_sha256']:
        raise ValueError('Read release packer changed after native compilation')
    receipt, raw_output = invoke(output, 'native-read-release-link', image, frame)
    executable = _check_pack_output(receipt, raw_output, artifact=packer, source=frame)
    verify_placement(executable, binding, parts, instructions=(b'\xe9',) * len(ENTRIES))
    if (current_sources() != admitted or compiler.read_bytes() != seed or cold_report.read_bytes() != report
            or image.read_bytes() != packer
            or any(path.read_bytes() != snapshots[role] for role, path in members.items())):
        raise ValueError('Read release source or native role changed before publication')
    target = output / 'hia-agent-read-carrier'
    with target.open('xb') as stream:
        stream.write(executable)
    target.chmod(0o500)
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.agent-read-carrier-stdio-build.v2',
        'source_sha256': pins,
        'executable_sha256': sha256(executable).hexdigest(),
        'members': {role: reports[role]['executable_sha256'] for role in ENTRIES},
        'packer_compilation': compile_receipt, 'native_link': receipt, 'elf': inspect_executable(executable),
    }, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return target
