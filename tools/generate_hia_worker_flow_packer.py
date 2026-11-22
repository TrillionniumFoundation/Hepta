"""Author the HIA ELF packer for the source-visible Worker syscall adapter."""

from pathlib import Path
import re
from tempfile import TemporaryDirectory

from hepta.hia_agent_assembly import render_assembly
from tools.build_hia_agent_batch_commit import adapter_layout
from tools.generate_hia_native_filter import bind_adapter, document, elf_header

FLOW = 'tools/hia_worker_flow_syscalls.S'
PORTS = 'tools/hia_worker_descriptor_ports.S'
PEERS = 'tools/hia_worker_peer_ports.S'
PACKER = 'examples/hia_bootstrap/worker_describe_flow_packer.hepta'
POLICY = 'examples/hia_bootstrap/worker_describe_flow.hepta'
READ_PACKER = 'examples/hia_bootstrap/worker_read_flow_packer.hepta'
READ_POLICY = 'examples/hia_bootstrap/worker_read_flow.hepta'
COST_PACKER = 'examples/hia_bootstrap/worker_cost_flow_packer.hepta'
COST_POLICY = 'examples/hia_bootstrap/worker_cost_flow.hepta'
READ_STORE_PACKER = 'examples/hia_bootstrap/worker_read_store_flow_packer.hepta'
READ_STORE_POLICY = 'examples/hia_bootstrap/worker_read_store_flow.hepta'
PROGRAMS = {
    'describe': (POLICY, PACKER), 'read': (READ_POLICY, READ_PACKER),
    'cost': (COST_POLICY, COST_PACKER), 'read-store': (READ_STORE_POLICY, READ_STORE_PACKER),
}
PEER_KINDS = ('cost', 'read-store')
MAGIC = int.from_bytes(b'HIADPK01', 'little')


def adapter_source(flow, ports, *, kind='describe', peers=b''):
    # Local references let the existing flat-template builder prove that
    # every syscall adapter relocation is already resolved. The sole HIA
    # application call deliberately remains a zero rel32 hole.
    flow = flow.replace(b'call hia_worker_', b'call .Lhia_worker_')
    if peers:
        ports += b'\n.text\n' + peers
    ports = ports.replace(b'call hia_worker_', b'call .Lhia_worker_')
    ports = re.sub(br'(?m)^\.section \.note\.GNU-stack[^\n]*$', b'.text', ports)
    ports = re.sub(br'^(hia_worker_[a-z_]+):$', br'\1:\n.L\1:', ports, flags=re.MULTILINE)
    ports = ports.replace(b'.section .rodata', b'.text')
    variant = {
        'describe': b'', 'read': b'.equ WORKER_READ, 1\n', 'cost': b'.equ WORKER_COST, 1\n',
        'read-store': b'.equ WORKER_COST, 1\n.equ WORKER_STORED_READ, 1\n',
    }[kind]
    return variant + flow + b'\n' + ports


def source_packer(flow, ports, packer_path, *, kind, peers):
    source = adapter_source(flow, ports, kind=kind, peers=peers)
    with TemporaryDirectory(prefix='hia-worker-flow-adapter-') as temporary:
        stub, locations, _ = adapter_layout(Path(temporary), 'worker_flow.S', source,
                                            {'policy': 'worker_policy_hole'})
    hole = locations['policy']
    header = elf_header()
    packer = document(magic=MAGIC, module=Path(packer_path).stem,
                      image_template=(header + stub, (len(header) + hole,)))
    return bind_adapter(packer, source, stub, (hole,))


if __name__ == '__main__':
    sources = Path(FLOW).read_bytes(), Path(PORTS).read_bytes()
    for kind, (_, path) in PROGRAMS.items():
        peers = Path(PEERS).read_bytes() if kind in PEER_KINDS else b''
        packer = source_packer(*sources, path, kind=kind, peers=peers)
        Path(path).write_text(render_assembly(packer), encoding='utf-8')
