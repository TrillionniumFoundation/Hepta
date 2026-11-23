"""Author the HIA ELF packer for the source-visible Worker syscall adapter."""

from pathlib import Path
import re
from tempfile import TemporaryDirectory

from hepta.hia_agent_assembly import render_assembly
from tools.build_hia_agent_batch_commit import adapter_layout
from tools.generate_hia_artifact_publication import document as author_policy
from tools.generate_hia_native_filter import bind_adapter, document, elf_header, source_program

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
READ_EXTERNAL_PACKER = 'examples/hia_bootstrap/worker_read_external_flow_packer.hepta'
READ_EXTERNAL_POLICY = 'examples/hia_bootstrap/worker_read_external_flow.hepta'
INPUT_PACKER = 'examples/hia_bootstrap/worker_input_flow_packer.hepta'
INPUT_POLICY = 'examples/hia_bootstrap/worker_input_flow.hepta'
ARTIFACT_PACKER = 'examples/hia_bootstrap/worker_artifact_flow_packer.hepta'
ARTIFACT_POLICY = 'examples/hia_bootstrap/worker_artifact_flow.hepta'
DISCOVERY_PACKER = 'examples/hia_bootstrap/worker_discovery_flow_packer.hepta'
DISCOVERY_POLICY = 'examples/hia_bootstrap/worker_discovery_flow.hepta'
CONTEXT_PACKER = 'examples/hia_bootstrap/worker_context_flow_packer.hepta'
CONTEXT_POLICY = 'examples/hia_bootstrap/worker_context_flow.hepta'
INSPECTION_PACKER = 'examples/hia_bootstrap/worker_inspection_flow_packer.hepta'
INSPECTION_POLICY = 'examples/hia_bootstrap/worker_inspection_flow.hepta'
CANDIDATE_PACKER = 'examples/hia_bootstrap/worker_candidate_flow_packer.hepta'
CANDIDATE_POLICY = 'examples/hia_bootstrap/worker_candidate_flow.hepta'
ROLLBACK_PACKER = 'examples/hia_bootstrap/worker_rollback_flow_packer.hepta'
ROLLBACK_POLICY = 'examples/hia_bootstrap/worker_rollback_flow.hepta'
BOOTSTRAP_PACKER = 'examples/hia_bootstrap/worker_bootstrap_flow_packer.hepta'
BOOTSTRAP_POLICY = 'examples/hia_bootstrap/worker_bootstrap_flow.hepta'
LAUNCHER = 'tools/hia_worker_launcher_ports.S'
LAUNCHER_POLICY = 'examples/hia_bootstrap/worker_launcher_flow.hepta'
LAUNCHER_PACKER = 'examples/hia_bootstrap/worker_launcher_flow_packer.hepta'
LAUNCHER_KIND = 'native-launcher'
DOCUMENT_KIND = 'evaluate-document'
RUN_INPUT_KIND = 'evaluate-run-input'
RUN_INPUT_POLICY = 'examples/hia_bootstrap/worker_evaluate_run_input_flow.hepta'
CLAIM_KIND = 'evaluate-claim'
CLAIM_POLICY = 'examples/hia_bootstrap/worker_evaluate_claim_flow.hepta'
INTAKE_KIND = 'evaluate-intake'
INTAKE_LAUNCHER_KIND = 'evaluate-intake-launcher'
INTAKE_LAUNCHER_POLICY = 'examples/hia_bootstrap/worker_evaluate_intake_launcher.hepta'
INTAKE_POLICY = 'examples/hia_bootstrap/worker_evaluate_intake_flow.hepta'
INTAKE_PACKER = 'examples/hia_bootstrap/worker_evaluate_intake_flow_packer.hepta'
REPLAY_KIND = 'evaluate-replay'
REPLAY_LAUNCHER_KIND = 'evaluate-replay-launcher'
REPLAY_LAUNCHER_POLICY = 'examples/hia_bootstrap/worker_evaluate_replay_launcher.hepta'
LAUNCHER_KINDS = (LAUNCHER_KIND, REPLAY_LAUNCHER_KIND, INTAKE_LAUNCHER_KIND)
REPLAY_POLICY = 'examples/hia_bootstrap/worker_evaluate_replay_flow.hepta'
REPLAY_PACKER = 'examples/hia_bootstrap/worker_evaluate_replay_flow_packer.hepta'
EMIT_KIND = 'emit'
EMIT_PACK_LIMIT = 2 << 20
EMIT_POLICY = 'examples/hia_bootstrap/worker_emit_flow.hepta'
EMIT_PRODUCT = 'examples/hia_bootstrap/worker_emit_product_flow.hepta'
EMIT_PROOF = 'examples/hia_bootstrap/worker_emit_proof_flow.hepta'
EMIT_PACKER = 'examples/hia_bootstrap/worker_emit_flow_packer.hepta'
ADOPT_KIND = 'adopt'
ADOPT_POLICY = 'examples/hia_bootstrap/worker_adopt_flow.hepta'
ADOPT_PRODUCT = 'examples/hia_bootstrap/worker_adopt_custody.hepta'
ADOPT_PROOF = 'examples/hia_bootstrap/worker_adopt_proof.hepta'
ADOPT_PACKER = 'examples/hia_bootstrap/worker_adopt_flow_packer.hepta'
PROOF_KIND = 'evaluate-proof'
PROOF_POLICY = 'examples/hia_bootstrap/worker_evaluate_proof_flow.hepta'
PROOF_CUSTODY = 'examples/hia_bootstrap/worker_evaluate_proof_custody.hepta'
PROOF_PACKER = 'examples/hia_bootstrap/worker_evaluate_proof_flow_packer.hepta'
PROOF_REPLAY = 'examples/hia_bootstrap/worker_evaluate_proof_replay.hepta'
VERIFY_KIND = 'verify'
VERIFY_POLICY = 'examples/hia_bootstrap/worker_verify_flow.hepta'
VERIFY_PRODUCT = 'examples/hia_bootstrap/worker_verify_publication_flow.hepta'
VERIFY_PROOF = 'examples/hia_bootstrap/worker_verify_finite_flow.hepta'
VERIFY_PACKER = 'examples/hia_bootstrap/worker_verify_flow_packer.hepta'
SECTIONS = {
    EMIT_KIND: (EMIT_PRODUCT, EMIT_PROOF),
    ADOPT_KIND: (ADOPT_PRODUCT, ADOPT_PROOF),
    PROOF_KIND: (PROOF_CUSTODY, PROOF_REPLAY),
    VERIFY_KIND: (VERIFY_PRODUCT, VERIFY_PROOF),
}
PROGRAMS = {
    'describe': (POLICY, PACKER), 'read': (READ_POLICY, READ_PACKER),
    'cost': (COST_POLICY, COST_PACKER), 'read-store': (READ_STORE_POLICY, READ_STORE_PACKER),
    'read-external': (READ_EXTERNAL_POLICY, READ_EXTERNAL_PACKER),
    'input': (INPUT_POLICY, INPUT_PACKER),
    'artifact': (ARTIFACT_POLICY, ARTIFACT_PACKER),
    REPLAY_KIND: (REPLAY_POLICY, REPLAY_PACKER),
    INTAKE_KIND: (INTAKE_POLICY, INTAKE_PACKER),
    DOCUMENT_KIND: ('examples/hia_bootstrap/worker_evaluate_document_flow.hepta',
                    'examples/hia_bootstrap/worker_evaluate_document_flow_packer.hepta'),
    CLAIM_KIND: (CLAIM_POLICY, INTAKE_PACKER),
    RUN_INPUT_KIND: (RUN_INPUT_POLICY, INTAKE_PACKER),
    'discovery': (DISCOVERY_POLICY, DISCOVERY_PACKER),
    'context': (CONTEXT_POLICY, CONTEXT_PACKER),
    'inspection': (INSPECTION_POLICY, INSPECTION_PACKER),
    'candidate': (CANDIDATE_POLICY, CANDIDATE_PACKER),
    'rollback': (ROLLBACK_POLICY, ROLLBACK_PACKER),
    EMIT_KIND: (EMIT_POLICY, EMIT_PACKER),
    ADOPT_KIND: (ADOPT_POLICY, ADOPT_PACKER),
    PROOF_KIND: (PROOF_POLICY, PROOF_PACKER),
    VERIFY_KIND: (VERIFY_POLICY, VERIFY_PACKER),
    'discovery-bootstrap': (BOOTSTRAP_POLICY, BOOTSTRAP_PACKER),
    LAUNCHER_KIND: (LAUNCHER_POLICY, LAUNCHER_PACKER),
    REPLAY_LAUNCHER_KIND: (REPLAY_LAUNCHER_POLICY, LAUNCHER_PACKER),
    INTAKE_LAUNCHER_KIND: (INTAKE_LAUNCHER_POLICY, LAUNCHER_PACKER),
}
PEER_KINDS = ('cost', 'read-store', 'read-external', 'input', 'artifact', 'discovery', 'context',
              'inspection', 'candidate', 'rollback', *SECTIONS, 'discovery-bootstrap', INTAKE_KIND, CLAIM_KIND, RUN_INPUT_KIND, DOCUMENT_KIND, REPLAY_KIND, *LAUNCHER_KINDS)
MAGIC = int.from_bytes(b'HIADPK01', 'little')


def adapter_source(flow, ports, *, kind='describe', peers=b'', launcher=b''):
    # Local references let the existing flat-template builder prove that
    # every syscall adapter relocation is already resolved. The sole HIA
    # application call deliberately remains a zero rel32 hole.
    if kind == DOCUMENT_KIND:
        from tools.generate_hia_worker_evaluate_document_flow import ROLES
        for original, replacement in (
            (b'.equ ROLE_COUNT, 31', f'.equ ROLE_COUNT, {len(ROLES)}'.encode()),
            (b'.equ WORK_BYTES, 4096', b'.equ WORK_BYTES, 12288'),
            (b'--worker-context', b'--worker-evaluate-document'),
            (b'native HIA Context Worker transport', b'native HIA Evaluate document Worker transport'),
        ):
            if flow.count(original) != 1:
                raise ValueError('unexpected Context descriptor transport layout')
            flow = flow.replace(original, replacement)
        kind = 'context'
    if kind == PROOF_KIND:
        replacements = ((b'.equ ROLE_COUNT, 73', b'.equ ROLE_COUNT, 74'),
                        (b'--worker-adopt', b'--worker-evaluate-proof'),
                        (b'HIA Adopt Worker transport', b'HIA Evaluate proof Worker transport'))
        for previous, new in replacements:
            if flow.count(previous) != 1:
                raise ValueError('unexpected Adopt descriptor transport layout')
            flow = flow.replace(previous, new)
        kind = ADOPT_KIND
    if kind in (CLAIM_KIND, RUN_INPUT_KIND):
        kind = INTAKE_KIND
    if kind in (REPLAY_LAUNCHER_KIND, INTAKE_LAUNCHER_KIND):
        kind = LAUNCHER_KIND
    if kind in (REPLAY_KIND, INTAKE_KIND):
        if kind == REPLAY_KIND:
            from tools.generate_hia_worker_evaluate_replay_flow import ROLES
            label = b'Evaluate replay'
            previous_name, previous_count = b'Artifact', 23
        else:
            from tools.generate_hia_worker_evaluate_intake_flow import ROLES
            label = b'Evaluate intake'
            previous_name, previous_count = b'Context', 31
        for original, selected in (
            (f'.equ ROLE_COUNT, {previous_count}'.encode(), f'.equ ROLE_COUNT, {len(ROLES)}'.encode()),
            (b'--worker-' + previous_name.lower(), ('--worker-' + kind).encode()),
            (b'native HIA ' + previous_name + b' Worker transport', b'native HIA ' + label + b' Worker transport'),
        ):
            if flow.count(original) != 1:
                raise ValueError('unexpected descriptor transport layout')
            flow = flow.replace(original, selected)
    if launcher:
        flow += b'\n' + launcher
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
        'read-external': (b'.equ WORKER_COST, 1\n.equ WORKER_STORED_READ, 1\n'
                          b'.equ WORKER_EXTERNAL_READ, 1\n'),
        'input': b'.equ WORKER_COST, 1\n.equ WORKER_STORED_READ, 1\n.equ WORKER_INPUT, 1\n',
        INTAKE_KIND: b'.equ WORKER_CONTEXT, 1\n.equ WORKER_COST, 1\n.equ WORKER_STORED_READ, 1\n.equ WORKER_ARTIFACT, 1\n',
        REPLAY_KIND: b'.equ WORKER_COST, 1\n.equ WORKER_STORED_READ, 1\n.equ WORKER_ARTIFACT, 1\n',
        'artifact': (b'.equ WORKER_COST, 1\n.equ WORKER_STORED_READ, 1\n'
                     b'.equ WORKER_ARTIFACT, 1\n'),
        'discovery': (b'.equ WORKER_COST, 1\n.equ WORKER_STORED_READ, 1\n'
                      b'.equ WORKER_INPUT, 1\n.equ WORKER_DISCOVERY, 1\n'),
        'context': (b'.equ WORKER_COST, 1\n.equ WORKER_STORED_READ, 1\n'
                    b'.equ WORKER_ARTIFACT, 1\n.equ WORKER_CONTEXT, 1\n'),
        'inspection': (b'.equ WORKER_COST, 1\n.equ WORKER_STORED_READ, 1\n'
                       b'.equ WORKER_ARTIFACT, 1\n.equ WORKER_CONTEXT, 1\n.equ WORKER_INSPECTION, 1\n'),
        'candidate': (b'.equ WORKER_COST, 1\n.equ WORKER_STORED_READ, 1\n.equ WORKER_ARTIFACT, 1\n'
                      b'.equ WORKER_CONTEXT, 1\n.equ WORKER_INSPECTION, 1\n.equ WORKER_CANDIDATE, 1\n'),
        'rollback': (b'.equ WORKER_COST, 1\n.equ WORKER_STORED_READ, 1\n.equ WORKER_ARTIFACT, 1\n'
                     b'.equ WORKER_CONTEXT, 1\n.equ WORKER_INSPECTION, 1\n.equ WORKER_ROLLBACK, 1\n'),
        EMIT_KIND: (b'.equ WORKER_COST, 1\n.equ WORKER_STORED_READ, 1\n'
                    b'.equ WORKER_ARTIFACT, 1\n.equ WORKER_CONTEXT, 1\n'
                    b'.equ WORKER_INSPECTION, 1\n.equ WORKER_EMIT, 1\n'),
        ADOPT_KIND: (b'.equ WORKER_COST, 1\n.equ WORKER_STORED_READ, 1\n'
                     b'.equ WORKER_ARTIFACT, 1\n.equ WORKER_CONTEXT, 1\n'
                     b'.equ WORKER_INSPECTION, 1\n.equ WORKER_EMIT, 1\n.equ WORKER_ADOPT, 1\n'),
        VERIFY_KIND: (b'.equ WORKER_COST, 1\n.equ WORKER_STORED_READ, 1\n'
                      b'.equ WORKER_ARTIFACT, 1\n.equ WORKER_CONTEXT, 1\n'
                      b'.equ WORKER_INSPECTION, 1\n.equ WORKER_EMIT, 1\n.equ WORKER_VERIFY, 1\n'),
        'discovery-bootstrap': (b'.equ WORKER_COST, 1\n.equ WORKER_STORED_READ, 1\n'
                                b'.equ WORKER_ARTIFACT, 1\n.equ WORKER_BOOTSTRAP, 1\n'),
        LAUNCHER_KIND: (b'.equ WORKER_COST, 1\n.equ WORKER_STORED_READ, 1\n'
                        b'.equ WORKER_ARTIFACT, 1\n.equ WORKER_LAUNCHER, 1\n'),
    }[kind]
    return variant + flow + b'\n' + ports


def partitioned_packer(module, prefix, holes, *, extra_image=False, separate_sections=False):
    # Keep the constant adapter writes within the cold compiler's ordinary
    # block budget. The bytes and relocation are still emitted solely by HIA.
    source = source_program(magic=MAGIC, image_template=(prefix, holes), formatter=extra_image,
                            separate_sections=separate_sections,
                            pack_limit=EMIT_PACK_LIMIT if separate_sections else 1 << 20)
    start = source.index('    write(o, 0,')
    end = source.index('    write(o, 96, size, 8)', start)
    writes = source[start:end].splitlines(keepends=True)
    calls = []
    bodies = []
    for index, first in enumerate(range(0, len(writes), 96)):
        name = f'emit_adapter_{index}'
        calls.append(f'    {name}(o)\n')
        bodies.extend((f'\ndef {name}(o:mutbuf) -> u64:\n',
                       ''.join(writes[first:first + 96]), '    return 0\n'))
    return author_policy(source[:start] + ''.join(calls) + source[end:] + ''.join(bodies), module)


def source_packer(flow, ports, packer_path, *, kind, peers, launcher=b''):
    source = adapter_source(flow, ports, kind=kind, peers=peers, launcher=launcher)
    symbols = {'policy': 'worker_policy_hole'}
    if kind == LAUNCHER_KIND:
        symbols['authority'] = 'worker_authority_hole'
    if kind in SECTIONS:
        symbols.update(product='worker_emit_product_hole', proof='worker_emit_proof_hole')
    with TemporaryDirectory(prefix='hia-worker-flow-adapter-') as temporary:
        stub, locations, _ = adapter_layout(Path(temporary), 'worker_flow.S', source, symbols)
    holes = tuple(locations[name] for name in symbols)
    header = elf_header()
    module = Path(packer_path).stem
    template = header + stub, tuple(len(header) + hole for hole in holes)
    if kind in ('input', 'artifact', 'discovery', 'context', 'inspection', 'candidate', 'rollback', *SECTIONS,
                'discovery-bootstrap', DOCUMENT_KIND, INTAKE_KIND, REPLAY_KIND, LAUNCHER_KIND):
        packer = partitioned_packer(module, *template, extra_image=kind == LAUNCHER_KIND,
                                    separate_sections=kind in SECTIONS)
    else:
        packer = document(magic=MAGIC, module=module, image_template=template)
    return bind_adapter(packer, source, stub, holes)


if __name__ == '__main__':
    sources = Path(FLOW).read_bytes(), Path(PORTS).read_bytes()
    for kind, (_, path) in PROGRAMS.items():
        if kind in (CLAIM_KIND, RUN_INPUT_KIND, REPLAY_LAUNCHER_KIND, INTAKE_LAUNCHER_KIND):
            continue  # Both launchers use the same platform packer.
        peers = Path(PEERS).read_bytes() if kind in PEER_KINDS else b''
        launcher = Path(LAUNCHER).read_bytes() if kind == LAUNCHER_KIND else b''
        packer = source_packer(*sources, path, kind=kind, peers=peers, launcher=launcher)
        Path(path).write_text(render_assembly(packer), encoding='utf-8')
