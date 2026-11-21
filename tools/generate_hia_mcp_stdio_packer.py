"""Author fixed Linux transports for the HIA stdio ELF packer."""
from __future__ import annotations

import struct

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_stdio import ROOT, document, writes
from tools.generate_hia_borrowed_export_wire import (
    ARENA_BYTES as EXPORT_ARENA, CORE_WITH_EXPORTS_BYTES, PREFLIGHT_BYTES as EXPORT_PREFLIGHT,
)
from tools.generate_hia_core_json_cli import LIMIT, source_program as core_packer_source
from tools.generate_hia_mcp_connection import RESPONSE_BYTES, WORKSPACE_BYTES as CONNECTION_WORKSPACE
from tools.generate_hia_native_filter import WORKER_PRIVATE_BYTES, WORKER_WORKSPACE_BYTES

SOURCE = 'examples/hia_bootstrap/mcp_stdio_packer.hepta'
MAGIC = int.from_bytes(b'HIAMCPK1', 'little')
INPUT_MAX = 8 << 20
ARENA_BYTES = 64 + 262144 * 72 + INPUT_MAX
# A zero descriptor selects the variable-length reply contract.
DESCRIPTORS = (88, 0, 112, 24)
PAGE_MODE = len(DESCRIPTORS)
TERMINAL_MODE = PAGE_MODE + 1
SCHEMA_MODE = TERMINAL_MODE + 1
CONNECTION_MODE = SCHEMA_MODE + 1
READ_REQUEST_MODE = 16
STORE_UNIQUE_MODE = 17
WORKER_DATA_MODE = 18
WORKER_RESPONSE_MODE = 19
WORKER_JOURNAL_MODE = 20
JOURNAL_COST_MODE = 21
WORKER_PORT_MODE = 22
READ_REACTOR_MODE = 23
STORE_READY_MODE = 24
JOURNAL_READ_WORKFLOW_MODE = 25
WORKER_ARGUMENTS_MODE = 26
DESCRIBE_REQUEST_MODE = 27
DISCOVERY_MODE = 28
DESCRIBE_ANSWER_MODE = 29
DISCOVERY_ARTIFACT_MODE = 30
ARTIFACT_REQUEST_MODE = 31
JOURNAL_RECORD_MODE = 32
ARTIFACT_DIAGNOSTIC_MODE = 33
CONTEXT_WORKLOAD_MODE = 34
INSPECTION_MODE = 35
WORKER_CANONICAL_MODE = 36
LOWERING_ELF_MODE = 37
LOWERING_FRAMES_MODE = 38
BORROWED_EXPORT_MODE = 39
PACK_MODES = (*range(CONNECTION_MODE + 1), READ_REQUEST_MODE, STORE_UNIQUE_MODE,
              WORKER_DATA_MODE, WORKER_RESPONSE_MODE, WORKER_JOURNAL_MODE, JOURNAL_COST_MODE,
              READ_REACTOR_MODE, STORE_READY_MODE, JOURNAL_READ_WORKFLOW_MODE, WORKER_ARGUMENTS_MODE,
              DESCRIBE_REQUEST_MODE, DISCOVERY_MODE, DESCRIBE_ANSWER_MODE, DISCOVERY_ARTIFACT_MODE,
              ARTIFACT_REQUEST_MODE, JOURNAL_RECORD_MODE, ARTIFACT_DIAGNOSTIC_MODE,
              CONTEXT_WORKLOAD_MODE, INSPECTION_MODE, WORKER_CANONICAL_MODE, LOWERING_ELF_MODE, LOWERING_FRAMES_MODE, BORROWED_EXPORT_MODE)
WORKER_DATA_HEADER = 16
WORKER_RESPONSE_HEADER = 224
SCHEMA_HEADER = 72  # little-endian tool ordinal and 64 ASCII catalog digest bytes
SCHEMA_ARENA_BYTES = 64 + 262144 * 56 + INPUT_MAX + 8192
INSPECTION_HEADER = 9472
INSPECTION_ARENA_BYTES = 64 + 262144 * 56 + INPUT_MAX + INSPECTION_HEADER
INSPECTION_MAX = (24 << 20) + 2200
# The installed pager returns its canonical JSON alongside the cursor insertion.
PAGE_OUTPUT = 32 + 512 + 6 * 65536 + 132 + 533
PAGE_WORKSPACE = 512 + 4128
MODES = {'mcp-request': 0, 'mcp-reply': 1, 'mcp-terminal': 1, 'mcp-catalog': 1,
         'job-terminal-receipt': 1,
         'mcp-negotiation': 2, 'mcp-uri': 3, 'read-page': PAGE_MODE,
         'mcp-input-schema': SCHEMA_MODE, 'mcp-response-schema': SCHEMA_MODE,
         'mcp-proof-schema': SCHEMA_MODE, 'mcp-connection': CONNECTION_MODE,
         'read-request': READ_REQUEST_MODE, 'store-unique': STORE_UNIQUE_MODE,
         'journal-cost': JOURNAL_COST_MODE, 'read-effect': READ_REACTOR_MODE,
         'store-ready': STORE_READY_MODE, 'journal-read-workflow': JOURNAL_READ_WORKFLOW_MODE,
         'worker-arguments': WORKER_ARGUMENTS_MODE, 'describe-request': DESCRIBE_REQUEST_MODE,
         'discovery': DISCOVERY_MODE, 'describe-answer': DESCRIBE_ANSWER_MODE,
         'discovery-artifact': DISCOVERY_ARTIFACT_MODE, 'discovery-effect': READ_REACTOR_MODE,
         'describe-bind': DISCOVERY_MODE, 'discovery-bootstrap-plan': DISCOVERY_MODE,
         'discovery-bootstrap-assemble': DISCOVERY_MODE, 'artifact-request': ARTIFACT_REQUEST_MODE,
         'journal-records': JOURNAL_RECORD_MODE,
         'journal-observation': JOURNAL_RECORD_MODE,
         'context-store': DISCOVERY_MODE,
         'context-record': JOURNAL_RECORD_MODE,
         'context-request': ARTIFACT_REQUEST_MODE,
         'inspection-request': ARTIFACT_REQUEST_MODE,
         'candidate-request': ARTIFACT_REQUEST_MODE,
         'candidate-effect': READ_REACTOR_MODE,
         'inspection-effect': READ_REACTOR_MODE,
         'inspection-journal': JOURNAL_READ_WORKFLOW_MODE,
         'inspection-journal-observation': JOURNAL_RECORD_MODE,
         'inspection-journal-records': JOURNAL_RECORD_MODE,
         'inspection-diagnostic': ARTIFACT_DIAGNOSTIC_MODE,
         'candidate-journal': JOURNAL_READ_WORKFLOW_MODE,
         'candidate-journal-observation': JOURNAL_RECORD_MODE,
         'candidate-journal-records': JOURNAL_RECORD_MODE,
         'candidate-diagnostic': ARTIFACT_DIAGNOSTIC_MODE,
         'context-workload': CONTEXT_WORKLOAD_MODE,
         'context-payload': SCHEMA_MODE,
         'context-cost': CONTEXT_WORKLOAD_MODE,
         'context-cost-diagnostic': ARTIFACT_DIAGNOSTIC_MODE,
         'context-effect': DISCOVERY_MODE,
         'context-diagnostic': ARTIFACT_DIAGNOSTIC_MODE,
         'context-journal': JOURNAL_READ_WORKFLOW_MODE,
         'context-journal-records': JOURNAL_RECORD_MODE,
         'context-journal-observation': JOURNAL_RECORD_MODE,
         'inspection-wire': INSPECTION_MODE,
         'borrowed-export-wire': BORROWED_EXPORT_MODE,
         'borrowed-wrapper': ARTIFACT_REQUEST_MODE,
         'inspection-lowering-elf': LOWERING_ELF_MODE,
         'inspection-lowering-frames': LOWERING_FRAMES_MODE,
         'worker-canonical': WORKER_CANONICAL_MODE,
         'artifact-authority': DISCOVERY_MODE,
         'artifact-diagnostic': ARTIFACT_DIAGNOSTIC_MODE,
         'artifact-journal': JOURNAL_READ_WORKFLOW_MODE}


def elf_prefix(code):
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
              + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
              + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
              + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    return header + code


def resolve(code, labels, branches):
    for offset, target in branches:
        struct.pack_into('<i', code, offset, labels[target] - offset - 4)


def template(mode):
    if mode == READ_REACTOR_MODE:
        return read_reactor_template()
    if mode == STORE_UNIQUE_MODE:
        return store_unique_template()
    if mode == CONNECTION_MODE:
        return connection_template()
    if mode == TERMINAL_MODE:
        return terminal_template()
    page = mode == PAGE_MODE
    schema = mode == SCHEMA_MODE
    diagnostic = mode == ARTIFACT_DIAGNOSTIC_MODE
    context_workload = mode == CONTEXT_WORKLOAD_MODE
    inspection = mode in (INSPECTION_MODE, LOWERING_FRAMES_MODE)
    lowering_elf = mode == LOWERING_ELF_MODE
    borrowed_export = mode == BORROWED_EXPORT_MODE
    read_request = mode == READ_REQUEST_MODE
    worker_data = mode == WORKER_DATA_MODE
    worker_response = mode == WORKER_RESPONSE_MODE
    worker_journal = mode == WORKER_JOURNAL_MODE
    worker_arguments = mode == WORKER_ARGUMENTS_MODE
    worker_canonical = mode == WORKER_CANONICAL_MODE
    describe_request = mode == DESCRIBE_REQUEST_MODE
    discovery = mode in (DISCOVERY_MODE, ARTIFACT_REQUEST_MODE, JOURNAL_RECORD_MODE)
    artifact_request = mode == ARTIFACT_REQUEST_MODE
    journal_records = mode == JOURNAL_RECORD_MODE
    describe_answer = mode == DESCRIBE_ANSWER_MODE
    discovery_artifact = mode == DISCOVERY_ARTIFACT_MODE
    journal_cost = mode == JOURNAL_COST_MODE
    store_ready = mode == STORE_READY_MODE
    journal_read = mode == JOURNAL_READ_WORKFLOW_MODE
    worker = worker_data or worker_response or worker_journal or worker_arguments or worker_canonical
    worker_header = (8 if worker_canonical else WORKER_RESPONSE_HEADER if worker_response
                     else WORKER_DATA_HEADER)
    direct = page or read_request or store_ready or journal_read
    descriptor = None if (direct or schema or diagnostic or worker or describe_request or discovery
                          or describe_answer or discovery_artifact or context_workload or inspection or lowering_elf or borrowed_export) else (
        0 if journal_cost else DESCRIPTORS[mode])
    scratch = PAGE_OUTPUT if page else ((4 << 20) if descriptor or schema else INPUT_MAX + 32)
    prefix_bytes = 0 if direct else 8
    workspace = PAGE_WORKSPACE if page else (SCHEMA_ARENA_BYTES if schema else ARENA_BYTES)
    minimum = 24 if page else (SCHEMA_HEADER + 2 if schema else 2)
    maximum = ((64 << 20) + 1024 + 512) if page else (INPUT_MAX + SCHEMA_HEADER if schema else INPUT_MAX)
    if diagnostic:
        scratch, workspace, minimum = 4 << 20, SCHEMA_ARENA_BYTES, 1
    if context_workload:
        # The decoder also uses this mapping for its original duplicate-key table.
        scratch, workspace = 4 << 20, ARENA_BYTES + 8192
    if inspection:
        scratch, workspace = 16 << 20, INSPECTION_ARENA_BYTES
        minimum, maximum = INSPECTION_HEADER + 1, INSPECTION_HEADER + INSPECTION_MAX
        if mode == LOWERING_FRAMES_MODE:
            workspace, maximum = ARENA_BYTES + INSPECTION_HEADER, INSPECTION_HEADER + INPUT_MAX
    if borrowed_export:
        scratch, workspace, maximum = EXPORT_PREFLIGHT, EXPORT_ARENA, CORE_WITH_EXPORTS_BYTES
    if lowering_elf:
        scratch, workspace, minimum, maximum = 32 + 8 * 1024, 16 * 1024, 512, 64 << 20
    if read_request:
        scratch, workspace, maximum = 8192, 32768, 16384
    if describe_request:
        scratch, workspace, maximum = 8192, 32768, 16384
    if worker:
        # The common JSON engine uses this mapping as structural preflight
        # scratch even when the public role returns only a status.
        scratch = INPUT_MAX
        workspace = WORKER_WORKSPACE_BYTES
        minimum, maximum = worker_header + 1, worker_header + INPUT_MAX
    if journal_cost:
        scratch, workspace = INPUT_MAX + 2048, 24
        minimum, maximum = 56, INPUT_MAX + 2048
    if store_ready:
        scratch, workspace, minimum, maximum = 16, 8, 80, 80
    if journal_read:
        scratch, workspace, minimum, maximum = INPUT_MAX + 576, 24, 40, 2 * INPUT_MAX + 1112
    if discovery:
        scratch, workspace, minimum, maximum = 65536 + 32, 72 << 10, 8, 1 << 20
    if artifact_request:
        scratch, workspace, minimum, maximum = (4 << 16) + 512, (1 << 20) + 4096, 2, 1 << 20
    if journal_records:
        scratch, workspace, minimum, maximum = INPUT_MAX + 1024, 8, 72, INPUT_MAX + 1024
    if describe_answer:
        scratch, workspace, minimum, maximum = 65536, 8, 16, 1 << 20
    if discovery_artifact:
        scratch, workspace, minimum, maximum = 1024, 1152, 80, 233
    code, labels, branches = bytearray(), {}, []

    def emit(hexadecimal):
        code.extend(bytes.fromhex(hexadecimal))

    def word(value):
        code.extend(struct.pack('<I', value))

    def branch(opcode, target):
        emit(opcode)
        branches.append((len(code), target))
        word(0)

    def label(name):
        labels[name] = len(code)

    emit('48 83 3c 24 01')                      # argc == 1 at ELF entry
    branch('0f 85', 'bad_frame')
    emit('48 81 ec b0 00 00 00')                # aligned stat buffer
    emit('31 ff be 0a 04 00 00 b8 48 00 00 00 0f 05')  # fcntl(STDIN, F_GET_SEALS)
    emit('48 85 c0')
    branch('0f 88', 'bad_frame')
    emit('83 e0 0f 83 f8 0f')
    branch('0f 85', 'bad_frame')
    emit('31 ff 48 89 e6 b8 05 00 00 00 0f 05')  # fstat(STDIN, &stat)
    emit('48 85 c0')
    branch('0f 85', 'io_error')
    emit('4c 8b 6c 24 30')                     # r13 = stat.st_size
    if minimum < 128:
        emit(f'49 83 fd {minimum:02x}')
    else:
        emit('49 81 fd')
        word(minimum)
    branch('0f 82', 'bad_frame')
    emit('49 81 fd')
    word(maximum)
    branch('0f 87', 'bad_frame')

    # The sealed input is mapped read-only; result and kernel workspace stay RW.
    emit('31 ff 4c 89 ee ba 01 00 00 00 41 ba 02 00 00 00 45 31 c0 45 31 c9')
    emit('b8 09 00 00 00 0f 05 48 3d 01 f0 ff ff')
    branch('0f 83', 'io_error')
    emit('49 89 c4 31 ff be')
    word(prefix_bytes + scratch + workspace)
    emit('ba 03 00 00 00 41 ba 22 00 00 00 49 c7 c0 ff ff ff ff 45 31 c9')
    emit('b8 09 00 00 00 0f 05 48 3d 01 f0 ff ff')
    branch('0f 83', 'io_error')

    emit('49 89 c6')                            # r14 = private mapping base
    if journal_read:
        emit('49 c7 86')                        # select only the Journal workflow wire
        word(scratch)
        word(17)
    if schema:
        # Copy the sealed role and catalog digest into the schema arena.
        # The schema kernel, not the transport, validates those bytes.
        emit('49 8d be')
        word(prefix_bytes + scratch)
        emit('4c 89 e6 b9 09 00 00 00 f3 48 a5')
        emit('49 8d 7c 24 48 49 8d 75 b8')      # input pointer +72, bytes -72
    elif inspection:
        # The owner constructs the fixed native control area (view selectors,
        # nominal identity or lowering mode). Relay it without interpretation.
        emit('49 8d be')
        word(prefix_bytes + scratch + workspace - INSPECTION_HEADER)
        emit('4c 89 e6 b9')
        word(INSPECTION_HEADER // 8)
        emit('f3 48 a5 49 8d bc 24')
        word(INSPECTION_HEADER)
        emit('49 8d b5')
        word((1 << 32) - INSPECTION_HEADER)
    elif worker:
        # Forward the digit policy and any closed Journal recipe without
        # interpreting them. Only the HIA application admits the data.
        emit('49 8d be')
        word(prefix_bytes + scratch)
        policy = {WORKER_CANONICAL_MODE: 0, WORKER_DATA_MODE: 5, WORKER_RESPONSE_MODE: 6,
                  WORKER_JOURNAL_MODE: 7, WORKER_ARGUMENTS_MODE: 8}
        emit(f'48 c7 07 {policy[mode]:02x} 00 00 00 48 83 c7 08')
        emit('4c 89 e6 b9')
        word(worker_header // 8)
        emit('f3 48 a5 49 8d bc 24')
        word(worker_header)
        emit('49 8d b5')
        word((1 << 32) - worker_header)
    else:
        emit('4c 89 e7 4c 89 ee')
    emit('4c 89 f2' if direct else '49 8d 56 08')   # payload or status-prefixed result
    emit('b9')
    word(scratch)
    emit('4d 8d 86')
    word(prefix_bytes + scratch)
    emit('41 b9')
    word(workspace)
    emit('e8')
    branch_address = len(code)
    word(0)                                     # packer binds the actual HIA kernel
    if direct:
        if store_ready:
            emit('48 83 f8 10')                  # readiness decision plus generation
        elif journal_read:
            emit('48 3d')
            word(40)                            # nonempty admitted workflow result
        elif read_request:
            emit('48 3d')
            word(128)                           # complete read-plan header
        else:
            emit('48 83 f8 28')                  # complete 40-byte page header
        branch('0f 82', 'bad_frame')
        emit('48 3d')
        word(scratch)
        branch('0f 87', 'bad_frame')
        emit('48 89 c2 4c 89 f6')                # raw page without a status word
    else:
        emit('89 c0 49 89 06 4c 89 f6 ba 08 00 00 00')
        if descriptor:
            emit(f'83 f8 {descriptor:02x}')
            branch('0f 85', 'write_result')
            emit(f'83 c2 {descriptor:02x}')
        elif not (schema or worker_data):     # policy-only calls have no result body
            emit('83 f8 01' if worker_canonical else '83 f8 02')
            branch('0f 82', 'write_result')
            emit('3d')
            word(scratch)
            branch('0f 87', 'write_result')
            emit('01 c2')
    label('write_result')
    emit('bf 01 00 00 00 b8 01 00 00 00 0f 05 48 83 f8 fc')
    branch('0f 84', 'write_result')              # retry EINTR without dropping bytes
    emit('48 85 c0')
    branch('0f 8e', 'io_error')
    emit('48 01 c6 48 29 c2')
    branch('0f 85', 'write_result')
    emit('31 ff')
    branch('e9', 'exit')
    label('bad_frame')
    emit('bf 02 00 00 00')
    branch('e9', 'exit')
    label('io_error')
    emit('bf 04 00 00 00')
    label('exit')
    emit('b8 3c 00 00 00 0f 05 0f 0b')
    resolve(code, labels, branches)
    prefix = elf_prefix(code)
    return prefix, len(prefix) - len(code) + branch_address


def terminal_template():
    # RBP owns private header/IO control on the initial stack; R12/R13
    # are the payload/result mappings and R14/R15 the two HIA workspaces.
    frame_bytes, admission_bytes = 296, 88
    header_mode, extra, newline, sigpipe = 304, 312, 313, 320
    source_fd, source_size, stack = 352, 360, 368
    workspace = WORKER_WORKSPACE_BYTES
    private = workspace - WORKER_PRIVATE_BYTES
    code, labels, branches = bytearray(), {}, []

    def emit(hexadecimal):
        code.extend(bytes.fromhex(hexadecimal))

    def word(value):
        code.extend(struct.pack('<I', value))

    def branch(opcode, target):
        emit(opcode)
        branches.append((len(code), target))
        word(0)

    def label(name):
        labels[name] = len(code)

    def call(target):
        branch('e8', target)

    def call_with_extent(target, register, count):
        emit(register)
        word(count)
        call(target)

    def syscall(number):
        emit('b8')
        word(number)
        emit('0f 05')

    emit('fc 31 d2 48 83 3c 24 01')         # no argument: framed-only transport
    branch('0f 84', 'startup')
    emit('48 83 3c 24 02')
    branch('0f 85', 'bad_frame')
    emit('48 8b 74 24 10')                  # argv[1]: inherited raw source descriptor
    label('fd_digit')
    emit('0f b6 06 85 c0')
    branch('0f 84', 'fd_finished')
    emit('83 e8 30 83 f8 09')
    branch('0f 87', 'bad_frame')
    emit('48 6b d2 0a 48 01 c2 48 81 fa ff ff ff 7f')
    branch('0f 87', 'bad_frame')
    emit('48 ff c6')
    branch('e9', 'fd_digit')
    label('fd_finished')
    emit('83 fa 02')
    branch('0f 86', 'bad_frame')
    label('startup')
    emit('48 81 ec')
    word(stack)
    emit('48 89 e5 48 c7 85')               # RBP = frame base; mode = 4
    word(header_mode)
    word(4)
    emit('48 89 95')
    word(source_fd)
    emit('c6 85')
    word(newline)
    emit('0a')
    for offset, value in ((sigpipe, 1), (sigpipe + 8, 0),
                          (sigpipe + 16, 0), (sigpipe + 24, 0)):
        emit('48 c7 85')
        word(offset)
        word(value)
    emit('bf 0d 00 00 00 48 8d b5')        # rt_sigaction(SIGPIPE, &ignore, NULL, 8)
    word(sigpipe)
    emit('31 d2 41 ba 08 00 00 00')
    syscall(13)
    emit('48 85 c0')
    branch('0f 85', 'io_failure')
    emit('48 89 ee')                       # read frame marker, HIA selects full extent
    call_with_extent('read_exact', 'ba', 8)
    call_with_extent('check_header', 'be', 8)
    emit('83 f8 58')                       # admission header is 88 bytes
    branch('0f 84', 'admission')
    emit('48 83 bd')
    word(source_fd)
    emit('00')
    branch('0f 85', 'bad_frame')
    emit('3d')
    word(frame_bytes)
    branch('0f 85', 'bad_frame')
    emit('48 8d 75 08')
    call_with_extent('read_exact', 'ba', frame_bytes - 8)
    call_with_extent('check_header', 'be', frame_bytes)
    emit('83 f8 fe')
    branch('0f 84', 'budget')
    emit('3d')
    word(frame_bytes)
    branch('0f 85', 'bad_frame')

    call('allocate')                       # initialize request workspace and catalog pin
    emit('48 8b 45 18 49 89 46 08 48 8d 75 28')
    call('copy_catalog')
    emit('4c 89 e6 48 8b 55 08')
    call('read_exact')
    emit('4c 89 e7 48 8b 75 08 4c 89 ea 4d 89 f0')
    call('run_hia')
    emit('4c 89 e6 48 8b 55 10')
    call('read_exact')
    call('read_eof')
    call_with_extent('map_private', 'be', workspace)
    emit('49 89 c7 49 c7 07 03 00 00 00')   # second workspace with response-canonicalization mode
    emit('48 8b 45 18 49 89 47 08')
    emit('4c 89 e7 48 8b 75 10 4c 89 ea 4d 89 f8')
    call('run_hia')
    emit('48 89 c3 49 c7 06 02 00 00 00 48 8b 45 20')
    emit('49 89 86')                       # hand flags and remaining pins to HIA's renderer
    word(private + 520)
    emit('49 8d be')
    word(private + 528)
    emit('48 8d 75 68 b9 18 00 00 00 f3 48 a5')
    emit('4c 89 ef 48 89 de 4c 89 e2 4d 89 f0')
    call('run_hia')
    emit('48 89 c2 4c 89 e6')
    call('write_exact')
    emit('48 8d b5')
    word(newline)
    call_with_extent('write_exact', 'ba', 1)
    branch('e9', 'complete')

    label('admission')
    emit('48 8d 75 08')
    call_with_extent('read_exact', 'ba', admission_bytes - 8)
    call_with_extent('check_header', 'be', admission_bytes)
    emit('83 f8 fe')
    branch('0f 84', 'budget')
    emit('83 f8 58')
    branch('0f 85', 'bad_frame')
    call('allocate')
    emit('48 8b 45 10 49 89 46 08 48 8d 75 18')
    call('copy_catalog')
    emit('48 83 bd')
    word(source_fd)
    emit('00')
    branch('0f 84', 'admission_framed')
    emit('48 83 7d 08 00')                  # metadata contains no request bytes
    branch('0f 85', 'bad_frame')
    call('read_eof')
    emit('48 8b bd')
    word(source_fd)
    emit('4c 89 e6 ba')
    word(INPUT_MAX + 1)
    label('stream_read')
    emit('31 c0 0f 05 48 83 f8 fc')
    branch('0f 84', 'stream_read')
    emit('48 85 c0')
    branch('0f 88', 'io_failure')
    branch('0f 84', 'stream_read_complete')
    emit('48 01 c6 48 29 c2')
    branch('0f 85', 'stream_read')
    branch('e9', 'budget')
    label('stream_read_complete')
    emit('4c 29 e6 48 89 75 08 48 89 b5')
    word(source_size)
    branch('e9', 'admit_payload')
    label('admission_framed')
    emit('4c 89 e6 48 8b 55 08 48 85 d2')
    branch('0f 84', 'admission_eof')
    call('read_exact')
    label('admission_eof')
    call('read_eof')
    label('admit_payload')
    emit('4c 89 e7 48 8b 75 08 4c 89 ea 4d 89 f0')
    call('raw_hia')
    emit('89 c0 48 89 45 08 45 31 ff 3d')    # preserve raw admission status
    word(INPUT_MAX)
    branch('0f 86', 'admission_arena')
    emit('83 f8 e9')
    branch('0f 82', 'admission_reply')
    emit('83 f8 ef')
    branch('0f 87', 'admission_reply')
    label('admission_arena')
    emit('4d 8b 7e 20 49 83 ff 40')
    branch('0f 82', 'io_failure')
    emit('49 81 ff')
    word(private)
    branch('0f 87', 'io_failure')
    label('admission_reply')
    emit('4c 89 7d 10 48 89 ee 48 83 bd')
    word(source_fd)
    emit('00')
    branch('0f 84', 'framed_reply')
    emit('48 b8')
    code.extend(b'HIAWSO01')
    emit('48 89 45 00 48 8b 85')
    word(source_size)
    emit('48 89 45 18')
    call_with_extent('write_exact', 'ba', 32)
    branch('e9', 'reply_arena')
    label('framed_reply')
    emit('48 b8')
    code.extend(b'HIAWRO02')
    emit('48 89 45 00')
    call_with_extent('write_exact', 'ba', 24)
    label('reply_arena')
    emit('4d 85 ff')
    branch('0f 84', 'reply_bytes')
    emit('4c 89 f6 4c 89 fa')
    call('write_exact')
    label('reply_bytes')
    emit('48 83 bd')
    word(source_fd)
    emit('00')
    branch('0f 84', 'complete')
    emit('48 8b 95')
    word(source_size)
    emit('48 85 d2')
    branch('0f 84', 'complete')
    emit('4c 89 e6')
    call('write_exact')
    label('complete')
    emit('31 ff')
    branch('e9', 'exit')

    label('allocate')
    call_with_extent('map_private', 'be', INPUT_MAX + 1)
    emit('49 89 c4')
    call_with_extent('map_private', 'be', INPUT_MAX)
    emit('49 89 c5')
    call_with_extent('map_private', 'be', workspace)
    emit('49 89 c6 49 c7 06 01 00 00 00 c3')
    label('copy_catalog')
    emit('49 8d be')
    word(private + 64)
    emit('b9 08 00 00 00 f3 48 a5 c3')

    label('check_header')
    emit('48 89 ef 31 d2 31 c9 4c 8d 85')
    word(header_mode)
    emit('41 b9 08 00 00 00')
    branch('e9', 'kernel')
    label('run_hia')
    emit('48 83 ec 08')
    call('raw_hia')
    emit('48 83 c4 08 83 f8 fe')
    branch('0f 84', 'budget')
    emit('83 f8 ea')
    branch('0f 84', 'budget')
    emit('83 f8 fd')
    branch('0f 84', 'bad_frame')
    emit('3d 00 ff ff ff')
    branch('0f 83', 'rejected')
    emit('85 c0')
    branch('0f 84', 'io_failure')
    emit('3d')
    word(INPUT_MAX)
    branch('0f 87', 'io_failure')
    emit('89 c0 c3')
    label('raw_hia')
    emit('b9')
    word(INPUT_MAX)
    emit('41 b9')
    word(workspace)
    label('kernel')
    emit('e9')                            # tail jump bound by the HIA packer
    displacement = len(code)
    word(0)

    label('map_private')
    emit('31 ff ba 03 00 00 00 41 ba 22 00 00 00 49 c7 c0 ff ff ff ff 45 31 c9')
    syscall(9)
    emit('48 3d 01 f0 ff ff')
    branch('0f 83', 'io_failure')
    emit('c3')
    label('read_exact')
    emit('31 ff 31 c0 0f 05 48 83 f8 fc')
    branch('0f 84', 'read_exact')
    emit('48 85 c0')
    branch('0f 88', 'io_failure')
    branch('0f 84', 'bad_frame')
    emit('48 01 c6 48 29 c2')
    branch('0f 85', 'read_exact')
    emit('c3')
    label('read_eof')
    emit('31 ff 48 8d b5')
    word(extra)
    emit('ba 01 00 00 00 31 c0 0f 05 48 83 f8 fc')
    branch('0f 84', 'read_eof')
    emit('48 85 c0')
    branch('0f 88', 'io_failure')
    branch('0f 85', 'bad_frame')
    emit('c3')
    label('write_exact')
    emit('bf 01 00 00 00')
    syscall(1)
    emit('48 83 f8 fc')
    branch('0f 84', 'write_exact')
    emit('48 85 c0')
    branch('0f 8e', 'io_failure')
    emit('48 01 c6 48 29 c2')
    branch('0f 85', 'write_exact')
    emit('c3')
    for name, status in (('rejected', 2), ('budget', 3), ('io_failure', 4), ('bad_frame', 64)):
        label(name)
        emit('bf')
        word(status)
        branch('e9', 'exit')
    label('exit')
    syscall(60)
    emit('0f 0b')
    resolve(code, labels, branches)
    prefix = elf_prefix(code)
    return prefix, len(prefix) - len(code) + displacement


def connection_template():
    """Only Linux I/O stays in the adapter; the HIA kernel owns the session."""
    chunk_bytes = 4096
    code, labels, branches = bytearray(), {}, []

    def emit(value):
        code.extend(bytes.fromhex(value))

    def word(value):
        code.extend(struct.pack('<I', value))

    def branch(opcode, target):
        emit(opcode)
        branches.append((len(code), target))
        word(0)

    def label(name):
        labels[name] = len(code)

    def map_private(size, register):
        emit('be')
        word(size)
        branch('e8', 'map')
        emit(register)

    emit('48 83 3c 24 01')                     # argc == 1
    branch('0f 85', 'bad_frame')
    emit('48 83 ec 20 48 89 e5 fc')            # aligned local storage; clear DF
    map_private(INPUT_MAX + chunk_bytes, '49 89 c4')
    map_private(RESPONSE_BYTES, '49 89 c5')
    map_private(CONNECTION_WORKSPACE, '49 89 c6')
    emit('4d 8d bc 24')
    word(INPUT_MAX)                           # r15 = chunk after the input
    emit('31 db')                             # rbx = bytes in current frame

    label('read')
    emit('31 ff 4c 89 fe ba')
    word(chunk_bytes)
    emit('31 c0 0f 05 48 83 f8 fc')
    branch('0f 84', 'read')                    # EINTR
    emit('48 85 c0')
    branch('0f 88', 'io_failure')
    branch('0f 84', 'eof')
    emit('48 89 45 00 48 c7 45 08 00 00 00 00')

    label('next')
    emit('4c 8b 45 08 4c 3b 45 00')
    branch('0f 84', 'read')
    emit('43 0f b6 14 07 48 ff 45 08 80 fa 0a')
    branch('0f 84', 'frame')
    emit('48 81 fb')
    word(INPUT_MAX)
    branch('0f 83', 'bad_frame')
    emit('41 88 14 1c 48 ff c3')
    branch('e9', 'next')

    label('frame')
    emit('4c 89 e7 48 89 de 4c 89 ea b9')     # s, bytes, o, o_capacity
    word(RESPONSE_BYTES)
    emit('4d 89 f0 41 b9')                    # workspace, w_capacity
    word(CONNECTION_WORKSPACE)
    emit('e8')
    displacement = len(code)
    word(0)
    emit('31 db 89 c0 85 c0')                  # notification => zero output
    branch('0f 84', 'next')
    emit('3d')
    word(RESPONSE_BYTES)
    branch('0f 87', 'io_failure')
    emit('41 80 7c 05 ff 0a')
    branch('0f 85', 'io_failure')
    emit('4c 89 ee 89 c2')

    label('write')
    emit('bf 01 00 00 00 b8 01 00 00 00 0f 05 48 83 f8 fc')
    branch('0f 84', 'write')
    emit('48 85 c0')
    branch('0f 8e', 'io_failure')
    emit('48 01 c6 48 29 c2')
    branch('0f 85', 'write')
    branch('e9', 'next')

    label('map')
    emit('31 ff ba 03 00 00 00 41 ba 22 00 00 00 49 c7 c0 ff ff ff ff')
    emit('45 31 c9 b8 09 00 00 00 0f 05 48 3d 01 f0 ff ff')
    branch('0f 83', 'io_failure')
    emit('c3')

    label('eof')
    emit('48 85 db')
    branch('0f 85', 'bad_frame')
    emit('31 ff')
    branch('e9', 'exit')
    for name, status in (('bad_frame', 64), ('io_failure', 4)):
        label(name)
        emit('bf')
        word(status)
        branch('e9', 'exit')
    label('exit')
    emit('b8 3c 00 00 00 0f 05 0f 0b')
    resolve(code, labels, branches)
    prefix = elf_prefix(code)
    return prefix, len(prefix) - len(code) + displacement


def store_unique_template():
    """Run HIA-owned Store transactions over the inherited descriptor pair."""
    # The fixed Linux adapter carries bytes; it never parses the Store protocol.
    code = bytes.fromhex(
        # Check exact argv shape and inherited descriptor numbers.
        '48 8b 1c 24 48 83 fb 02 0f 82 5a 05 00 00 48 83 fb 03 0f 87 50 05 00 00 '
        '48 8b 74 24 10 e8 3a 00 00 00 41 89 c5 41 be ff ff ff ff 48 83 fb 03 75 '
        '16 48 8b 74 24 18 e8 21 00 00 00 44 39 e8 0f 84 24 05 00 00 41 89 c6 48 '
        '81 ec 80 49 00 00 49 89 e4 45 89 b4 24 10 49 00 00 fc eb 47 31 d2 31 c9 '
        '0f b6 06 85 c0 74 30 83 f9 0a 0f 83 f8 04 00 00 83 e8 30 83 f8 09 0f 87 '
        'ec 04 00 00 48 6b d2 0a 48 01 c2 48 81 fa ff ff ff 7f 0f 87 d8 04 00 00 '
        '48 ff c6 ff c1 eb c9 83 fa 03 0f 82 c8 04 00 00 89 d0 c3 '
        # Validate the sealed control, map its immutable bytes and check private output custody.
        '31 ff be 0a 04 00 00 b8 48 00 00 00 0f 05 48 85 c0 0f 88 ae 04 00 00 83 '
        'e0 0f 83 f8 0f 0f 85 a2 04 00 00 31 ff 49 8d b4 24 00 20 00 00 b8 05 00 '
        '00 00 0f 05 48 85 c0 0f 85 8f 04 00 00 4d 8b b4 24 30 20 00 00 49 83 fe '
        '18 74 17 49 83 fe 69 0f 82 70 04 00 00 49 81 fe 00 08 80 00 0f 87 63 04 '
        '00 00 bf 01 00 00 00 be 0a 04 00 00 b8 48 00 00 00 0f 05 48 85 c0 0f 85 '
        '49 04 00 00 bf 01 00 00 00 31 f6 ba 02 00 00 00 b8 08 00 00 00 0f 05 48 '
        '85 c0 0f 85 2d 04 00 00 49 8d bc 24 00 40 00 00 31 c0 b9 20 01 00 00 f3 '
        '48 ab 31 ff 4c 89 f6 ba 01 00 00 00 41 ba 02 00 00 00 45 31 c0 45 31 c9 '
        'b8 09 00 00 00 0f 05 48 3d 01 f0 ff ff 0f 83 f9 03 00 00 49 89 84 24 38 '
        '49 00 00 4d 89 b4 24 40 49 00 00 e8 6b 03 00 00 49 8b bc 24 38 49 00 00 '
        'eb 03 4c 89 e7 '
        # Invoke HIA; transport only admits bounded mechanical actions.
        '4c 89 f6 49 8d 94 24 00 20 00 00 b9 e0 1f 00 00 4d 8d 84 24 00 40 00 00 '
        '41 b9 00 09 00 00 e8 00 00 00 00 83 f8 20 0f 82 a4 03 00 00 3d e0 1f 00 '
        '00 0f 87 99 03 00 00 41 89 c7 49 8d 9c 24 00 20 00 00 48 8b 03 48 8b 53 '
        '08 48 83 f8 01 0f 84 84 00 00 00 48 83 f8 02 0f 84 89 00 00 00 48 83 f8 '
        '03 74 34 48 83 f8 04 0f 84 b4 00 00 00 48 83 f8 06 0f 84 6c 01 00 00 48 '
        '83 f8 07 0f 84 ce 00 00 00 48 83 f8 05 0f 85 45 03 00 00 41 83 ff 30 0f '
        '85 3b 03 00 00 eb 0a 41 83 ff 20 0f 85 2f 03 00 00 bf 01 00 00 00 48 89 '
        'de 44 89 fa e8 3a 02 00 00 bf 01 00 00 00 be 09 04 00 00 ba 0f 00 00 00 '
        'b8 48 00 00 00 0f 05 48 85 c0 0f 85 07 03 00 00 31 ff e9 05 03 00 00 41 '
        '83 ff 20 0f 85 ef 02 00 00 e9 5b 01 00 00 48 85 d2 0f 84 e1 02 00 00 48 '
        '81 fa c0 1f 00 00 0f 87 d4 02 00 00 48 8d 42 20 4c 39 f8 0f 85 c7 02 00 '
        '00 bf 01 00 00 00 48 8d 73 20 e8 d4 01 00 00 ba 08 00 00 00 e9 20 01 00 '
        '00 48 83 fa 30 0f 82 a5 02 00 00 48 81 fa 68 08 00 00 0f 87 98 02 00 00 '
        '48 8d 42 20 4c 39 f8 0f 85 8b 02 00 00 e8 14 02 00 00 e9 d3 00 00 00 '
        # Write the HIA frame and its bounded slice of the sealed control mapping.
        '41 83 ff 50 0f 85 77 02 00 00 48 85 d2 0f 84 6e 02 00 00 48 8b 43 10 49 '
        '8b 8c 24 40 49 00 00 48 39 c8 0f 87 59 02 00 00 48 29 c1 48 39 ca 0f 87 '
        '4d 02 00 00 49 03 84 24 38 49 00 00 49 89 84 24 48 49 00 00 49 89 94 24 '
        '50 49 00 00 e8 be 01 00 00 41 8b bc 24 10 49 00 00 83 ff 03 0f 82 1f 02 '
        '00 00 48 8d 73 20 ba 30 00 00 00 e8 2c 01 00 00 41 8b bc 24 10 49 00 00 '
        '49 8b b4 24 48 49 00 00 49 8b 94 24 50 49 00 00 e8 0f 01 00 00 ba 08 00 '
        '00 00 eb 5e '
        # Publish the private uncertain-commit marker before advancing the Store.
        '41 83 ff 58 0f 85 e3 01 00 00 83 fa 30 0f 85 da 01 00 00 41 83 bc 24 10 '
        '49 00 00 03 0f 82 cb 01 00 00 e8 54 01 00 00 bf 01 00 00 00 48 8d 73 50 '
        'ba 08 00 00 00 e8 ce 00 00 00 ba 30 00 00 00 41 8b bc 24 10 49 00 00 83 '
        'ff 03 0f 82 9d 01 00 00 48 8d 73 20 e8 af 00 00 00 ba 08 00 00 00 '
        # Carry the next exact reply extent back to HIA.
        '48 85 d2 0f 84 86 01 00 00 48 81 fa c0 1f 00 00 0f 87 79 01 00 00 4c 8d '
        '72 08 48 b8 48 49 41 53 54 55 43 31 49 89 04 24 44 89 ef 49 8d 74 24 08 '
        'e8 05 00 00 00 e9 82 fd ff ff '
        # Poll and implement exact I/O across interruptions and short writes.
        '41 89 f8 49 89 f1 41 89 d2 e8 f0 00 00 00 45 89 84 24 00 49 00 00 41 c7 '
        '84 24 04 49 00 00 01 00 00 00 49 8d bc 24 00 49 00 00 be 01 00 00 00 b8 '
        '07 00 00 00 0f 05 48 83 f8 fc 74 cd 48 85 c0 0f 8e 17 01 00 00 44 89 c7 '
        '4c 89 ce 44 89 d2 31 c0 0f 05 48 83 f8 fc 74 b1 48 83 f8 f5 74 ab 48 85 '
        'c0 0f 8e f5 00 00 00 49 01 c1 49 29 c2 75 9a c3 41 89 f8 49 89 f1 41 89 '
        'd2 e8 80 00 00 00 45 89 84 24 00 49 00 00 41 c7 84 24 04 49 00 00 04 00 '
        '00 00 49 8d bc 24 00 49 00 00 be 01 00 00 00 b8 07 00 00 00 0f 05 48 83 '
        'f8 fc 74 cd 48 85 c0 0f 8e a7 00 00 00 44 89 c7 4c 89 ce 44 89 d2 b8 01 '
        '00 00 00 0f 05 48 83 f8 fc 74 ae 48 83 f8 f5 74 a8 48 85 c0 0f 8e 82 00 '
        '00 00 49 01 c1 49 29 c2 75 97 c3 '
        # Lease a single ten-second monotonic deadline for each Store command.
        'e8 3c 00 00 00 48 bf 00 e4 0b 54 02 00 00 00 48 01 f8 49 89 84 24 30 49 '
        '00 00 c3 e8 21 00 00 00 49 8b b4 24 30 49 00 00 48 29 c6 7e 4c 48 8d 86 '
        '3f 42 0f 00 31 d2 be 40 42 0f 00 48 f7 f6 89 c2 c3 bf 01 00 00 00 49 8d '
        'b4 24 20 49 00 00 b8 e4 00 00 00 0f 05 48 85 c0 75 1f 49 8b 84 24 20 49 '
        '00 00 48 69 c0 00 ca 9a 3b 49 03 84 24 28 49 00 00 c3 '
        # Reject malformed inputs and distinguish incomplete I/O.
        'bf 02 00 00 00 eb 05 bf 04 00 00 00 b8 3c 00 00 00 0f 05 0f 0b '
    )
    return elf_prefix(code), len(elf_prefix(b"")) + 439


def read_reactor_template():
    """Retain the HIA read effect's private state across observations."""
    code = bytes.fromhex(
        # Allocate one private HIA arena for the retained read session.
        '48 83 3c 24 01 0f 85 3e 01 00 00 31 ff be 08 e0 00 00 ba 03 00 00 00 41 '
        'ba 22 00 00 00 41 b8 ff ff ff ff 45 31 c9 b8 09 00 00 00 0f 05 48 3d 01 '
        'f0 ff ff 0f 83 17 01 00 00 49 89 c4 '
        # Read only the fixed observation frame and its bounded tail.
        '4c 89 e6 ba 28 00 00 00 e8 c8 00 00 00 83 f8 00 0f 84 f3 00 00 00 83 f8 '
        '01 0f 85 f5 00 00 00 48 b8 48 49 41 46 44 45 30 31 49 39 04 24 0f 85 da '
        '00 00 00 4d 8b 6c 24 20 49 81 fd d8 3f 00 00 0f 87 c8 00 00 00 4d 85 ed '
        '74 16 49 8d 74 24 28 4c 89 ea e8 7e 00 00 00 83 f8 01 0f 85 b4 00 00 00 '
        # Call HIA in the same arena; write the bounded raw action.
        '4c 89 e7 49 8d 75 28 49 8d 94 24 08 40 00 00 b9 00 20 00 00 4d 8d 84 24 '
        '08 60 00 00 41 b9 00 80 00 00 e8 00 00 00 00 89 c0 49 89 84 24 00 40 00 '
        '00 ba 08 00 00 00 83 f8 ff 74 0e 83 f8 30 72 74 3d 00 20 00 00 77 6d 01 '
        'c2 49 8d b4 24 00 40 00 00 bf 01 00 00 00 b8 01 00 00 00 0f 05 48 83 f8 '
        'fc 74 ee 48 85 c0 7e 4c 48 01 c6 48 29 c2 75 e1 e9 2b ff ff ff '
        # Preserve extent across short reads and distinguish truncated input.
        '45 31 c0 31 ff 31 c0 0f 05 48 83 f8 fc 74 f4 48 85 c0 78 2b 74 11 49 01 '
        'c0 48 01 c6 48 29 c2 75 e2 b8 01 00 00 00 c3 31 c0 4d 85 c0 74 05 b8 02 '
        '00 00 00 c3 31 ff eb 0c bf 02 00 00 00 eb 05 bf 04 00 00 00 b8 3c 00 00 '
        '00 0f 05 0f 0b '
    )
    return elf_prefix(code), len(elf_prefix(b'')) + 191


def worker_port_prefix():
    """Fixed Linux child I/O; all Worker role selection stays in HIA policy."""
    code = bytes.fromhex(
        # Admit the inherited sealed program and input, and the fresh output descriptor.
        '48 83 3c 24 02 0f 85 d9 03 00 00 48 8b 74 24 10 e8 98 03 00 00 41 89 c4 '
        '48 81 ec 80 00 00 00 48 89 e5 44 89 e7 be 0a 04 00 00 b8 48 00 00 00 0f '
        '05 83 f8 0f 0f 85 aa 03 00 00 44 89 e7 48 89 ee ba 04 00 00 00 45 31 d2 '
        'b8 11 00 00 00 0f 05 48 83 f8 04 0f 85 8b 03 00 00 81 7d 00 7f 45 4c 46 '
        '0f 85 7e 03 00 00 31 ff be 0a 04 00 00 b8 48 00 00 00 0f 05 83 f8 0f 0f '
        '85 67 03 00 00 31 ff 31 f6 31 d2 b8 08 00 00 00 0f 05 48 85 c0 0f 85 51 '
        '03 00 00 bf 01 00 00 00 be 0a 04 00 00 b8 48 00 00 00 0f 05 85 c0 0f 85 '
        '38 03 00 00 bf 01 00 00 00 31 f6 ba 02 00 00 00 b8 08 00 00 00 0f 05 48 '
        '85 c0 0f 85 1c 03 00 00 48 8d 3d 2a 03 00 00 be 01 00 00 00 b8 3f 01 00 '
        '00 0f 05 48 85 c0 0f 88 07 03 00 00 41 89 c7 48 8d 3d 0b 03 00 00 be 01 '
        '00 00 00 b8 3f 01 00 00 0f 05 48 85 c0 0f 88 e8 02 00 00 41 89 c6 48 c7 '
        '45 60 00 00 00 00 48 c7 45 68 00 00 00 00 48 c7 45 70 00 00 00 00 48 c7 '
        '45 78 00 00 00 00 bf 11 00 00 00 48 8d 75 60 31 d2 41 ba 08 00 00 00 b8 '
        '0d 00 00 00 0f 05 48 85 c0 0f 85 a4 02 00 00 b8 27 00 00 00 0f 05 89 45 '
        '08 b8 39 00 00 00 0f 05 48 85 c0 0f 88 8a 02 00 00 0f 84 62 01 00 00 41 '
        '89 c5 44 89 ef 31 f6 b8 b2 01 00 00 0f 05 48 85 c0 0f 88 0e 01 00 00 89 '
        '45 10 c7 45 14 01 00 00 00 48 c7 45 18 0a 00 00 00 48 c7 45 20 00 00 00 '
        '00 '
        # Wait against one bounded pidfd lease without consuming stdout.
        '48 8d 7d 10 be 01 00 00 00 48 8d 55 18 45 31 d2 45 31 c0 b8 0f 01 00 00 '
        '0f 05 48 83 f8 fc 74 e0 48 85 c0 0f 8e cb 00 00 00 e8 df 00 00 00 8b 45 '
        '28 a9 7f 00 00 00 0f 85 16 02 00 00 89 c7 c1 ef 08 81 e7 ff 00 00 00 0f '
        '85 0a 02 00 00 44 89 ff 31 f6 ba 02 00 00 00 b8 08 00 00 00 0f 05 48 85 '
        'c0 0f 85 eb 01 00 00 44 89 f7 31 f6 ba 02 00 00 00 b8 08 00 00 00 0f 05 '
        '48 3d 00 04 00 04 0f 87 ce 01 00 00 48 89 45 58 44 89 f7 31 f6 31 d2 b8 '
        '08 00 00 00 0f 05 48 85 c0 0f 85 b3 01 00 00 '
        # Transfer complete staged output and seal the separate destination.
        '4c 8b 55 58 4d 85 d2 74 26 bf 01 00 00 00 44 89 f6 31 d2 b8 28 00 00 00 '
        '0f 05 48 83 f8 fc 74 e0 48 85 c0 0f 8e 8a 01 00 00 48 29 45 58 eb d1 bf '
        '01 00 00 00 be 09 04 00 00 ba 0f 00 00 00 b8 48 00 00 00 0f 05 48 85 c0 '
        '0f 85 65 01 00 00 31 ff e9 63 01 00 00 '
        # Terminate and reap only the unreaped owned child.
        '44 89 ef be 09 00 00 00 b8 3e 00 00 00 0f 05 e8 05 00 00 00 e9 45 01 00 '
        '00 44 89 ef 48 8d 75 28 31 d2 45 31 d2 b8 3d 00 00 00 0f 05 48 83 f8 fc '
        '74 e7 44 39 e8 0f 85 23 01 00 00 c3 '
        # Apply the parent lease, descriptor custody and fixed execveat transport.
        'bf 01 00 00 00 be 09 00 00 00 31 d2 45 31 d2 45 31 c0 b8 9d 00 00 00 0f '
        '05 48 85 c0 0f 85 00 01 00 00 b8 6e 00 00 00 0f 05 3b 45 08 0f 85 f0 00 '
        '00 00 44 89 f7 be 01 00 00 00 b8 21 00 00 00 0f 05 48 83 f8 01 0f 85 d7 '
        '00 00 00 44 89 ff be 02 00 00 00 b8 21 00 00 00 0f 05 48 83 f8 02 0f 85 '
        'be 00 00 00 48 c7 45 30 00 04 00 04 48 c7 45 38 00 04 00 04 bf 01 00 00 '
        '00 48 8d 75 30 b8 a0 00 00 00 0f 05 48 85 c0 0f 85 95 00 00 00 bf 03 00 '
        '00 00 be ff ff ff ff ba 04 00 00 00 b8 b4 01 00 00 0f 05 48 85 c0 75 7a '
        '48 8d 05 81 00 00 00 48 89 45 40 48 c7 45 48 00 00 00 00 48 c7 45 50 00 '
        '00 00 00 44 89 e7 48 8d 35 74 00 00 00 48 8d 55 40 4c 8d 55 50 41 b8 00 '
        '10 00 00 b8 42 01 00 00 0f 05 eb 3e '
        # Decode only inherited decimal descriptor numbers.
        '31 d2 31 c9 0f b6 06 85 c0 74 24 83 f9 0a 73 27 83 e8 30 83 f8 09 77 1f '
        '48 6b d2 0a 48 01 c2 48 81 fa ff ff ff 7f 77 0f 48 ff c6 ff c1 eb d5 83 '
        'fa 03 72 03 89 d0 c3 bf 02 00 00 00 eb 05 bf 04 00 00 00 b8 3c 00 00 00 '
        '0f 05 0f 0b 68 69 61 2d 77 6f 72 6b 65 72 2d 63 68 69 6c 64 00 00 '
    )
    return elf_prefix(code)


def render():
    common_header = elf_prefix(b'')
    header_bytes = len(common_header)
    source = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    count = length(s)
    if count < 16 or count > {16 + LIMIT} or read_word(s, 0) != {MAGIC}:
        return 4294967295
    mode = read_word(s, 8)
    if mode == {WORKER_PORT_MODE}:
        if count != 16:
            return 4294967295
        return pack_worker_port(o)
    if count == 16:
        return 4294967295
'''
    for mode in PACK_MODES:
        source += f'    if mode == {mode}:\n        return pack_{mode}(s, o)\n'
    source += '    return 4294967295\n'
    for mode in PACK_MODES:
        prefix, call = template(mode)
        source += f'''
def pack_{mode}(s:readbuf, o:mutbuf) -> u32:
    size = {len(prefix)} + length(s) - 16
    if length(o) < size:
        return 4294967294
'''
        if prefix[:header_bytes] != common_header:
            raise ValueError('stdio adapter has a different ELF header')
        source += '    pack_elf_header(o)\n' + writes(prefix[header_bytes:], offset=header_bytes)
        source += f'''    put_word(o, 96, size)
    put_word(o, 104, size)
    put_four(o, {call}, {len(prefix) - call - 4})
    i = 16
    while i < length(s):
        store(o, {len(prefix)} + i - 16, byte(s, i))
        i = i + 1
    return size
'''
    prefix = worker_port_prefix()
    source += f'''
def pack_worker_port(o:mutbuf) -> u32:
    size = {len(prefix)}
    if length(o) < size:
        return 4294967294
'''
    if prefix[:header_bytes] != common_header:
        raise ValueError('worker port has a different ELF header')
    source += '    pack_elf_header(o)\n' + writes(prefix[header_bytes:], offset=header_bytes)
    source += '''    put_word(o, 96, size)
    put_word(o, 104, size)
    return size
'''
    source += '\ndef pack_elf_header(o:mutbuf) -> u64:\n' + writes(common_header) + '    return 0\n'
    helpers = core_packer_source()
    source += helpers[helpers.index('\ndef read_word('):]
    return render_assembly(document(source, 'mcp_stdio_packer'))


if __name__ == '__main__':
    (ROOT / SOURCE).write_text(render(), encoding='utf-8')
