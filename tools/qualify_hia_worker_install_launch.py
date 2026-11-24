"""Qualify native Worker Store installation, verification and controller launch.

This external component fixture embeds the retained HIA owner, DAG and SHA
images unchanged. A test-only mechanical adapter preloads the state reached
after a complete Store build and stops before the Worker DAG. It does not
qualify or bypass production source/cold admission; the complete owner must
still be exercised separately. All installation decisions execute in HIA.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ast,fcntl,hashlib,json,os,struct,subprocess,sys,time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.generate_hia_worker_install_owner import policy_source

def seal(label, raw, mode=0o400):
    fd = os.memfd_create(label, os.MFD_ALLOW_SEALING)
    at = 0
    while at < len(raw):
        used = os.write(fd, memoryview(raw)[at:])
        if used <= 0:
            raise OSError("incomplete fixture capability write")
        at += used
    os.fchmod(fd, mode)
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, 15)
    os.lseek(fd, 0, os.SEEK_SET)
    return fd


def build_capsule(directory, component, stop_phase=7012):
    source = (ROOT / 'tools/hia_worker_install_owner_syscalls.S').read_text()
    preload = '''
    xor ebp,ebp
test_state_read:
    mov eax,17
    mov edi,200
    lea rsi,[r15+rbp]
    mov edx,STATE_BYTES
    sub rdx,rbp
    mov r10,rbp
    syscall
    test rax,rax
    jle invalid
    add rbp,rax
    cmp rbp,STATE_BYTES
    jb test_state_read
    mov eax,39
    syscall
    mov [r15+16],rax
'''
    source = source.replace('advance:\n', preload + f'''advance:
    cmp QWORD PTR [r15],{stop_phase}
    jne test_continue
    xor edi,edi
    jmp test_exit
test_continue:
''', 1)
    source = source.replace('    mov rax,[r14]\n', '''    cmp QWORD PTR [r14],60
    jne test_no_exit
    mov rdi,[rsp]
    jmp test_exit
test_no_exit:
    mov rax,[r14]
''', 1)
    source += '''
test_exit:
    mov [r15+61992],rdi
    mov eax,72
    mov rdi,[r15+1800144]
    mov esi,1
    syscall
    mov [r15+61800],rax
    mov eax,72
    mov rdi,[r15+1800456]
    mov esi,1
    syscall
    mov [r15+61808],rax
    mov eax,72
    mov rdi,[r15+1800464]
    mov esi,1
    syscall
    mov [r15+61816],rax
    mov eax,72
    mov rdi,[r15+1800472]
    mov esi,1
    syscall
    mov [r15+61824],rax
    xor ebp,ebp
test_state_write:
    mov eax,18
    mov edi,201
    lea rsi,[r15+rbp]
    mov edx,STATE_BYTES
    sub rdx,rbp
    mov r10,rbp
    syscall
    test rax,rax
    jle invalid
    add rbp,rax
    cmp rbp,STATE_BYTES
    jb test_state_write
    mov rdi,[r15+61992]
    mov eax,60
    syscall
    ud2
'''
    assembler = directory / 'fixture.S'
    assembler.write_text(source)
    obj, text = directory / 'fixture.o', directory / 'fixture.bin'
    subprocess.run(['as', '--64', str(assembler), '-o', str(obj)], check=True)
    subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(text)], check=True)
    symbols = {name: int(address, 16) for address, _, name in
               (line.split() for line in subprocess.check_output(['nm', '-n', str(obj)], text=True).splitlines())}
    if 'R_X86_64' in subprocess.check_output(['objdump', '-r', str(obj)], text=True):
        raise ValueError('unresolved test adapter relocation')
    images = []
    for name in ('worker_install_owner', 'worker_install_dag', 'sha256_stream'):
        alias = 'hia-worker-install-owner' if name == 'worker_install_owner' else name
        candidates = (component / (name + '.image.bin'), component / (alias + '.hepta.image.bin'))
        matches = [path for path in candidates if path.is_file()]
        if len(matches) != 1:
            raise ValueError((name, [str(path) for path in matches]))
        images.append(matches[0].read_bytes())
    body = bytearray(text.read_bytes())
    size = 176 + len(body) + sum(map(len, images))
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
              + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
              + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, size, size, 4096)
              + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    at = len(body)
    for name, image in zip(('policy_hole', 'stage_hole', 'sha_hole'), images):
        struct.pack_into('<i', body, symbols[name], at - symbols[name] - 4)
        at += len(image)
    raw = header + body + b''.join(images)
    path = directory / 'hia-dag-component'
    path.write_bytes(raw)
    path.chmod(0o500)
    return path, [hashlib.sha256(value).hexdigest() for value in images]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--component', type=Path, required=True)
    parser.add_argument('--programs', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expect-code', type=int, default=0)
    parser.add_argument('--expect-callback', type=int)
    parser.add_argument('--timeout', type=int, default=300)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(mode=0o700)
    stage, work, installation = (out / name for name in ('stage', 'work', 'installation'))
    for directory in (stage, work, installation):
        directory.mkdir(mode=0o700)
    package = args.package.resolve(strict=True).read_bytes()
    package_pin = sha256(package).hexdigest()
    (installation / 'store.hiapack').write_bytes(package)
    reserve = os.open('/dev/null', os.O_RDONLY)
    os.dup2(reserve, 200); os.dup2(reserve, 201); os.close(reserve)
    keep = [200, 201]
    state = bytearray(4 << 20)
    pins = {}
    def put(at, *values):
        struct.pack_into('<' + 'Q' * len(values), state, at, *values)
    def capability(name, raw, mode=0o500):
        fd = seal(name, raw, mode); keep.append(fd)
        pins[name] = sha256(raw).hexdigest()
        return fd, len(raw), sha256(raw).digest()
    def program(name):
        return capability(name, (args.programs / name).read_bytes())
    runner, seed, capture = (program(name) for name in
                             ('hia-subprocess', 'hia-source-build', 'hia-source-capture'))
    release, builder = (program(name) for name in ('hia-release', 'hia-directory-package-build'))
    package_fd = capability('package', package, 0o400)
    directory_fds = [os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                     for path in (ROOT, stage, work, out, installation)]
    keep.extend(directory_fds)
    nodes = [node for node in ast.parse(policy_source() + '\n' + policy_source(stage=True)).body
             if isinstance(node, ast.FunctionDef) and node.name in ('constants', 'worker_constants')]
    for statement in [statement for node in nodes for statement in node.body]:
        if isinstance(statement, ast.Expr):
            call = statement.value
            assert isinstance(call, ast.Call) and call.func.id == 'put'
            put(ast.literal_eval(call.args[1]), ast.literal_eval(call.args[2]))
    # This is deliberately a component request, without a cold-admission claim.
    inventory = struct.pack('<8sQ', b'HIASPI01', 0)
    name = installation.name.encode('ascii')
    deadline = time.monotonic_ns() + args.timeout * 1_000_000_000
    request = struct.pack('<8s15Q', b'HIAWIN01', 0, deadline, *directory_fds[:3],
                          runner[0], seed[0], capture[0], seed[0], seed[0],
                          *directory_fds[3:], len(name), len(inventory), 0)
    request += runner[2] + seed[2] + capture[2] + seed[2] + seed[2] + name + inventory
    request_fd = capability('component-request', request, 0o400)[0]
    put(0, 7000, 0)
    # A retained roots extent must survive the later controller/Worker transitions.
    put(1800696, 136)
    put(24, os.geteuid())
    put(216, seed[0], capture[0], runner[0])
    put(3000, runner[1], seed[1])
    put(1530040, builder[0])
    put(1530056, release[0])
    put(1800016, package_fd[0], len(package))
    state[1800032:1800064] = bytes.fromhex(package_pin)
    state[1800064:1800128] = package_pin.encode('ascii')
    roles = ('hia-controller-install', 'hia-directory-package-build', 'hia-release',
             'HIA_AGENT_NATIVE_TOOL_CATALOG.json', 'hia-agent-job-terminal-receipt',
             'hia-agent-mcp-catalog', 'hia-agent-mcp-input-schema', 'hia-agent-mcp-negotiation',
             'hia-agent-mcp-proof-schema', 'hia-agent-mcp-reply', 'hia-agent-mcp-request',
             'hia-agent-mcp-response-schema', 'hia-agent-mcp-terminal', 'hia-agent-mcp-uri',
             'hia-job-receipt', 'hia-job-supervisor', 'hia-worker-prepare')
    for index, role in enumerate(roles):
        fd, size, unused = program(role)
        at = 1600000 + index * 160
        put(at, fd, size, len(role))
        state[at + 32:at + 32 + len(role)] = role.encode('ascii')
    put(1599904, len(roles))
    state_fd = seal('component-state', state)
    os.dup2(state_fd, 200); os.close(state_fd)
    snapshot = os.open(out / 'terminal-state.bin', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.dup2(snapshot, 201); os.close(snapshot)
    executable, image_pins = build_capsule(out, args.component.resolve(strict=True))
    begin = time.monotonic()
    try:
        result = subprocess.run(['/usr/bin/strace', '-f', '-qq', '-s', '128', '-o',
                                 str(out / 'trace.log'), str(executable)], stdin=request_fd,
                                capture_output=True, pass_fds=tuple(keep), env={'PATH': ''},
                                timeout=args.timeout + 30)
    finally:
        for fd in keep: os.close(fd)
    terminal = (out / 'terminal-state.bin').read_bytes()
    assert len(terminal) == 4 << 20
    selected = {name: struct.unpack_from('<Q', terminal, at)[0]
                for name, at in (('phase', 0), ('sysret', 8), ('callback', 512), ('stored_result', 152), ('retained_roots_bytes', 1800696))}
    report = {'scope': 'NATIVE_WORKER_POST_RELEASE_COMPONENT_WITHOUT_COLD_ADMISSION',
              'returncode': result.returncode, 'expected_returncode': args.expect_code,
              'elapsed': time.monotonic() - begin, 'terminal': selected,
              'owner_dag_sha_image_sha256': image_pins, 'capability_sha256': pins,
              'package_sha256': package_pin, 'stdout_hex': result.stdout.hex(),
              'stderr_hex': result.stderr.hex(), 'trace_sha256': sha256((out / 'trace.log').read_bytes()).hexdigest()}
    if result.returncode == 0:
        assert selected['phase'] == 7012
        parent_flags = list(struct.unpack_from('<4Q', terminal, 61800))
        assert parent_flags == [1, 1, 1, 1], parent_flags
        report['parent_directory_cloexec_preserved'] = True
        report['retained_roots_extent_preserved'] = selected['retained_roots_bytes'] == 136
        controllers = list((installation / 'controller').glob('*/hia-controller.json'))
        assert len(controllers) == 1
        controller = json.loads(controllers[0].read_bytes())
        assert controller['schema'] == 'hepta.hia.mcp.controller.v25' and len(controller['files']) == 14
        for role, pin in controller['files'].items():
            assert sha256((controllers[0].parent / role).read_bytes()).hexdigest() == pin
            assert (controllers[0].parent / role).read_bytes() == (installation / 'store' / package_pin / role).read_bytes()
        report['controller_sha256'] = sha256(controllers[0].read_bytes()).hexdigest()
        report['native_store_install_verify_controller_completed'] = True
    (out / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))
    if result.returncode == 0 and not report['retained_roots_extent_preserved']:
        raise SystemExit('retained roots extent changed across native controller installation')
    if args.expect_callback is not None and selected['callback'] != args.expect_callback:
        raise SystemExit('unexpected native Worker refusal phase')
    if result.returncode != args.expect_code or result.stdout or result.stderr:
        raise SystemExit('unexpected native Worker launch result')

if __name__ == '__main__':
    main()
