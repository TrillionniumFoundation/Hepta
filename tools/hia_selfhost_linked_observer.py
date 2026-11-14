"""Native transport for linked self-host qualification, with the real ELF loader.

Each call execs a fresh HIA-policy-directed adapter, dlopens the exact complete sealed
target shared object, and calls its fixed byte ABI. This helper does not replace
the independent seed/shared loader, parse HIA, compile user code, reuse a child,
or claim a security sandbox. It is selected only for the qualifier's linked HIA
objects. Non-whitespace private response noise is refused, never searched for a
later magic sequence; the original JSON loader's boundary whitespace is kept.

The real libc startup/exit path preserves loader constructors/finalizers.
Reported values and ordinary output are captured before normal finalization;
requested trap/shared-output observation reads the actual mapping after exit.
A separate parent-owned snapshot is committed by the native observer after f0,
before publishing stdout or entering libc exit. It retains ordinary output even
when a finalizer traps, exits nonzero, or prevents a well-formed stdout report.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

from tools.hia_selfhost_native_observer import (LIMIT, WORKSPACE_FIELDS, digest,
                                               frame, shared_output, read_capture)

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "examples/hia_bootstrap/linked_observer_policy.hepta"
PACKER = ROOT / "examples/hia_bootstrap/linked_observer_packer.hepta"
SOURCE_PATHS = (POLICY, PACKER, ROOT / "tools/generate_hia_linked_observer.py",
                ROOT / "tools/hia_linked_observer_bridge.S")


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


def source_identity():
    return {p.relative_to(ROOT).as_posix(): digest(p.read_bytes()) for p in SOURCE_PATHS}


def vm_packer(checked, policy):
    from tools.generate_hia_linked_observer import reference_object
    expected = reference_object(policy)
    values, output, workspace, steps = _vm(checked, policy, b'\xa5'*len(expected), b'')
    if values != [len(expected)] or output != expected or workspace:
        raise AssertionError('linked observer VM did not reproduce every actual object byte')
    return output, {'input_bytes':len(policy),'input_sha256':digest(policy),
                    'output_bytes':len(output),'output_sha256':digest(output),
                    'result':values,'steps':steps,'every_output_byte_compared':True}


def independent_reference(*, before_B0=False):
    """All continuation actions and complete object bytes precede compilation."""
    from hepta.hia_agent_assembly import assemble_program
    before = source_identity()
    policy = assemble_program(POLICY.read_bytes())
    packer = assemble_program(PACKER.read_bytes())
    packing = []
    for actual in (b'\xc3', bytes(range(256))*17):
        _, receipt = vm_packer(packer, actual)
        packing.append(receipt)
    workspace, control = bytearray(512), bytes(512)
    struct.pack_into('<Q', workspace, 8, 1)
    request = _linked_frame(b'complete ELF remains opaque to policy',b'source\0\xff',17,40,90,None,11)
    observations = []
    def step(source, expected, feedback=()):
        nonlocal workspace, control
        for at, value in feedback:
            struct.pack_into('<Q',workspace,at,value)
        values, control, updated, steps = _vm(policy,source,control,bytes(workspace))
        workspace = bytearray(updated)
        if values != [expected]:
            raise AssertionError('linked observer VM continuation differs')
        observations.append({'action':expected,'output_hex':control.hex(),
                             'workspace_hex':updated.hex(),'steps':steps})
        return control
    first = step(b'',1)
    if struct.unpack_from('<8Q',first) != (5242937,10,256<<20,8<<20,16<<20,32,0,0):
        raise AssertionError('linked observer resource limits differ')
    step(request,2,((16,0),))
    path = step(request,3,((16,0),(24,7),(32,15)))
    if path[64:80] != b'/proc/self/fd/7\0':
        raise AssertionError('linked observer descriptor path differs')
    symbol = step(request,4,((16,0x12340000),))
    if symbol[64:67] != b'f0\0':
        raise AssertionError('linked observer symbol differs')
    step(request,5,((16,0),(32,0x12340100)))
    step(request,6,((16,0),))
    snapshot = step(request,8,((16,0),(24,11),(32,999999990),(40,12),(48,10),(56,0xdeadbeef0000002a)))
    if struct.unpack_from('<2Q',snapshot,32) != (11,18):
        raise AssertionError('linked observer return-snapshot custody differs')
    if snapshot[128:152] != b'HIAOBR03'+struct.pack('<QQ',0xdeadbeef0000002a,20):
        raise AssertionError('linked observer result/time framing differs')
    response = step(request,7,((16,0),))
    if response[128:152] != snapshot[128:152]:
        raise AssertionError('linked observer changed its committed response')
    final = step(request,0,((16,0),))
    if struct.unpack_from('<Q',final)[0] != 0:
        raise AssertionError('linked observer completion differs')
    if source_identity() != before:
        raise AssertionError('linked observer source changed during independent VM')
    return {'before_B0':before_B0,'before_native_compilation':True,'source_sha256':before,
            'policy_core_sha256':policy.sha256,'packer_core_sha256':packer.sha256,
            'policy_observations':observations,'packer_observations':packing,
            'every_output_byte_compared':True,
            'actual_policy_bytes_checked_again_after_native_compilation':True,
            'whole_stack_rewritten_in_hia':False,'all_input_equivalence_proved':False}


def build(directory, compiler, reference):
    """HIA emits policy and full ET_REL; the real linker resolves the foreign ABI."""
    from hepta.hia_agent_assembly import assemble_program
    from tools.qualify_hia_selfhost import compile_stage, invoke, observe_native_tool
    if (reference.get('before_native_compilation') is not True
            or reference.get('source_sha256') != source_identity()):
        raise ValueError('linked observer independent source identity differs')
    directory = Path(directory)
    policy, policy_receipt = compile_stage(directory,'linked-observer-policy',compiler,POLICY.read_bytes())
    packer, packer_receipt = compile_stage(directory,'linked-observer-packer',compiler,PACKER.read_bytes())
    actual_policy = policy.read_bytes()
    independent, vm_receipt = vm_packer(assemble_program(PACKER.read_bytes()),actual_policy)
    execution, raw = invoke(directory,'linked-observer-emit',packer,actual_policy)
    if (execution.get('status') != 'returned' or execution.get('abi_status') != 0
            or execution.get('core_u32') != len(independent) or not execution.get('source_unchanged')
            or raw[:len(independent)] != independent):
        raise AssertionError('linked observer native ET_REL differs from independent Core VM output')
    obj = directory/'linked-observer.o'
    obj.write_bytes(raw[:len(independent)])
    interpreter, runtime = _runtime_interpreter()
    executable = directory/'linked-observer.elf'
    observations = [
        observe_native_tool(directory,'linked-observer-object-readelf','readelf',['-W','-h','-S','-s','-r',obj]),
        observe_native_tool(directory,'linked-observer-link','ld',[
            '-m','elf_x86_64','-pie','-e','_start','--dynamic-linker',interpreter,
            '-z','defs','-z','noexecstack','-z','relro','-z','now','--build-id=none',obj,'-ldl','-lc','-o',executable]),
        observe_native_tool(directory,'linked-observer-executable-readelf','readelf',['-W','-h','-l','-s','-r','-d',executable]),
    ]
    if (source_identity() != reference['source_sha256']
            or digest(interpreter.read_bytes()) != runtime['interpreter_sha256']):
        raise AssertionError('linked observer source or loader changed during construction')
    image = executable.read_bytes(); executable.chmod(0o700)
    receipt = {'source_sha256':reference['source_sha256'],
        'compiler_sha256':digest(Path(compiler).read_bytes()),
        'policy_sha256':digest(actual_policy),'object_sha256':digest(independent),'object_bytes':len(independent),
        'executable_sha256':digest(image),'executable_bytes':len(image),
        'native_policy_compilation':policy_receipt,'native_packer_compilation':packer_receipt,
        'native_emission':execution,'actual_policy_vm_packing':vm_receipt,
        'independent_reference_before_B0':reference['before_B0'],
        'independent_reference_before_native_compilation':reference['before_native_compilation'],
        'native_tool_observations':observations,'runtime_loader':runtime,
        'target_loading':'complete sealed target shared object; RTLD_LOCAL|RTLD_NOW; dlsym(f0)',
        'lifecycle':'HIA policy; libc startup/exit; no eager dlclose; real signal termination',
        'production_activated':False,'whole_stack_rewritten_in_hia':False}
    (directory/'linked-observer-build.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
    return executable, receipt


def _runtime_interpreter():
    """Read only the admitted running interpreter's ELF representation."""
    executable = Path(sys.executable).resolve(strict=True)
    data = executable.read_bytes()
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("linked observer requires the actual Linux x86-64 ELF interpreter")
    fields = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    _, kind, machine, version, _, phoff, _, _, ehsize, phsize, phnum, _, _, _ = fields
    if kind not in (2, 3) or machine != 62 or version != 1 or ehsize != 64 or phsize != 56:
        raise ValueError("running interpreter has an unsupported ELF representation")
    if phoff > len(data) or phnum > (len(data) - phoff) // phsize:
        raise ValueError("running interpreter program headers are outside the file")
    interpreters = []
    for index in range(phnum):
        header = struct.unpack_from("<IIQQQQQQ", data, phoff + index * phsize)
        if header[0] == 3:
            offset, size = header[2], header[5]
            if offset > len(data) or size > len(data) - offset:
                raise ValueError("running interpreter PT_INTERP is outside the file")
            raw = data[offset:offset + size]
            if not raw.startswith(b"/") or not raw.endswith(b"\0") or b"\0" in raw[:-1]:
                raise ValueError("running interpreter PT_INTERP is not one absolute path")
            interpreters.append(os.fsdecode(raw[:-1]))
    if len(interpreters) != 1:
        raise ValueError("running interpreter must identify exactly one system loader")
    path = Path(interpreters[0])
    raw = path.read_bytes()
    return path, {"executable": str(executable), "executable_sha256": digest(data),
                  "interpreter": str(path), "resolved_interpreter": str(path.resolve(strict=True)),
                  "interpreter_sha256": digest(raw)}


def execute(executable_bytes, request, *, cwd, timeout=20, arguments=(), output_fd=None, snapshot_fd=None):
    """Exec exact sealed bytes, with binary stdin/stdout; never interpret them."""
    fd = os.memfd_create('hia-linked-native-observer', os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(executable_bytes)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError('short observer image write')
            view = view[written:]
        fcntl.fcntl(fd, getattr(fcntl,'F_ADD_SEALS',1033), 15)
        if fcntl.fcntl(fd, getattr(fcntl,'F_GET_SEALS',1034)) & 15 != 15:
            raise OSError('observer image sealing failed')
        return subprocess.run(['/proc/self/fd/'+str(fd), *arguments], input=request,
            cwd=cwd, capture_output=True, timeout=timeout, pass_fds=(fd, *(value for value in (output_fd, snapshot_fd) if value is not None)),
            env=None)
    finally:
        os.close(fd)


@contextmanager
def output_snapshot(capacity):
    """Own a fixed-size return snapshot, separate from the live output mapping."""
    if type(capacity) is not int or not 0 <= capacity <= LIMIT:
        raise ValueError('native output snapshot exceeds the unchanged byte ABI limit')
    descriptor = os.memfd_create('hia-linked-return-snapshot', os.MFD_ALLOW_SEALING)
    try:
        # Fresh anonymous pages include a zero completion word. The snapshot
        # may be filled, but its shape cannot be changed by the child.
        os.ftruncate(descriptor, 8 + capacity)
        fcntl.fcntl(descriptor, getattr(fcntl, 'F_ADD_SEALS', 1033), 7)
        if fcntl.fcntl(descriptor, getattr(fcntl, 'F_GET_SEALS', 1034)) & 7 != 7:
            raise OSError('return snapshot extent sealing failed')
        yield descriptor
    finally:
        os.close(descriptor)


def _linked_frame(image, source, capacity, workspace_size, workspace_fill,
                  output_fd, snapshot_fd):
    original = frame(image, source, capacity, workspace_size, workspace_fill, output_fd)
    if (type(snapshot_fd) is not int or not 3 <= snapshot_fd <= 2147483647
            or snapshot_fd == output_fd):
        raise ValueError('native return snapshot descriptor is invalid')
    descriptors = struct.pack('<2I', 0xffffffff if output_fd is None else output_fd, snapshot_fd)
    return b'HIAOBS03' + original[8:48] + descriptors + original[56:]


def read_output_snapshot(descriptor, capacity):
    marker = os.pread(descriptor, 8, 0)
    if len(marker) != 8:
        raise OSError('short native return completion word')
    completed = int.from_bytes(marker, 'little')
    if completed == 0:
        return None
    if completed != capacity + 1:
        raise ValueError('native return snapshot completion differs')
    result = bytearray()
    while len(result) < capacity:
        part = os.pread(descriptor, capacity - len(result), 8 + len(result))
        if not part:
            raise OSError('short native return snapshot')
        result.extend(part)
    return bytes(result)


def _response_frame(raw, expected):
    """Keep the old JSON loader's boundary whitespace without trimming buffers.

    Only JSON's four ASCII whitespace bytes may precede the first magic byte
    or follow the complete fixed-length response. The frame itself, including
    trailing whitespace in source/output/workspace, is copied without changes.
    A later magic sequence is never searched for.
    """
    begin = 0
    while begin < len(raw) and raw[begin] in b" \t\r\n":
        begin += 1
    end = begin + expected
    if end > len(raw) or raw[begin:begin + 8] != b"HIAOBR03":
        return None
    for byte in raw[end:]:
        if byte not in b" \t\r\n":
            return None
    return raw[begin:end]


def invoke(directory, label, observer, image, source, *, capacity, workspace_size, workspace_fill,
           output_initial=None, observe_trap_writes=False):
    directory, image, observer = Path(directory), Path(image), Path(observer)
    image_bytes, executable = image.read_bytes(), observer.read_bytes()
    # Validate before creating a file descriptor or serializing large buffers.
    frame(image_bytes,source,capacity,workspace_size,workspace_fill)
    initial = b'\xa5'*capacity if output_initial is None else output_initial
    if not isinstance(initial,bytes) or len(initial)!=capacity:
        raise ValueError('output preimage must match the capacity')
    with shared_output(initial,output_initial is not None or observe_trap_writes) as capture_fd, \
            output_snapshot(capacity) as snapshot_fd:
        payload = _linked_frame(image_bytes,source,capacity,workspace_size,workspace_fill,capture_fd,snapshot_fd)
        input_path = directory/(label+'.input.bin')
        output_path = directory/(label+'.output.bin')
        input_path.write_bytes(source)
        request = {'format':'linked-selfhost', 'transport':'HIA-policy-dynamic-ELF-linked-observer-v2',
            'image':str(image.resolve()), 'image_sha256':digest(image_bytes),
            'source':str(input_path.resolve()), 'source_sha256':digest(source),
            'capacity':capacity, 'workspace_size':workspace_size, 'workspace_fill':workspace_fill,
            'observer_sha256':digest(executable),'shared_output_fd':capture_fd,'return_snapshot_fd':snapshot_fd,
            'observe_trap_writes':observe_trap_writes,'output_initial_sha256':digest(initial), 'frame_sha256':digest(payload),
            'output':str(output_path.resolve())}
        (directory/(label+'.request.json')).write_text(json.dumps(request,sort_keys=True)+'\n')
        began = time.monotonic_ns()
        output = b''
        try:
            try:
                process = execute(executable,payload,cwd=directory,output_fd=capture_fd,snapshot_fd=snapshot_fd)
            except subprocess.TimeoutExpired as exc:
                stderr = exc.stderr or b''
                if exc.stdout:
                    (directory/(label+'.failure-stdout.raw')).write_bytes(exc.stdout)
                result = {'status':'timeout','wall_limit_seconds':20}
            else:
                stderr = process.stderr
                if process.returncode:
                    if process.stdout:
                        (directory/(label+'.failure-stdout.raw')).write_bytes(process.stdout)
                    result = {'status':'child_failed','returncode':process.returncode,
                        'stderr':stderr.decode('utf-8','replace')[-4096:]}
                else:
                    raw = process.stdout
                    framed = _response_frame(raw, 24+len(source)+capacity+workspace_size)
                    if framed is None:
                        (directory/(label+'.failure-stdout.raw')).write_bytes(raw)
                        result = {'status':'protocol_failed','returncode':0,
                            'response_bytes':len(raw),'response_sha256':digest(raw),
                            'error':'native observer response framing differs'}
                    else:
                        raw = framed
                        returned, elapsed = struct.unpack_from('<2Q',raw,8)
                        actual_source = raw[24:24+len(source)]
                        output = raw[24+len(source):24+len(source)+capacity]
                        workspace = raw[24+len(source)+capacity:]
                        if actual_source != source:
                            (directory/(label+'.modified-source.bin')).write_bytes(actual_source)
                        result = {'status':'returned','result_u64':returned,'abi_status':returned>>32,
                            'return_encoding':'zero-extended-u32','core_u32':returned & 0xffffffff,
                            'source_sha256':digest(source),'image_sha256':digest(image_bytes),
                            'output_sha256':digest(output),'source_unchanged':actual_source==source,
                            'output_unchanged':output==initial,
                            'workspace_header':{str(at):int.from_bytes(workspace[at:at+8],'little')
                                for at in WORKSPACE_FIELDS if workspace_size>=at+8},
                            'native_elapsed_ns':elapsed,'forbidden_compiler_modules_loaded':[],
                            'loader_operations':'HIA-emitted linked observer; sealed exec and target memfd; real dlopen/dlsym; fixed ABI call; libc finalization',
                            'limits':{'cpu_seconds':10,'address_bytes':256<<20,'core_dumpable':False,
                                'stack_bytes':8<<20,'output_capacity':capacity,'workspace_bytes':workspace_size}}
        finally:
            capture=None
            if capture_fd is not None:
                capture=read_capture(capture_fd,capacity)
        snapshot = read_output_snapshot(snapshot_fd, capacity)
        if result.get('status') == 'returned':
            if snapshot is None or snapshot != output:
                (directory/(label+'.failure-stdout.raw')).write_bytes(process.stdout)
                output = b''
                result = {'status':'protocol_failed','returncode':0,
                    'response_bytes':len(process.stdout),'response_sha256':digest(process.stdout),
                    'error':'native observer return snapshot differs'}
            else:
                output_path.write_bytes(output)
        elif result.get('status') in ('child_failed', 'timeout') and snapshot is not None:
            # The original child wrote its output file immediately after f0.
            # A later finalizer failure must not erase that already-observed
            # preimage. Stdout cannot prove it: a constructor can emit bytes
            # and exit before f0, and a finalizer can append non-JSON noise.
            output = snapshot
            output_path.write_bytes(output)
        result['prefinalizer_output_snapshot'] = {
            'available': snapshot is not None,
            'bytes': 0 if snapshot is None else len(snapshot),
            'sha256': None if snapshot is None else digest(snapshot),
            'origin': 'parent-owned size-sealed memfd; native commit after f0',
        }
        # The old linked child records values before normal loader finalizers.
        # A finalizer may then change the actually shared output. Preserve that
        # ordering; custom preimages without trap capture remain the earlier bytes.
        if observe_trap_writes:
            if capture is None or len(capture)!=capacity:
                raise AssertionError('shared output observation unavailable')
            output=capture
            output_path.write_bytes(output)
            result['shared_output_observation']={
                'available':True,'initial_sha256':digest(initial),'observed_sha256':digest(output),
                'observed_bytes':len(output),'unchanged':output==initial,
                'capture_origin':'parent-owned size-sealed memfd, mapped by actual native child'}
        result.update(case=label,input_sha256=digest(source),input_bytes=len(source),
            artifact_sha256=digest(image_bytes),format='linked-selfhost',runner_sha256=digest(executable),
            wall_elapsed_ns=time.monotonic_ns()-began,transport=request['transport'],
            fresh_native_exec=True,successor_process_reuse=False)
        if observer.read_bytes()!=executable or image.read_bytes()!=image_bytes or input_path.read_bytes()!=source:
            raise AssertionError('native observer or immutable inputs changed')
        (directory/(label+'.stdout.log')).write_text(json.dumps(result,sort_keys=True)+'\n')
        (directory/(label+'.stderr.log')).write_bytes(stderr)
        (directory/(label+'.receipt.json')).write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
        return result, output
