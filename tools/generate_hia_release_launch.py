"""Author an explicit HIA selected-release execution boundary.

The old selection verifier is unchanged. This independent executable consumes
the package on fd3 and launches one separately hash-pinned, sealed native ELF.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import struct
import subprocess
import tempfile

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_release_install import policy_source as installer_source
from tools.generate_hia_release_selection import adapter_source as selection_adapter

ROOT = Path(__file__).resolve().parents[1]
MAGIC = int.from_bytes(b'HIALPK01', 'little')
WORK_BYTES = 8192
EXPECTED_ADAPTER_INPUTS = {
    'tools/hia_release_install_syscalls.S':
        '8d131a8f2453f35230851621e9c093be8142e275f8d5c06487564590f4b4bd3e',
    'tools/hia_release_selection_syscalls.S':
        'bc0c4d5aeeb1c8aedf265ae9ccc94a65fb9dae1e32beba3750c3d38db8fa451e',
    'tools/generate_hia_release_selection.py':
        '3c357d803692ad3ea637a8aca558539a3bc11688deae9cd1ffbe33d45fa9b0d7',
}

POLICY = '''def launch(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 8192:
        return 16
    phase = get(w, 0)
    stage = get(w, 8)
    if phase == 0:
        if stage != 0 or length(o) < 8192:
            return 16
        return arguments(s, o, w)
    if phase == 1:
        if stage != 1 or length(o) < 65536:
            return 16
        return selected_entry(s, o, w)
    if phase == 2:
        if stage != 2 or length(s) != 32:
            return 16
        if get(w, 64) != 63 or get(w, 80) != get(w, 40):
            return 11
        if get(w, 848) != 0 or get(w, 880) != get(w, 40):
            return 10
        if get(w, 856) & 4294967295 != 33088:
            return 10
        if (get(w, 856) >> 32) & 4294967295 != get(w, 88):
            return 10
        i = 0
        while i < 32:
            expected = unhex(byte(w, 128 + i * 2)) * 16 + unhex(byte(w, 129 + i * 2))
            if byte(s, i) != expected:
                return 11
            i = i + 1
        put(w, 8, 3)
        return 0
    if phase == 3:
        if stage != 3 or length(s) != 0:
            return 16
        put(w, 8, 4)
        return 0
    return 16

def arguments(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 48 or length(s) > 8192:
        return 16
    root = uint(s, 0, 8)
    sequence = uint(s, 8, 8)
    release = uint(s, 16, 8)
    name = uint(s, 24, 8)
    digest = uint(s, 32, 8)
    argument = uint(s, 40, 8)
    if root == 0 or root > 4095 or sequence == 0 or sequence > 20:
        return 16
    if release != 64 or digest != 64 or name == 0 or name > 127:
        return 16
    if argument == 0 or argument > 31:
        return 16
    if length(s) != 48 + root + sequence + release + name + digest + argument:
        return 16
    name_at = 48 + root + sequence + release
    digest_at = name_at + name
    argument_at = digest_at + digest
    i = 0
    while i < name:
        v = byte(s, name_at + i)
        if alnum(v) == 0:
            if i == 0 or v != 46 and v != 45 and v != 95:
                return 16
        store(w, 256 + i, v)
        i = i + 1
    store(w, 256 + name, 0)
    i = 0
    while i < 64:
        v = byte(s, digest_at + i)
        if unhex(v) > 15:
            return 16
        store(w, 128 + i, v)
        i = i + 1
    i = 0
    while i < argument:
        v = byte(s, argument_at + i)
        if v == 0:
            return 16
        store(w, 512 + i, v)
        i = i + 1
    store(w, 512 + argument, 0)
    put(w, 16, name)
    put(w, 24, argument)
    write(o, 0, 6, 8)
    write(o, 8, root, 8)
    write(o, 16, sequence, 8)
    write(o, 24, 64, 8)
    write(o, 32, 0, 8)
    write(o, 40, VERIFY_COMMAND, 6)
    i = 0
    while i < root + sequence + 64:
        store(o, 46 + i, byte(s, 48 + i))
        i = i + 1
    put(w, 8, 1)
    return 46 + root + sequence + 64

def selected_entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    count = get(o, 24)
    if count == 0 or count > 256 or get(o, 16) != length(s):
        return 16
    if length(s) < 24 or length(s) > 67108864:
        return 16
    wanted = get(w, 16)
    if wanted == 0 or wanted > 127:
        return 16
    found = 0
    index = 0
    i = 0
    while i < count:
        row = 4096 + i * 96
        name_at = get(o, row)
        name = get(o, row + 8)
        start = get(o, row + 16)
        size = get(o, row + 24)
        if name == 0 or name > 127 or name_at > length(s) or name > length(s) - name_at:
            return 16
        if start > length(s) or size > length(s) - start:
            return 16
        same = 0
        if name == wanted:
            same = 1
            j = 0
            while j < name:
                if byte(s, name_at + j) != byte(w, 256 + j):
                    same = 0
                j = j + 1
        if same == 1:
            if found != 0:
                return 16
            if get(o, row + 32) != 320:
                return 10
            if executable(s, start, size) == 0:
                return 10
            found = 1
            index = i
            put(w, 32, start)
            put(w, 40, size)
        i = i + 1
    if found != 1:
        return 10
    put(w, 48, index)
    put(w, 8, 2)
    return 0

def executable(s:readbuf, start:u64, size:u64) -> u64:
    if size <= 176 or size > 1048576:
        return 0
    if start > length(s) or size > length(s) - start:
        return 0
    ELF_HEADER_CHECKS
    return 1
'''


def policy_source():
    # Same exact canonical ELF profile as qualify_hia_selfhost_cli.inspect_executable.
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
        + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
        + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    checks = []
    for offset in range(0, len(header), 8):
        expected = 'size' if offset in (96, 104) else str(int.from_bytes(header[offset:offset+8], 'little'))
        checks.append(f'if uint(s, start + {offset}, 8) != {expected}:\n        return 0')
    source = POLICY.replace('ELF_HEADER_CHECKS', '\n    '.join(checks))
    source = source.replace('VERIFY_COMMAND', str(int.from_bytes(b'verify', 'little')))
    helpers = installer_source()
    return source + helpers[helpers.index('\ndef decimal('):]


def _replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('selected-launch adapter preimage is not unique: ' + before[:100])
    return text.replace(before, after, 1)


def adapter_source():
    for name, expected in EXPECTED_ADAPTER_INPUTS.items():
        if sha256((ROOT/name).read_bytes()).hexdigest() != expected:
            raise ValueError('reviewed selected-launch dependency changed: ' + name)
    original = selection_adapter()
    new = (ROOT/'tools/hia_release_launch_syscalls.S').read_text()
    marker = '/* @LAUNCH_HELPERS@ */\n'
    if new.count(marker) != 1:
        raise ValueError('selected-launch adapter fragment boundary changed')
    start, helpers = new.split(marker)
    before = original[original.index('_start:\n'):original.index('selection_arity_complete:\n')]
    source = _replace_once(original, before, start)
    source = _replace_once(source, '.equ MAPSIZE,262144', '.equ MAPSIZE,294912\n.equ RUNWORK,262144\n.equ RUNINPUT,270336\n.equ RUNOUT,278528')
    source = _replace_once(source, 'sha_hole, selection_hole\n', 'sha_hole, selection_hole, launch_hole\n')
    source = _replace_once(source, 'stdin_next:\n xor edi,edi\n', 'stdin_next:\n mov edi,3\n')
    source = _replace_once(source,
        ' mov edx,1\n mov eax,10\n syscall\n test rax,rax\n js io_exit\n\nselection_root:\n mov eax,107\n',
        ' mov edx,1\n mov eax,10\n syscall\n test rax,rax\n js io_exit\n'
        ' mov edi,3\n mov eax,3\n syscall\n test rax,rax\n js io_exit\n\nselection_root:\n mov eax,107\n')
    source = _replace_once(source, 'selection_verified_current:\n',
        'selection_verified_current:\n call launch_prepare_image\n')
    source = _replace_once(source,
        ' sgate 20\n sgate 18\n call selection_check_lock_name\n stat_current r14d\n gate 5\n jmp selection_receipt\n',
        ' sgate 20\n sgate 18\n call selection_check_lock_name\n stat_current r14d\n gate 5\n jmp launch_enter\n')
    return source + '\n' + helpers


def template():
    with tempfile.TemporaryDirectory(prefix='hia-release-launch-template-') as folder:
        base = Path(folder)
        assembly, obj, raw = base/'adapter.S', base/'adapter.o', base/'adapter.bin'
        assembly.write_text(adapter_source())
        subprocess.run(['as', '--64', str(assembly), '-o', str(obj)], check=True, capture_output=True)
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(raw)], check=True, capture_output=True)
        symbols = {}
        for line in subprocess.check_output(['nm', '-n', str(obj)], text=True).splitlines():
            address, _, name = line.split()
            symbols[name] = int(address, 16)
        if 'R_X86_64' in subprocess.check_output(['objdump', '-r', str(obj)], text=True):
            raise ValueError('unresolved selected-launch adapter relocation')
        code = raw.read_bytes()
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
        + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
        + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    names = ('policy_initial_hole', 'policy_hole', 'sha_hole', 'selection_hole', 'launch_hole')
    return header + code, {name:176 + symbols[name] for name in names}


def packer_source():
    from tools.generate_hia_native_filter import LINK_SOURCE
    prefix, holes = template()
    source = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 44 or length(s) > 1048576:
        return 4294967295
    if uint(s, 0, 8) != {MAGIC}:
        return 4294967295
    policy = uint(s, 8, 8)
    sha = uint(s, 16, 8)
    selection = uint(s, 24, 8)
    launch = uint(s, 32, 8)
    if policy == 0 or sha == 0 or selection == 0 or launch == 0:
        return 4294967295
    if policy > 1048576 or sha > 1048576 or selection > 1048576 or launch > 1048576:
        return 4294967295
    if length(s) != 40 + policy + sha + selection + launch:
        return 4294967295
    size = {len(prefix)} + policy + sha + selection + launch
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
    # A single prefix emitter exceeded the original 2048-SSA-per-function
    # contract. Keep the byte order and bounds, but use bounded mechanical
    # helpers; neither the compiler limit nor the generated ELF changes.
    helpers = []
    for start in range(0, len(prefix), 512):
        name = f'prefix_{start // 512}'
        source += f'    {name}(o)\n'
        helper = f'\ndef {name}(o:mutbuf) -> u64:\n'
        for at in range(start, min(start + 512, len(prefix)), 8):
            chunk = prefix[at:at+8]
            helper += f'    write(o, {at}, {int.from_bytes(chunk,"little")}, {len(chunk)})\n'
        helpers.append(helper + '    return 0\n')
    source += '    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    for name, offset in holes.items():
        target = str(len(prefix))
        if name in ('sha_hole', 'selection_hole', 'launch_hole'):
            target += ' + policy'
        if name in ('selection_hole', 'launch_hole'):
            target += ' + sha'
        if name == 'launch_hole':
            target += ' + selection'
        source += f'    write(o, {offset}, {target} - {offset+4}, 4)\n'
    source += f'    copy_bytes(s, o, 40, {len(prefix)}, policy + sha + selection + launch)\n    return size\n'
    return source + ''.join(helpers) + LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]


def main():
    for name, source in [('release_launch_policy', policy_source()),
                         ('release_launch_packer', packer_source())]:
        path = ROOT/'examples/hia_bootstrap'/f'{name}.hepta'
        path.write_text(render_assembly(document(source, name)))
        print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
