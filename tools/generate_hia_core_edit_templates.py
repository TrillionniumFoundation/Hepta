"""Regenerate the source-bound HIA records for fixed Linux Core adapters."""

from hashlib import sha256
from pathlib import Path
import struct
from tempfile import TemporaryDirectory

from hepta.hia_agent_assembly import render_assembly
from tools.build_hia_agent_batch_commit import assemble_adapter
from tools.build_hia_core_edit import (
    ADAPTER_RECORD, NOMINAL_ADAPTER_GROUPS, NOMINAL_ADAPTER_ROLES, NOMINAL_OBJECT_LIMIT,
    NOMINAL_OBJECT_RECORD, ROOT, STATIC_ADAPTER_ROLES, STATIC_ADAPTERS, STATIC_RELOCATIONS,
)
from tools.build_hia_sqlite_pager import assemble
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_elf_linker import SOURCE as LINK_SOURCE


def render(group):
    selector = [
        'def materialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:',
        '    if length(s) != 8:',
        '        return 0',
        '    role = uint(s, 0, 8)',
    ]
    functions = []
    with TemporaryDirectory(prefix='hia-core-adapters-') as temporary:
        for name, (path, role) in STATIC_ADAPTER_ROLES.items():
            if path != group:
                continue
            relocations = STATIC_RELOCATIONS[name]
            folder = Path(temporary) / str(role)
            folder.mkdir()
            source = (ROOT / name).read_bytes()
            stub, symbols, identity = assemble_adapter(folder, name, source)
            offsets = [symbols[call + '_hole'] for call, _target in relocations]
            record = ADAPTER_RECORD.pack(sha256(source).digest(), sha256(stub).digest(),
                                         bytes.fromhex(identity), len(stub), len(offsets))
            record += struct.pack(f'<{len(offsets)}Q', *offsets) + stub
            selector.extend((f'    if role == {role}:', f'        return adapter_{role}(o)'))
            functions.extend(('', f'def adapter_{role}(o:mutbuf) -> u32:',
                              f'    if length(o) < {len(record)}:', '        return 0'))
            for at in range(0, len(record), 8):
                part = record[at:at + 8]
                functions.append(f'    write(o, {at}, {int.from_bytes(part, "little")}, {len(part)})')
            functions.append(f'    return {len(record)}')
    selector.append('    return 0')
    helpers = LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]
    return render_assembly(document('\n'.join(selector + functions) + helpers, Path(group).stem))


def render_nominal(group):
    selector = [
        'def materialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:',
        '    if length(s) != 8:',
        '        return 0',
        '    role = uint(s, 0, 8)',
    ]
    functions = []
    with TemporaryDirectory(prefix='hia-core-nominal-adapters-') as temporary:
        for name, (path, role) in NOMINAL_ADAPTER_ROLES.items():
            if path != group:
                continue
            folder = Path(temporary) / str(role)
            folder.mkdir()
            source = (ROOT / name).read_bytes()
            raw = assemble(folder, name, source)
            if not 0 < len(raw) <= NOMINAL_OBJECT_LIMIT:
                raise ValueError('fixed nominal adapter object exceeds the retained template extent')
            record = NOMINAL_OBJECT_RECORD.pack(sha256(source).digest(), sha256(raw).digest(), len(raw)) + raw
            selector.extend((f'    if role == {role}:', f'        return adapter_{role}(o)'))
            functions.extend(('', f'def adapter_{role}(o:mutbuf) -> u32:',
                              f'    if length(o) < {len(record)}:', '        return 0'))
            chunks = []
            for start in range(0, len(record), 1024):
                chunk = f'copy_{role}_{start}'
                functions.append(f'    {chunk}(o)')
                chunks.extend(('', f'def {chunk}(o:mutbuf) -> u64:'))
                for at in range(start, min(start + 1024, len(record)), 8):
                    part = record[at:at + 8]
                    chunks.append(f'    write(o, {at}, {int.from_bytes(part, "little")}, {len(part)})')
                chunks.append('    return 0')
            functions.append(f'    return {len(record)}')
            functions.extend(chunks)
    selector.append('    return 0')
    helpers = LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]
    return render_assembly(document('\n'.join(selector + functions) + helpers, Path(group).stem))


if __name__ == '__main__':
    for group in STATIC_ADAPTERS:
        (ROOT / group).write_text(render(group))
    for group in NOMINAL_ADAPTER_GROUPS:
        (ROOT / group).write_text(render_nominal(group))
