"""Author HIA relocatable-object templates with a retained assembly oracle."""
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory

from hepta.hia_agent_assembly import render_assembly
from tools.build_hia_sqlite_pager import ROOT, STATIC_OBJECT_LIMIT, STATIC_OBJECT_RECORD, assemble
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_elf_linker import SOURCE as LINK_SOURCE


def render_objects(group, roles):
    selector = [
        'def materialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:',
        '    if length(s) != 8:',
        '        return 0',
        '    role = uint(s, 0, 8)',
    ]
    functions = []
    with TemporaryDirectory(prefix='hia-elf-adapters-') as temporary:
        for name, role, prefix in roles:
            folder = Path(temporary) / str(role)
            folder.mkdir()
            source = (ROOT / name).read_bytes()
            raw = assemble(folder, name, prefix + source)
            if not 0 < len(raw) <= STATIC_OBJECT_LIMIT:
                raise ValueError('static adapter object exceeds the retained template extent')
            record = STATIC_OBJECT_RECORD.pack(sha256(source).digest(), sha256(raw).digest(), len(raw)) + raw
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
