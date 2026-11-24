"""Author HIA relocatable-object templates with a retained assembly oracle."""
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory

from hepta.hia_agent_assembly import render_assembly
from tools.build_hia_sqlite_pager import ROOT, STATIC_OBJECT_LIMIT, STATIC_OBJECT_RECORD, assemble
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_elf_linker import SOURCE as LINK_SOURCE


def render_objects(group, roles, record_slice=slice(None), *, read_source=None, zero_fill=False, literal_words=2):
    if literal_words not in (2, 4):
        raise ValueError("unsupported literal grouping")
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
            source = (ROOT / name).read_bytes() if read_source is None else read_source(name)
            raw = assemble(folder, name, prefix + source)
            if not 0 < len(raw) <= STATIC_OBJECT_LIMIT:
                raise ValueError('static adapter object exceeds the retained template extent')
            record = (STATIC_OBJECT_RECORD.pack(sha256(source).digest(), sha256(raw).digest(), len(raw)) + raw)[record_slice]
            if not record:
                raise ValueError('static adapter has an empty template part')
            selector.extend((f'    if role == {role}:', f'        return adapter_{role}(o)'))
            functions.extend(('', f'def adapter_{role}(o:mutbuf) -> u32:',
                              f'    if length(o) < {len(record)}:', '        return 0'))
            if zero_fill:
                functions.extend(('    i = 0', f'    while i < {len(record)}:',
                                  '        store(o, i, 0)', '        i = i + 1'))
            chunks = []
            for start in range(0, len(record), 1024):
                chunk = f'copy_{role}_{start}'
                functions.append(f'    {chunk}(o)')
                chunks.extend(('', f'def {chunk}(o:mutbuf) -> u64:'))
                stop = min(start + 1024, len(record))
                at = start
                while at < stop:
                    part = record[at:at + 8]
                    word = int.from_bytes(part, 'little')
                    next_part = record[at + 8:min(at + 16, stop)]
                    quartet = record[at:min(at + 32, stop)]
                    if (zero_fill and literal_words == 4 and len(quartet) == 32
                            and all(any(quartet[index:index + 8]) for index in range(0, 32, 8))):
                        words = [int.from_bytes(quartet[index:index + 8], 'little') for index in range(0, 32, 8)]
                        chunks.append(f'    write_quad(o, {at}, ' + ', '.join(map(str, words)) + ')')
                        at += 32
                    elif zero_fill and word and len(next_part) == 8 and any(next_part):
                        # Adjacent literals share a single position in the HIA instruction stream.
                        other = int.from_bytes(next_part, 'little')
                        chunks.append(f'    write_pair(o, {at}, {word}, {other})')
                        at += 16
                    else:
                        if word or not zero_fill:
                            chunks.append(f'    write(o, {at}, {word}, {len(part)})')
                        at += len(part)
                chunks.append('    return 0')
            functions.append(f'    return {len(record)}')
            functions.extend(chunks)
    selector.append('    return 0')
    if zero_fill:
        functions.extend(('', 'def write_pair(o:mutbuf, at:u64, first:u64, second:u64) -> u64:',
                          '    write(o, at, first, 8)', '    write(o, at + 8, second, 8)', '    return 0'))
    if zero_fill and literal_words == 4:
        functions.extend(('', 'def write_quad(o:mutbuf, at:u64, a:u64, b:u64, c:u64, d:u64) -> u64:',
                          '    write(o, at, a, 8)', '    write(o, at + 8, b, 8)',
                          '    write(o, at + 16, c, 8)', '    write(o, at + 24, d, 8)', '    return 0'))
    helpers = LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]
    return render_assembly(document('\n'.join(selector + functions) + helpers, Path(group).stem))
