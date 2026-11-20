"""Author the single-image ELF package for HIA's primitive Core commands."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document as publication_document
from tools.generate_hia_core_admission_cli import ARENA_BYTES, INSPECT_OUTPUT_BYTES
from tools.generate_hia_native_filter import LINK_SOURCE, template

SUITE_MAGIC = int.from_bytes(b'HIACS001', 'little')


def document(source, module):
    program = publication_document(source, module)
    if module == 'core_suite_dispatch':
        program['schema'] = 'hepta.hia.program.v9'
    return program


def dispatcher_source():
    source = '''def dispatch(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
'''
    for action, mode in (('verify', 1), ('normalize', 2), ('inspect', 3), ('verify-report', 4)):
        source += f'    if length(s) == {len(action)}:\n'
        match = ' and '.join(f'byte(s, {i}) == {value}'
                             for i, value in enumerate(action.encode('ascii')))
        source += f'        if {match}:\n            return {mode}\n'
    return source + '    return 0\n'


def packer_source():
    prefix, calls = template(output_bytes=INSPECT_OUTPUT_BYTES, workspace_bytes=ARENA_BYTES,
                             suite=True)
    source = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 44 or length(s) > 1048576 or uint(s, 0, 8) != {SUITE_MAGIC}:
        return 4294967295
    dispatch = uint(s, 8, 8)
    admission = uint(s, 16, 8)
    normalize = uint(s, 24, 8)
    inspect = uint(s, 32, 8)
    payload = length(s) - 40
    remaining = payload
    if dispatch == 0 or dispatch >= remaining:
        return 4294967295
    remaining = remaining - dispatch
    if admission == 0 or admission >= remaining:
        return 4294967295
    remaining = remaining - admission
    if normalize == 0 or normalize >= remaining or inspect != remaining - normalize:
        return 4294967295
    size = {len(prefix)} + payload
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
    for offset in range(0, len(prefix), 8):
        chunk = prefix[offset:offset + 8]
        source += f'    write(o, {offset}, {int.from_bytes(chunk, "little")}, {len(chunk)})\n'
    source += '    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    for call, offset in zip(calls, ('0', 'dispatch', 'dispatch + admission',
                                   'dispatch + admission + normalize'), strict=True):
        source += f'    write(o, {call}, {len(prefix) - call - 4} + {offset}, 4)\n'
    source += f'    copy_bytes(s, o, 40, {len(prefix)}, payload)\n    return size\n'
    return source + LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]


def main():
    folder = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap'
    for name, source in (('core_suite_dispatch', dispatcher_source()),
                         ('core_suite_packer', packer_source())):
        (folder / (name + '.hepta')).write_text(render_assembly(document(source, name)))


if __name__ == '__main__':
    main()
