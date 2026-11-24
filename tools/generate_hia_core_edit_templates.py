"""Regenerate the source-bound HIA records for fixed Linux Core adapters."""

from hashlib import sha256
from pathlib import Path
import struct
import re
from tempfile import TemporaryDirectory

from hepta.hia_agent_assembly import render_assembly
from tools.build_hia_agent_batch_commit import assemble_adapter
from tools.build_hia_core_edit import (
    ADAPTER_RECORD, NOMINAL_ADAPTER, NOMINAL_ADAPTER_ROLES, NOMINAL_BUILD_GROUP, NOMINAL_TEMPLATE_GROUPS,
    REGISTER_RELAY, ROOT, STATIC_ADAPTER_ROLES, STATIC_ADAPTERS, STATIC_RELOCATIONS,
    expand_register_relay,
)
from tools.generate_hia_relocatable_templates import render_objects, assemble
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_elf_linker import SOURCE as LINK_SOURCE


def read_adapter_source(name):
    return expand_register_relay((ROOT / name).read_bytes(), (ROOT / REGISTER_RELAY).read_bytes())


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
            source = read_adapter_source(name)
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
    roles = ((name, role, b'.set HIA_NOMINAL_BUILD,1\n' if name == NOMINAL_ADAPTER else b'')
             for name, (path, role) in NOMINAL_ADAPTER_ROLES.items() if path == group)
    constructor = group == NOMINAL_ADAPTER_ROLES[NOMINAL_ADAPTER][0]
    return render_objects(group, roles, read_source=read_adapter_source,
                          zero_fill=group == NOMINAL_BUILD_GROUP or constructor,
                          literal_words=4 if constructor else 2)


def refresh_nominal_constructor_pin():
    """Bind the existing native policy to the current exact source/object pair.

    The role-15 predicate and both complete SHA comparisons are preserved.
    This materializes only eight digest words; no acceptance rule is changed.
    """
    path = ROOT / 'examples/hia_bootstrap/source_core_edit_link.hepta'
    policy = path.read_text()
    start = policy.index('fn pin_3(')
    end = policy.index('\nfn ', start + 1)
    block = policy[start:end]
    source = read_adapter_source(NOMINAL_ADAPTER)
    with TemporaryDirectory(prefix='hia-nominal-policy-pin-') as temporary:
        raw = assemble(Path(temporary), NOMINAL_ADAPTER, b'.set HIA_NOMINAL_BUILD,1\n' + source)
    words = struct.unpack('<8Q', sha256(source).digest() + sha256(raw).digest())
    for name, word in zip(('v28', 'v34', 'v41', 'v48', 'v79', 'v85', 'v92', 'v99'), words):
        expression = r'(' + name + r':u64 = const\(\) \{"value":)\d+(\})'
        block, count = re.subn(expression, lambda match: match[1] + str(word) + match[2], block)
        if count != 1:
            raise ValueError('nominal constructor digest word layout changed: ' + name)
    path.write_text(policy[:start] + block + policy[end:])


if __name__ == '__main__':
    for group in STATIC_ADAPTERS:
        (ROOT / group).write_text(render(group))
    for group in NOMINAL_TEMPLATE_GROUPS:
        (ROOT / group).write_text(render_nominal(group))
    refresh_nominal_constructor_pin()
