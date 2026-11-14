"""Test-only pure HIA packer: observe real BSS after the unchanged HIA return.

The production ELF is never patched. This separately compiled HIA packer emits
the same startup, controller, and fixed residents, followed by three write-all
loops to the test's inherited fds 29..31. Those high fds leave actual file fd3
available. There is no host-created startup capability or arbitrary call target.
"""
import ast
import copy
import hashlib
import types
from tools import generate_hia_linux_file_roundtrip_entry as original
from hepta.hia_agent_assembly import render_assembly

DUMPS = ((29, 0x602000, 8388609), (30, 0xe03000, 1048576), (31, 0xf03000, 1048576))


def source_program():
    tree = ast.parse(original.source_program())
    old = copy.deepcopy(tree)
    startup = next(node for node in tree.body if node.name == 'startup')
    marker = 'at = instruction(o, at, 51081, 2)'
    places = [i for i, node in enumerate(startup.body) if ast.unparse(node) == marker]
    assert len(places) == 1
    # r12d saves the actual controller's eax. syscall clobbers rcx/r11 only.
    lines = ['at = instruction(o, at, 12880193, 3)']  # 41 89 c4
    for i, (fd, address, extent) in enumerate(DUMPS):
        lines.extend([
            f'at = register32(o, at, 7, {fd})',
            f'at = register32(o, at, 6, {address})',
            f'at = register32(o, at, 2, {extent})',
            f'observe_loop_{i} = at',
            'at = register32(o, at, 0, 1)',
            'at = instruction(o, at, 1295, 2)',  # syscall
            f'at = instruction(o, at, {int.from_bytes(bytes.fromhex("4883f8fc"), "little")}, 4)',
            f'observe_retry_{i} = branch(o, at, 132)',
            f'at = observe_retry_{i} + 4',
            f'patch(o, observe_retry_{i}, observe_loop_{i})',
            'at = instruction(o, at, 12617032, 3)',  # test rax,rax:48 85 c0
            f'observe_fail_{i} = branch(o, at, 142)',
            f'at = observe_fail_{i} + 4',
            'at = instruction(o, at, 12976456, 3)',  # add rsi,rax:48 01 c6
            'at = instruction(o, at, 12724552, 3)',  # sub rdx,rax:48 29 c2
            f'observe_more_{i} = branch(o, at, 133)',
            f'at = observe_more_{i} + 4',
            f'patch(o, observe_more_{i}, observe_loop_{i})',
        ])
    lines.append('at = instruction(o, at, 14715204, 3)')  # 44 89 e0
    inserted = ast.parse('\n'.join(lines)).body
    startup.body[places[0]:places[0]] = inserted
    fail_at = [i for i, node in enumerate(startup.body) if ast.unparse(node) == 'patch(o, fail1, at)']
    assert len(fail_at) == 1
    patches = ast.parse('\n'.join(f'patch(o, observe_fail_{i}, at)' for i in range(3))).body
    startup.body[fail_at[0]:fail_at[0]] = patches
    inverse = copy.deepcopy(tree)
    restored = next(node for node in inverse.body if node.name == 'startup')
    del restored.body[fail_at[0]:fail_at[0] + len(patches)]
    del restored.body[places[0]:places[0] + len(inserted)]
    assert ast.dump(inverse, include_attributes=False) == ast.dump(old, include_attributes=False)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree) + '\n'


def document():
    # Execute the existing pure author body with only the explicit source AST
    # projection. All original guards, layout, packing, and type checks remain.
    namespace = dict(vars(original.original), source_program=source_program)
    result = types.FunctionType(original.original.document.__code__, namespace)()
    result['module'] = 'linux_file_roundtrip_postreturn_observer'
    return result


def generated():
    return render_assembly(document()).encode()
