"""Author the HIA decoder for the fixed-Huffman and stored blocks emitted by release_deflate."""
import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_cli_argument_transport import source_program


def fixed_functions():
    source = source_program()
    functions = {fn.name: fn for fn in ast.parse(source).body}
    body = ast.get_source_segment(source, functions['inflate'])
    dispatch = ('            if kind == 1:\n                fixed(w)\n'
                '            elif dynamic(s, w) == 4294967293:\n                return 4294967293\n')
    if body.count('header >= 6') != 1 or body.count(dispatch) != 1:
        raise ValueError('the release block decoder no longer has the expected dispatch')
    body = body.replace('header >= 6', 'header >= 4').replace(dispatch, '            fixed(w)\n')
    functions['inflate'] = ast.parse(body).body[0]

    reachable = {'inflate'}
    pending = ['inflate']
    while pending:
        function = functions[pending.pop()]
        for node in ast.walk(function):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            name = node.func.id
            if name in functions and name not in reachable:
                reachable.add(name)
                pending.append(name)
    return [fn for name, fn in functions.items() if name in reachable]


def render():
    header = ('def expand(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n'
              '    if length(w) != 4096:\n        return 4294967293\n'
              '    return inflate(s, o, w)\n')
    source = header + '\n\n'.join(ast.unparse(fn) for fn in fixed_functions())
    return render_assembly(document(source, 'release_fixed_inflate'))


if __name__ == '__main__':
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/core_cli/release_fixed_inflate.hepta'
    path.write_text(render())
