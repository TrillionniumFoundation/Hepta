"""Development-only author for the explicit HIA v9 cold control profile."""
import ast

from tools.generate_hia_selfhost import Builder, total_scalar_functions, compact_authoring_cfg


def document(source, module):
    nodes = ast.parse(source).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    sigs = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
            for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, sigs, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name],
                          'params': [builder.param(p) for p in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v9',
                                  'module': module, 'functions': functions})
