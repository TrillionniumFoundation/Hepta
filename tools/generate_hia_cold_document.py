"""Development-only author for the explicit HIA v9 cold control profile."""
import ast

from tools.generate_hia_selfhost import Builder, total_scalar_functions, compact_authoring_cfg


def document(source, module, *, builder_type=Builder):
    nodes = ast.parse(source).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    sigs = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
            for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = builder_type(node, names, sigs, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name],
                          'params': [builder.param(p) for p in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v9',
                                  'module': module, 'functions': functions})


class BulkBuilder(Builder):
    """Explicit separate resource-10 author profile; original Builder is intact."""
    def expr(self, expression):
        if (isinstance(expression, ast.Call)
                and isinstance(expression.func, ast.Name)
                and expression.func.id == 'move_within'):
            args = [self.expr(value) for value in expression.args]
            assert len(args) == 4 and args[0][1] == 'mutbuf'
            return self.op('buffer.move_within', [args[0],
                *(self.cast(value, 'usize') for value in args[1:])])
        return super().expr(expression)


def bulk_document(source, module):
    return document(source, module, builder_type=BulkBuilder)


class BulkWordBuilder(BulkBuilder):
    """Explicit resource-10 plus resource-26 author; parent profiles intact."""
    def expr(self, expression):
        if (isinstance(expression, ast.Call)
                and isinstance(expression.func, ast.Name)
                and expression.func.id == 'word_store'):
            args = [self.expr(value) for value in expression.args]
            assert len(args) == 3 and args[0][1] == 'mutbuf'
            return self.op('buffer.store.u64.le', [args[0],
                self.cast(args[1], 'usize'), self.cast(args[2], 'u64')])
        return super().expr(expression)


def bulk_word_document(source, module):
    return document(source, module, builder_type=BulkWordBuilder)
