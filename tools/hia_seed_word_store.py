"""Exact v1-family AST extension for the original resource-26 word store."""
import ast


def add_word_store(source, *, expected_entry, new_entry):
    """Add only LE word-store admission, whole-range guard and store emission.

    The parent must still have the exact original byte-store admission,
    word-load width check and byte-store leaf. Unrelated branches, including
    division and bulk fill/move, remain untouched. Reapplication is refused.
    """
    tree = ast.parse(source)
    counts = {'entry': 0, 'admit': 0, 'width': 0, 'write': 0}
    admission = ast.parse('if inputs != 3 or outputs != 0 or kind != 4:\n    return 0').body
    width = ast.parse('immediate(o,w,11,8)\nenc(o,w,14,2,11,0,0,0)\nfailure(o,w,2)').body
    byte_store = ast.parse('value_load(o,w,2,word(s,inputs+16))\nenc(o,w,8,2,0,0,0,0)\nreturn 0').body
    def require(actual, expected, label):
        if [ast.dump(node) for node in actual] != [ast.dump(node) for node in expected]:
            raise ValueError(('seed word-store parent shape differs', label))
    for function in tree.body:
        if not isinstance(function, ast.FunctionDef):
            raise ValueError('seed word-store parent contains non-function')
        if function.name == expected_entry:
            function.name = new_entry
            counts['entry'] += 1
        elif function.name == new_entry:
            raise ValueError('seed word-store destination entry already exists')
        if function.name == 'resource_admit':
            for node in ast.walk(function):
                if isinstance(node, ast.If) and ast.unparse(node.test) == 'op == 5':
                    require(node.body, admission, 'admission')
                    node.test = ast.parse('op == 5 or op == 26', mode='eval').body
                    counts['admit'] += 1
        if function.name == 'resource':
            for node in list(ast.walk(function)):
                if isinstance(node, ast.If) and ast.unparse(node.test) == 'code == 24':
                    if any(isinstance(item, ast.Expr)
                           and isinstance(item.value, ast.Call)
                           and isinstance(item.value.func, ast.Name)
                           and item.value.func.id == 'immediate' for item in node.body):
                        require(node.body, width, 'width')
                        node.test = ast.parse('code == 24 or code == 26', mode='eval').body
                        counts['width'] += 1
                if isinstance(node, ast.If) and ast.unparse(node.test) == 'code == 5':
                    require(node.body, byte_store, 'byte-store')
                    word = ast.parse('if code == 26:\n'
                        '    value_load(o,w,2,word(s,inputs+16))\n'
                        '    save(o,w,2,0,0)\n'
                        '    return 0').body[0]
                    word.orelse = [ast.If(test=node.test, body=node.body, orelse=node.orelse)]
                    node.test, node.body, node.orelse = word.test, word.body, word.orelse
                    counts['write'] += 1
    if counts != {'entry': 1, 'admit': 1, 'width': 1, 'write': 1}:
        raise ValueError(('seed word-store parent shape differs', counts))
    return ast.unparse(ast.fix_missing_locations(tree)) + '\n'
