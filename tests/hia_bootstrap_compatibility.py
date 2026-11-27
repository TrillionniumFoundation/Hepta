"""Execute only the five frozen source bodies and public historical wrappers.

This is a separately labelled compatibility observation. Current public options
and retained-program admission are observed through the current code elsewhere.
"""
from __future__ import annotations
import ast
from hashlib import sha256
from types import FunctionType
from tools import hia_bootstrap_source_history as history

def functions(root, namespace, api):
    historical, proof, saved = history.capture(root)
    proof.update(history.graph_bindings(saved[history.SOURCE], historical))
    tree = ast.parse(historical)
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)
               and node.name == 'HIAAgentService']
    if len(classes) != 1:
        raise ValueError('historical Bootstrap source class is not unique')
    methods = [node for node in classes[0].body if isinstance(node, ast.FunctionDef)
               and node.name in history.METHODS]
    wrappers = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                and node.name in {'_service_bootstrap_dispatch_' + name for name in history.METHODS}]
    if len(methods) != 5 or len(wrappers) != 5:
        raise ValueError('historical Bootstrap complete definition set differs')
    cls = ast.ClassDef(name='HIAAgentService', bases=[], keywords=[], body=methods, decorator_list=[])
    ast.copy_location(cls, classes[0])
    selected = ast.Module(body=[cls, *wrappers], type_ignores=[])
    ast.fix_missing_locations(selected)
    missing = object()
    previous = namespace.get('HIAAgentService', missing)
    exec(compile(selected, str(root / history.SOURCE), 'exec'), namespace)
    retained_class = namespace['HIAAgentService']
    retained = {mode: vars(retained_class)[name] for mode, name in enumerate(history.METHODS, 1)}
    public = {name: namespace['_service_bootstrap_dispatch_' + name] for name in history.METHODS}
    if previous is missing:
        del namespace['HIAAgentService']
    else:
        namespace['HIAAgentService'] = previous
    for mode, name in enumerate(history.METHODS, 1):
        for function in (retained[mode], public[name]):
            if (type(function) is not FunctionType or function.__globals__ is not namespace
                    or function.__builtins__ is not namespace['__builtins__']):
                raise ValueError('historical Bootstrap explicit namespace differs')
        if (sha256(retained[mode].__code__.co_code).hexdigest()
                != proof['historical_code']['retained'][name]
                or sha256(public[name].__code__.co_code).hexdigest()
                != proof['historical_code']['public'][name]):
            raise ValueError('historical Bootstrap actual code differs from source')
    for mode, name in enumerate(history.METHODS, 1):
        if (history.complete_code_digest(retained[mode].__code__)
                != proof['historical_code']['retained_complete'][name]
                or history.complete_code_digest(public[name].__code__)
                != proof['historical_code']['public_complete'][name]):
            raise ValueError('historical Bootstrap complete runtime code differs from source')
    # Live import ports retain their exact, independently checked current code.
    if len(api._SERVICE_BOOTSTRAP_IMPORT_PORTS) != proof['import_port_count']:
        raise ValueError('historical Bootstrap current import-port set differs')
    history.unchanged(root, saved)
    return retained, public, proof, saved
