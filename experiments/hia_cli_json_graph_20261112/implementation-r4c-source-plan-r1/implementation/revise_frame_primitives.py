"""Mechanical source edit only; no compiler, project import or runtime call."""
from pathlib import Path
from hashlib import sha1, sha256
import json
import re

BASE = Path('/workspace/scratch/e26ed3e2edcf/native-cli-json-graph-r1')
HERE = BASE / 'implementation-r4c'
INPUTS = HERE / 'inputs'
REFERENCE = BASE / 'implementation-r4b/reference/cpython-v3.12.14/Python/ceval.c'
REFERENCE_SHA = '29640a033f373391a5b000253f74a7a1bc3182265412c0b40a76c4615acd1fda'


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def definition(source, signature):
    """Match an exact signature followed by a body, never a declaration."""
    # The exact signature also occurs in the forward declaration. Require
    # its opening brace in the search itself, before selecting an offset.
    token = signature + '\n{'
    if source.count(token) != 1:
        raise ValueError('exactly one actual fixed function definition required')
    start = source.index(token)
    body = start + len(signature)
    if not source[body:].startswith('\n{'):
        raise ValueError('fixed definition signature must end immediately before its body')
    index, depth, mode = body + 1, 0, 'code'
    while index < len(source):
        char = source[index]
        following = source[index:index + 2]
        if mode == 'line':
            if char == '\n': mode = 'code'
        elif mode == 'comment':
            if following == '*/': mode = 'code'; index += 1
        elif mode in ('string', 'character'):
            if char == '\\': index += 1
            elif char == ('"' if mode == 'string' else "'"): mode = 'code'
        elif following == '//': mode = 'line'; index += 1
        elif following == '/*': mode = 'comment'; index += 1
        elif char == '"': mode = 'string'
        elif char == "'": mode = 'character'
        elif char == '{': depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0: return source[start:index + 1] + '\n'
        index += 1
    raise ValueError('unterminated fixed C definition')


def main():
    original = REFERENCE.read_bytes()
    if sha256(original).hexdigest() != REFERENCE_SHA:
        raise ValueError('official ceval source differs')
    source = original.decode()
    signature = ('static _PyInterpreterFrame *\n'
                 '_PyEvalFramePushAndInit(PyThreadState *tstate, PyFunctionObject *func,\n'
                 '                        PyObject *locals, PyObject* const* args,\n'
                 '                        size_t argcount, PyObject *kwnames)')
    body = definition(source, signature)
    substitutions = {
        '_PyEvalFramePushAndInit': 'cj312_push_and_init',
        '_PyThreadState_PushFrame': 'cj312_runtime.push_frame',
        'initialize_locals': 'cj312_initialize_locals',
        'clear_thread_frame': 'cj312_clear_thread_frame',
    }
    revised = re.sub(r'\b(' + '|'.join(map(re.escape, substitutions)) + r')\b',
                     lambda match: substitutions[match.group()], body)
    path = INPUTS / 'hepta/hia_cli_json_cpython312_call.inc'
    old_include = path.read_bytes()
    text = old_include.decode()
    start = text.index('static _PyInterpreterFrame *\ncj312_push_and_init(')
    old_tail = text[start:]
    if not old_tail.endswith('return interp->ceval.recursion_limit;\n}\n\n'):
        raise ValueError('expected historical declaration-extraction defect differs')
    if '{' in old_tail[:old_tail.index('Py_GetRecursionLimit(void)')]:
        raise ValueError('unexpected historical function body before unrelated export')
    new_include = (text[:start] + revised).encode()
    cpath = INPUTS / 'hepta/hia_cli_json_cpython.c'
    old_c = cpath.read_bytes()
    ctext = old_c.decode()
    old_gate = 'frame->op > CJ_PY312_FRAME_LOAD'
    if ctext.count(old_gate) != 1: raise ValueError('old leaf range differs')
    ctext = ctext.replace(old_gate, 'frame->op > CJ_PY312_STACK_COPY')
    old_clear = 'if (!cj312_runtime.ready || !a || !PyGen_CheckExact(a) || ctx->slot)\n            goto abi_error;'
    if ctext.count(old_clear) != 1: raise ValueError('old frame clear predicate differs')
    ctext = ctext.replace(old_clear,
        '/* A normal owned return value remains in ctx->slot across frame\n'
        '         * clearing, exactly as the evaluator retains retval. HIA drops\n'
        '         * its None only after this leaf and before gi_exc_state. */\n'
        '        if (!cj312_runtime.ready || !a || !PyGen_CheckExact(a))\n'
        '            goto abi_error;')
    new_c = ctext.encode()
    history = HERE / 'history/initial-frame-wip'
    history.mkdir(parents=True, exist_ok=False)
    records = {}
    for item in sorted(INPUTS.rglob('*')):
        if item.is_file():
            rel = item.relative_to(INPUTS)
            dest = history / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            raw = item.read_bytes()
            with dest.open('xb') as out: out.write(raw)
            records[str(rel)] = pin(raw)
    path.write_bytes(new_include)
    cpath.write_bytes(new_c)
    if new_include[:start] != old_include[:start]:
        raise ValueError('the six preceding runtime helper bodies changed')
    if 'Py_GetRecursionLimit(' in new_include.decode():
        raise ValueError('unintended runtime export retained')
    receipt = {
        'schema': 'hia.cli-json.r4c.frame-source-revision.v1',
        'status': 'MECHANICAL_SOURCE_EDITS_ONLY',
        'historical_wip': records,
        'official_reference': {'path': str(REFERENCE), **pin(original)},
        'definition': {'name': '_PyEvalFramePushAndInit', **pin(body.encode())},
        'definition_substitutions': substitutions,
        'six_preceding_helper_bytes_unchanged': True,
        'removed_unintended_export': 'Py_GetRecursionLimit',
        'leaf_range': {'before': 99, 'after': 112},
        'normal_owned_return_slot_retained_across_frame_clear': True,
        'modified': {'hepta/hia_cli_json_cpython312_call.inc': pin(new_include),
                     'hepta/hia_cli_json_cpython.c': pin(new_c)},
        'source_authoring_executed': False,
        'c_parsed_or_compiled': False,
        'native_executed': False,
        'full_generator_or_cli_equivalence_claimed': False,
    }
    with (HERE / 'FRAME-SOURCE-CORRECTION.json').open('x') as out:
        out.write(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'status': receipt['status'], 'modified': receipt['modified']}))


if __name__ == '__main__':
    main()
