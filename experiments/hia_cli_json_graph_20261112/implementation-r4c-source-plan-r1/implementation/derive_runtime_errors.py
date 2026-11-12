"""Static text extraction only; never imports or executes project code."""
from hashlib import sha256, sha1
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def function(text, signature):
    needle = signature + '\n{'
    if text.count(needle) != 1:
        raise ValueError('exact definition is absent or ambiguous')
    start = text.index(needle)
    at = start + len(signature) + 1
    depth = 0
    state = 'code'
    while at < len(text):
        char = text[at]
        pair = text[at:at + 2]
        if state == 'code':
            if pair == '/*':
                state = 'comment'; at += 2; continue
            if pair == '//':
                state = 'line'; at += 2; continue
            if char in ('"', "'"):
                state = char
            elif char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    return text[start:at + 1]
        elif state == 'comment' and pair == '*/':
            state = 'code'; at += 2; continue
        elif state == 'line' and char == '\n':
            state = 'code'
        elif state in ('"', "'"):
            if char == '\\':
                at += 2; continue
            if char == state:
                state = 'code'
        at += 1
    raise ValueError('unterminated C definition')


def pin(path, raw):
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def main():
    specs = (
        (ROOT.parent/'implementation-r4b/reference/cpython-v3.12.14/Python/ceval.c',
         'static int\ndo_raise(PyThreadState *tstate, PyObject *exc, PyObject *cause)',
         'do_raise', 'cj312_do_raise'),
        (ROOT/'reference/cpython-v3.12.14/Python/intrinsics.c',
         'static PyObject *\nstopiteration_error(PyThreadState* tstate, PyObject *exc)',
         'stopiteration_error', 'cj312_stopiteration_error'),
    )
    pieces = []
    records = []
    for path, signature, original_name, local_name in specs:
        raw = path.read_bytes()
        original = function(raw.decode('utf-8'), signature)
        if original.count(original_name + '(') != 1:
            raise ValueError('function identifier substitution is not singular')
        changed = original.replace(original_name + '(', local_name + '(', 1)
        if changed.replace(local_name + '(', original_name + '(', 1) != original:
            raise ValueError('function inverse differs')
        pieces.append(changed)
        records.append({'source': pin(path, raw), 'original_name': original_name,
                        'local_name': local_name,
                        'original_body_sha256': sha256(original.encode()).hexdigest(),
                        'changed_body_sha256': sha256(changed.encode()).hexdigest(),
                        'identifier_substitutions': 1, 'inverse_full_bytes_equal': True})
    output = ROOT/'inputs/hepta/hia_cli_json_cpython312_errors.inc'
    raw = ('/* Exact CPython v3.12.14 runtime error helpers. PSF License.\n'
           ' * Source/whole-body inverse pins: RUNTIME-ERRORS-DERIVATION.json.\n'
           ' * Only two local function identifiers change. No JSON traversal,\n'
           ' * message selection, normalization or lifetime body is rewritten.\n'
           ' * Private development ABI; not compiled or executed.\n */\n\n' +
           '\n\n'.join(pieces) + '\n').encode()
    with output.open('xb') as stream:
        stream.write(raw)
    report = {'schema': 'hia.cli-json.r4c.runtime-error-static-derivation.v1',
              'status': 'STATIC_TEXT_ONLY', 'functions': records,
              'output': pin(output, raw), 'native_executed': False,
              'generator_executed': False, 'c_compiler_executed': False}
    with (ROOT/'RUNTIME-ERRORS-DERIVATION.json').open('x') as stream:
        json.dump(report, stream, indent=2); stream.write('\n')
    print(json.dumps({'status': report['status'], 'output': report['output']}))


if __name__ == '__main__':
    main()
