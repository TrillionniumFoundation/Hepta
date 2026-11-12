"""Static, inverse-checked extraction of two original runtime name diagnostics."""
from hashlib import sha256
import json
from pathlib import Path
from derive_runtime_errors import function, pin

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT.parent/'implementation-r4b/reference/cpython-v3.12.14/Python/ceval.c'
SPECS = (
    'static void\nformat_exc_check_arg(PyThreadState *tstate, PyObject *exc,\n'
    '                     const char *format_str, PyObject *obj)',
    'static void\nformat_exc_unbound(PyThreadState *tstate, PyCodeObject *co, int oparg)',
)
REPLACE = (
    ('format_exc_check_arg', 'cj312_format_exc_check_arg'),
    ('format_exc_unbound', 'cj312_format_exc_unbound'),
    ('UNBOUNDLOCAL_ERROR_MSG', 'CJ312_UNBOUNDLOCAL_ERROR_MSG'),
    ('UNBOUNDFREE_ERROR_MSG', 'CJ312_UNBOUNDFREE_ERROR_MSG'),
)


def main():
    raw = SOURCE.read_bytes()
    text = raw.decode()
    macro_start = text.index('#define UNBOUNDLOCAL_ERROR_MSG \\\n')
    macro_end = text.index('\n\n', macro_start)
    original_parts = [text[macro_start:macro_end]] + [function(text, signature) for signature in SPECS]
    records, parts = [], []
    for original in original_parts:
        changed = original
        for before, after in REPLACE:
            changed = changed.replace(before, after)
        inverse = changed
        for before, after in reversed(REPLACE):
            inverse = inverse.replace(after, before)
        if inverse != original:
            raise ValueError('runtime diagnostic inverse differs')
        parts.append(changed)
        records.append({'original_sha256': sha256(original.encode()).hexdigest(),
                        'derived_sha256': sha256(changed.encode()).hexdigest(),
                        'inverse_full_bytes_equal': True})
    output = ROOT/'inputs/hepta/hia_cli_json_cpython312_names.inc'
    result = ('/* PSF-licensed CPython v3.12.14 runtime name diagnostics.\n'
              ' * Only local helper/macro identifiers change; the actual\n'
              ' * runtime _Py_ID(name) object is retained. Unexecuted. */\n\n' +
              '\n\n'.join(parts) + '\n').encode()
    with output.open('xb') as stream:
        stream.write(result)
    report = {'schema': 'hia.cli-json.r4c.runtime-name-static-derivation.v1',
              'status': 'STATIC_TEXT_ONLY', 'source': pin(SOURCE, raw),
              'parts': records, 'output': pin(output, result),
              'native_executed': False, 'c_compiler_executed': False}
    with (ROOT/'RUNTIME-NAMES-DERIVATION.json').open('x') as stream:
        json.dump(report, stream, indent=2); stream.write('\n')
    print(json.dumps({'status': report['status'], 'output': report['output']}))


if __name__ == '__main__':
    main()
