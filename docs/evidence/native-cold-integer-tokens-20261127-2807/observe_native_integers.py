"""Compare the original HIA token readers in actual native machine code.

This is a bounded component observation, not a native cold qualification.
The four independent bootstrap seed files are checked by NativeSeeds.
"""
from pathlib import Path
from hashlib import sha256
import argparse
import ast
import ctypes
import json
import struct
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--bootstrap', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    sys.path.insert(0, str(source))
    from hepta.hia_agent_assembly import render_assembly
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    from tools.generate_hia_worker_config_json import document
    from tools.generate_hia_source_release_cold_admit import SOURCE
    from tools.generate_hia_cold_report_admit import EXTRA
    from tools.hia_native_seed_test_support import NativeSeeds

    original = {node.name: node for node in ast.parse(SOURCE).body
                if isinstance(node, ast.FunctionDef)}
    extra = {node.name: node for node in ast.parse(EXTRA).body
             if isinstance(node, ast.FunctionDef)}
    names = ('zero_integer', 'kind', 'token_start', 'token_end', 'get', 'put')
    functions = [original[name] for name in names] + [extra['integer_value']]
    entry = '''def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 64 or length(o) < 1048640:
        return 17
    put(o, 1048608, 5)
    put(o, 1048616, 0)
    put(o, 1048624, length(s))
    put(o, 0, integer_value(s, o, 1))
    put(o, 8, zero_integer(s, o, 1))
    return 0
'''
    authored = entry + '\n'.join(ast.unparse(node) for node in functions) + '\n'
    assembly = render_assembly(document(authored, 'cold_integer_token_observer')).encode()
    seeds = NativeSeeds(source, args.bootstrap, args.output)
    flat = seeds.compile(assembly)
    seeds.save()
    (args.output / 'integer-token-observer.hepta').write_bytes(assembly)
    (args.output / 'integer-token-observer.flat').write_bytes(flat)
    machine = NativeHiaJsonImage(flat, sha256(flat).hexdigest())
    maximum = (1 << 64) - 1
    cases = [(b'0', 0, 1), (b'-0', maximum, 1), (b'1', 1, 0),
             (b'-1', maximum, 0), (b'0.0', maximum, 0),
             (b'-0.0', maximum, 0), (b'0e0', maximum, 0),
             (b'180000000000', 180000000000, 0),
             (b'18446744073709551615', maximum, 0),
             (b'18446744073709551616', maximum, 0),
             (b'100000000000000000000', maximum, 0), (b'', maximum, 0)]
    observations = []
    for token, unsigned, zero in cases:
        input_buffer = ctypes.create_string_buffer(token, max(1, len(token)))
        output_buffer = ctypes.create_string_buffer(1048640)
        scratch = ctypes.create_string_buffer(64)
        status = machine._entry(input_buffer, len(token), output_buffer,
                                len(output_buffer), scratch, len(scratch))
        actual = struct.unpack_from('<QQ', output_buffer, 0)
        row = {'token': token.decode(), 'status': status,
               'integer_value': actual[0], 'zero_integer': actual[1],
               'expected': [unsigned, zero]}
        observations.append(row)
        if status != 0 or actual != (unsigned, zero):
            raise RuntimeError(row)
    report = {'scope': 'actual native token-reader component only',
              'source_function_names': [node.name for node in functions],
              'source_functions_sha256': sha256('\n'.join(ast.dump(node) for node in functions).encode()).hexdigest(),
              'assembly_sha256': sha256(assembly).hexdigest(),
              'flat_sha256': sha256(flat).hexdigest(),
              'native_calls': len(observations), 'observations': observations,
              'passed': True, 'whole_cold_qualified': False}
    (args.output / 'observation.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
