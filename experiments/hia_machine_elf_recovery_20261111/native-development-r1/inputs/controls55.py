"""New reconstructed 55-case control; not the lost historical control bytes."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
import traceback
from common import SOURCE, ORACLE_SHA, create, load_exact, read_json, require, stable_file, wire

def decode(value):
    if isinstance(value, list):
        return [decode(item) for item in value]
    if isinstance(value, dict):
        kind = value.get('@type')
        if kind == 'bytes':
            return bytes.fromhex(value['hex'])
        if kind == 'bytearray':
            return bytearray.fromhex(value['hex'])
        if kind == 'tuple':
            return tuple(decode(item) for item in value['items'])
        if kind == 'float':
            return float(value['value'])
        if kind == 'repeat':
            return [decode(value['value']) for _ in range(value['count'])]
        if kind is not None:
            raise ValueError('unknown frozen input encoding')
        return {key:decode(item) for key, item in value.items()}
    return value

def observe(fn, specification):
    a = decode(specification)
    try:
        result = fn(a['code'], a['symbols'], a['relocations'], text_alignment=a['alignment'])
        return {'kind':'bytes', 'bytes':len(result), 'sha256':sha256(result).hexdigest(),
                'hex':result.hex()}
    except BaseException as exc:
        return {'kind':'exception', 'type':type(exc).__qualname__,
                'args_repr':repr(exc.args)}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--oracle', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(SOURCE))
    from hepta import hia_machine_elf as public
    from hepta.hia_machine_elf_native import installed_machine_elf
    require(Path(public.__file__).resolve() == SOURCE / 'hepta/hia_machine_elf.py',
            'public ELF implementation import differs')
    definitions, inputs_pin = read_json(args.inputs)
    rows = definitions['cases']
    require(definitions['revision'] == 'RECONSTRUCTED_NEW_55_NOT_RECOVERED_OLD_CONTROL'
            and len(rows) == 55 and len({row['id'] for row in rows}) == 55
            and sum(row['expected_kind'] == 'bytes' for row in rows) == 6,
            'new declared case denominator differs')
    oracle = load_exact('complete_608_elf_oracle', args.oracle, ORACLE_SHA)
    legacy = []
    def forbidden(*unused, **ignored):
        legacy.append('retained_writer')
        raise AssertionError('retained ELF writer called in selected control')
    public._reference_write_elf_object = forbidden
    image = installed_machine_elf(str(args.manifest))
    observations = []
    error = None
    try:
        for row in rows:
            expected = observe(oracle.write_elf_object, row['arguments'])
            actual = observe(public.write_elf_object, row['arguments'])
            observations.append({'id':row['id'], 'original':expected, 'native':actual,
                                 'pass':expected == actual and expected['kind'] == row['expected_kind']})
    except BaseException as exc:
        error = exc
    before_equal = stable_file(args.inputs, inputs_pin['sha256'])[0] == inputs_pin
    passed = (error is None and len(observations) == 55 and all(row['pass'] for row in observations)
              and before_equal and not legacy and sum(image.calls.values()) > 0)
    result = {'schema':'hepta.hia.machine-elf.reconstructed-55-case-result.v1',
              'status':'PASS' if passed else 'HOLD',
              'revision':definitions['revision'], 'historical_results_inherited':False,
              'loaded_case_ids':[row['id'] for row in rows],
              'executed_case_ids':[row['id'] for row in observations],
              'loaded':55, 'executed':len(observations),
              'valid':6, 'invalid':49, 'inputs':inputs_pin, 'inputs_stable':before_equal,
              'cases':observations, 'retained_owner_calls':legacy,
              'native_operation_counts':dict(image.calls), 'whole_writer_qualified':False}
    if error is not None:
        result['failure'] = {'type':type(error).__name__, 'text':str(error)}
    create(args.report, wire(result))
    print(json.dumps({'stage':'reconstructed_55', 'status':result['status'],
                      'loaded':55, 'executed':len(observations)}), flush=True)
    return 0 if passed else 1

if __name__ == '__main__':
    raise SystemExit(main())
