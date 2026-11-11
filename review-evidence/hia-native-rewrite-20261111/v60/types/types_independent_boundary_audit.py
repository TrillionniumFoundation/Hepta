"""Small independent development witnesses against an already compiled image.

No compiler invocation, no source regeneration, no cold-qualification claim.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
import time

BASE = Path('/workspace/scratch/623459b0e1bc')
REPO = BASE / 'Hepta-native-types'
sys.path.insert(0, str(REPO))
from hepta.hia_program import HIAProgramRejected
from hepta.hia_program_composite import _Types
from hepta.hia_composite_types_native import NativeCompositeTypes, NativeCompositeTypeSession


def digest(data):
    return sha256(data).hexdigest()


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def record(name, fields=(), params=()):
    return dict(kind='record', name=name, params=list(params),
                fields=[dict(name=name, type=typ) for name, typ in fields])


def enum(name, variants, params=()):
    return dict(kind='enum', name=name, params=list(params), variants=[
        dict(name=name, fields=[dict(name=name, type=typ) for name, typ in fields])
        for name, fields in variants])


def application(name, *args):
    return dict(name=name, args=list(args))


def counters(owner):
    if isinstance(owner, NativeCompositeTypeSession):
        return owner.observations
    return dict(cache_count=len(owner.cache), active_count=len(owner.active),
                partial_declaration_steps=owner.partial_declaration_steps)


def native_key(owner, identifier, memo):
    if identifier in memo:
        return memo[identifier]
    descriptor = owner._descriptors[identifier]
    kind = descriptor['kind']
    if kind == 'primitive':
        result = descriptor['name']
    elif kind == 'partial_record':
        result = ('partial<' + native_key(owner, descriptor['record'], memo) + ';'
                  + ','.join(name for name, _ in descriptor['fields']) + '>')
    else:
        result = descriptor['name'] + '<' + ','.join(
            native_key(owner, target, memo) for target in descriptor['args']) + '>'
    if len(result) > 65536:
        raise ValueError('independent key oracle exceeds its own small-witness scope')
    memo[identifier] = result
    return result


def layout(owner, value):
    memo = {}
    def key(typ):
        if isinstance(owner, NativeCompositeTypeSession):
            return native_key(owner, owner._ids[id(typ)], memo)
        return typ.key
    pending, nodes = [value], {}
    while pending:
        typ = pending.pop()
        name = key(typ)
        if name in nodes:
            continue
        nodes[name] = dict(kind=typ.kind, flat=list(typ.flat), linear=typ.linear,
            fields=[(name, key(child)) for name, child in typ.fields],
            variants=[(variant, [(name, key(child)) for name, child in fields])
                      for variant, fields in typ.variants],
            state=None if typ.state is None else key(typ.state),
            result=None if typ.result is None else key(typ.result),
            record=None if typ.record is None else key(typ.record),
            poll=typ.poll, cancel=typ.cancel)
        pending.extend(child for _, child in typ.fields)
        pending.extend(child for _, fields in typ.variants for _, child in fields)
        pending.extend(child for child in (typ.state,typ.result,typ.record) if child is not None)
    return dict(root=key(value), nodes=nodes)


def cases():
    chunk = record('Chunk', [('f'+str(i),'u8') for i in range(64)])
    full = record('Full', [('c'+str(i),'Chunk') for i in range(8)])
    over = record('Over', [('c'+str(i),'Chunk') for i in range(9)])
    yield ('record-flat-and-error-state', [chunk, full, over], dict(partial_records=True), [
        ('resolve','Over'), ('resolve','Over'), ('resolve','Full'),
        ('partial','Full',['c'+str(i) for i in range(8)]),
        ('partial','Full',['c'+str(i) for i in range(7)]),
        ('partial','Full',[]), ('partial','Full',['c1','c0']),
        ('partial','Full',['c0','c0']), ('resolve','Over'), ('resolve','u8')])
    tail = record('Tail', [('t'+str(i),'u8') for i in range(63)])
    edge = enum('Edge', [('v'+str(i), [('value','Chunk')]) for i in range(7)]
                + [('v7',[('value','Tail')])])
    too = enum('Too', [('v'+str(i), [('value','Chunk')]) for i in range(8)])
    yield ('enum-tag-flat-boundary', [chunk, tail, edge, too], {}, [
        ('resolve','Too'), ('resolve','Edge'), ('resolve','Too'), ('resolve','Tail')])
    loan = record('Loan', [('held','T')], ['T'])
    tagged = enum('Tagged', [('some',[('payload',application('Loan','T'))]),('none',[])], ['T'])
    yield ('enum-lazy-loan-refusal-state', [loan, tagged], {}, [
        ('resolve',application('Tagged','readbuf')), ('resolve',application('Loan','readbuf')),
        ('resolve',application('Tagged','buffer')), ('resolve',application('Tagged','readbuf')),
        ('resolve',application('Tagged','mutbuf')), ('resolve',application('Tagged','mutbuf'))])
    task = dict(kind='task', name='Task', params=[], state=application('Loan','readbuf'),
                result='unit',poll='poll',cancel='cancel')
    yield ('task-retained-loan-error-state', [loan, task], {}, [
        ('resolve','Task'), ('resolve',application('Loan','readbuf')), ('resolve','Task'),
        ('resolve',application('Loan','buffer')), ('resolve','unit')])
    zero = [record('R0')]+[record('R'+str(i), [('prior','R'+str(i-1))]) for i in range(1,34)]
    yield ('zero-width-depth-cold', zero, {}, [
        ('resolve','R33'), ('resolve','R0'), ('resolve','R32'), ('resolve','u8')])
    yield ('zero-width-depth-warm-cache', zero, {}, [
        ('resolve','R32'), ('resolve','R33'), ('resolve','R33'), ('resolve','R0')])
    refs = ['u8']
    for _ in range(33):
        refs.append(application('Phantom', refs[-1]))
    yield ('generic-reference-32-33', [record('Phantom',params=['T'])], {}, [
        ('resolve',refs[32]), ('resolve',refs[33]), ('resolve',refs[32]), ('resolve','unit')])
    yield ('malformed-reference-precedence', [record('A')], dict(partial_records=True), [
        ('resolve',None), ('resolve',True), ('resolve',[]), ('resolve',1),
        ('resolve',{'name':'A','args':[],'other':True}),
        ('resolve',{'name':'bad-identifier','args':[]}),
        ('resolve',{'name':'A','args':['u8']}),
        ('resolve',{'partial':'A','initialized':['missing']}),
        ('resolve',{'partial':'A','initialized':['x','x']}), ('resolve','A')])
    yield ('identifier-length-exact', [record('A'*128)], {}, [
        ('resolve','A'*128), ('resolve','A'*129), ('resolve','A'*128)])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--compiled-input', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_bytes())
    image_path = args.manifest.parent / manifest['image_path']
    image_bytes = image_path.read_bytes()
    compiled_source = args.compiled_input.read_bytes()
    receipt = json.loads(args.receipt.read_bytes())
    assert digest(image_bytes) == manifest['image_sha256'] == receipt['produced_sha256']
    assert digest(compiled_source) == manifest['source_sha256'] == receipt['input_sha256']
    assert manifest['compiler_sha256'] == receipt['image_sha256']
    native = NativeCompositeTypes(image_bytes, manifest['image_sha256'])
    fingerprints = {str(path):digest(path.read_bytes()) for path in [
        REPO/'hepta/hia_program_composite.py', REPO/'hepta/hia_composite_types_native.py']}
    rows, started = [], time.monotonic()
    for name, definitions, flags, commands in cases():
        old = _Types(definitions, **flags)
        new = native.session(definitions, **flags)
        try:
            rows.append(dict(case=name, command='init', equal=counters(old)==counters(new),
                             old=counters(old), native=counters(new)))
            for command in commands:
                pair = []
                for owner in (old,new):
                    try:
                        if command[0]=='resolve': value=owner.resolve(command[1])
                        else: value=owner.partial_record(owner.resolve(command[1]),command[2])
                    except HIAProgramRejected as exc:
                        pair.append(dict(error=exc.code, counters=counters(owner)))
                    else:
                        details=layout(owner,value)
                        pair.append(dict(error=None, counters=counters(owner),
                                         layout_sha256=digest(wire(details)),
                                         flat_slots=len(value.flat),nodes=len(details['nodes'])))
                rows.append(dict(case=name, command=command[0],
                    input_sha256=digest(wire(command)),equal=pair[0]==pair[1], old=pair[0], native=pair[1]))
        finally:
            new.close()
    unchanged={path:digest(Path(path).read_bytes())==value for path,value in fingerprints.items()}
    result=dict(schema='hepta.hia.composite-types-independent-development-audit.v1',
        status='DEVELOPMENT_DIFFERENTIAL_PASS' if all(row['equal'] for row in rows) and all(unchanged.values()) else 'DIFFERENCE_OR_SOURCE_CHANGE',
        input_generator='independent cases in this script; no project test functions imported',
        manifest=str(args.manifest),manifest_sha256=digest(args.manifest.read_bytes()),
        image_sha256=digest(image_bytes), compiled_source_sha256=digest(compiled_source),
        compiler_sha256=manifest['compiler_sha256'],receipt_path=str(args.receipt),
        receipt_sha256=digest(args.receipt.read_bytes()),adapter_reference_fingerprints=fingerprints,
        adapter_reference_unchanged=unchanged,checks=len(rows),rows=rows,
        elapsed_seconds=time.monotonic()-started,compiled_new_image=False,
        cold_qualified=False,whole_native_delivery_qualified=False)
    args.output.parent.mkdir(exist_ok=True,parents=True)
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'path':str(args.output),'sha256':digest(args.output.read_bytes()),
                      'status':result['status'],'checks':len(rows),
                      'mismatches':[row for row in rows if not row['equal']]}))


if __name__=='__main__':
    main()
