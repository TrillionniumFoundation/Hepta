"""Compile the retained encoder text to code metadata, without executing it.

This authoring command produces three immutable bytecode/exception packets
for HIA. It never imports json.encoder, calls _make_iterencode, constructs a
generator or serializes a value. Runtime code-object admission is separate.
It may run only in the frozen source-authoring request, under its original
owner. Merely writing/parsing this file does not generate a packet.
"""
from __future__ import annotations

import ast
import dis
import hashlib
import json
from pathlib import Path
import struct
import sys
import types

MAGIC = int.from_bytes(b'HCLIBC31', 'little')
NO_HANDLER = (1 << 64) - 1
NAMES = ('_iterencode_list', '_iterencode_dict', '_iterencode')
SUPPORTED = frozenset((1, 2, 4, 5, 9, 35, 55, 60, 61, 68, 69, 75, 83, 89,
                      92, 93, 99, 100, 102, 106, 110, 114, 115, 116, 117,
                      118, 119, 120, 121, 122, 123, 124, 125, 127, 128, 129,
                      130, 134, 136, 137, 138, 140, 144, 149, 150, 151, 155,
                      157, 171, 172, 173))
WORD = struct.Struct('<Q')
ROW = struct.Struct('<8Q')


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def wire(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode()


def const_identity(value):
    if value is None:
        return {'kind': 'None'}
    if value is Ellipsis:
        return {'kind': 'Ellipsis'}
    if type(value) is bool:
        return {'kind': 'bool', 'value': value}
    if type(value) is int:
        return {'kind': 'int', 'hex': hex(value)}
    if type(value) is str:
        return {'kind': 'str', 'utf32le': value.encode('utf-32-le', 'surrogatepass').hex()}
    if type(value) is bytes:
        return {'kind': 'bytes', 'hex': value.hex()}
    if type(value) is tuple:
        return {'kind': 'tuple', 'items': [const_identity(item) for item in value]}
    raise ValueError('unexpected constant kind in the fixed three generator code objects')


def one_named_child(parent, name):
    found = [value for value in parent.co_consts
             if type(value) is types.CodeType and value.co_name == name]
    if len(found) != 1:
        raise ValueError('fixed code object name is missing or ambiguous: ' + name)
    return found[0]


def encode_packet(code):
    if type(code) is not types.CodeType or code.co_name not in NAMES:
        raise ValueError('one original JSON generator code object is required')
    original = code.co_code
    if len(original) % 2 or not original:
        raise ValueError('fixed 3.12 wordcode extent differs')
    units = len(original) >> 1
    if units > (sys.maxsize - 64) >> 6:
        raise ValueError('instruction-packet allocation exceeds Py_ssize_t')
    instructions = tuple(dis.get_instructions(code, show_caches=False, adaptive=False))
    if any(item.opcode not in SUPPORTED for item in instructions):
        raise ValueError('unimplemented fixed-source opcode: ' + ','.join(
            item.opname for item in instructions if item.opcode not in SUPPORTED))
    if any(item.offset & 1 for item in instructions):
        raise ValueError('unaligned instruction offset')
    exceptions = tuple(dis.Bytecode(code).exception_entries)
    local_names = []
    index = 0
    while True:
        try:
            local_names.append(code._varname_from_oparg(index))
        except IndexError:
            break
        index += 1
    if len(local_names) < code.co_nlocals:
        raise ValueError('actual localsplus name table is incomplete')
    returns = [i for i in instructions if i.opname == 'RETURN_GENERATOR']
    if len(returns) != 1:
        raise ValueError('exact generator construction prologue is absent')
    resume_entry = (returns[0].offset >> 1) + 1
    output = bytearray(64 + (units << 6))
    ROW.pack_into(output, 0, MAGIC, 31214, units, NAMES.index(code.co_name),
                  resume_entry, len(local_names), code.co_stacksize, 1)
    rows = []
    offsets = {item.offset for item in instructions}
    for index, instruction in enumerate(instructions):
        pc = instruction.offset >> 1
        following = (instructions[index + 1].offset >> 1
                     if index + 1 < len(instructions) else units)
        argument = 0 if instruction.arg is None else instruction.arg
        if type(argument) is not int or argument < 0 or argument >= 1 << 64:
            raise ValueError('fixed opcode argument is outside the unsigned packet')
        target = NO_HANDLER
        if instruction.opcode in dis.hasjabs or instruction.opcode in dis.hasjrel:
            if type(instruction.argval) is not int or instruction.argval not in offsets:
                raise ValueError('branch target is not an original instruction')
            target = instruction.argval >> 1
        matched = [entry for entry in exceptions
                   if entry.start <= instruction.offset < entry.end]
        if len(matched) > 1:
            raise ValueError('overlapping exception entries need an explicit original lookup model')
        handler = NO_HANDLER
        packed = 0
        if matched:
            entry = matched[0]
            if entry.target not in offsets or entry.depth < 0:
                raise ValueError('exception entry target/depth differs')
            handler = entry.target >> 1
            packed = (entry.depth << 1) | int(entry.lasti)
        ROW.pack_into(output, 64 + (pc << 6), instruction.opcode, argument,
                      following, target, handler, packed, 0, 1)
        rows.append({'pc': pc, 'opcode': instruction.opcode, 'opname': instruction.opname,
                     'argument': argument, 'following': following, 'target': target,
                     'handler': handler, 'unwind_depth_and_lasti': packed})
    raw = bytes(output)
    code_identity = {
        'name': code.co_name, 'qualname': code.co_qualname,
        'code': pin(original), 'code_hex': original.hex(),
        'exception_table': pin(code.co_exceptiontable),
        'exception_table_hex': code.co_exceptiontable.hex(),
        'linetable': pin(code.co_linetable), 'linetable_hex': code.co_linetable.hex(),
        'firstlineno': code.co_firstlineno, 'flags': code.co_flags,
        'argcount': code.co_argcount, 'posonlyargcount': code.co_posonlyargcount,
        'kwonlyargcount': code.co_kwonlyargcount, 'stacksize': code.co_stacksize,
        'nlocals': code.co_nlocals, 'localsplus_names': local_names,
        'varnames': list(code.co_varnames), 'cellvars': list(code.co_cellvars),
        'freevars': list(code.co_freevars), 'names': list(code.co_names),
        'consts': [const_identity(item) for item in code.co_consts],
    }
    return raw, {'schema': 'hia.cli-json.py312-code-packet.v1',
                 'profile': 31214, 'code': code_identity,
                 'packet': pin(raw), 'instructions': rows,
                 'runtime_code_object_admitted': False,
                 'foreign_input_domain_restricted': False}


def author(source, expected_sha256, output):
    if sys.version_info[:3] != (3, 12, 14):
        raise ValueError('exact 3.12.14 compiler profile is required for wordcode packets')
    raw = Path(source).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError('retained original encoder source SHA differs')
    # compile is an authoring operation here. No globals dictionary is
    # executed, no original generator is resumed and no JSON object is read.
    syntax = ast.parse(raw, filename='<stdlib-json-encoder-v3.12.14>')
    module = compile(syntax, '<stdlib-json-encoder-v3.12.14>', 'exec',
                     flags=0, dont_inherit=True, optimize=0)
    factory = one_named_child(module, '_make_iterencode')
    target = Path(output)
    target.mkdir(mode=0o700, parents=False, exist_ok=False)
    records = []
    for name in NAMES:
        packet, report = encode_packet(one_named_child(factory, name))
        label = name.removeprefix('_')
        for filename, content in ((label + '.packet.bin', packet),
                                  (label + '.packet.json', wire(report))):
            with (target/filename).open('xb') as stream:
                stream.write(content)
            records.append({'path': filename, **pin(content)})
    result = {'schema': 'hia.cli-json.py312-packets-authoring.v1',
              'status': 'THREE_SOURCE_PACKETS_AUTHORED', 'source': pin(raw),
              'python': sys.version, 'exact_names': list(NAMES), 'outputs': records,
              'generator_bodies_executed': False, 'json_values_encoded': 0,
              'native_executed': False, 'runtime_code_objects_admitted': False}
    with (target/'REPORT.json').open('xb') as stream:
        stream.write(wire(result))
    return result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--source-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = author(args.source, args.source_sha256, args.output)
    print(json.dumps({'status': result['status'], 'outputs': len(result['outputs'])}))
