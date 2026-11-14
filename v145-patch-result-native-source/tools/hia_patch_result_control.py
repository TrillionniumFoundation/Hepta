"""Unchanged front lowering plus the exact four-result unpack inventory.

No prepare, verifier, interface or receipt body is implemented by this host
compiler. Both complete original functions are lowered by the same front
compiler; this adds only a finite validation for the newly used UNPACK4 port.
"""
from tools.hia_front_control import Compiler as _FrontCompiler, OPS


class Compiler(_FrontCompiler):
    def _validate_calls(self):
        super()._validate_calls()
        for function in self.functions:
            for instruction in function.instructions:
                if instruction['kind'] != 'effect' or instruction['opcode'] != OPS['UNPACK']:
                    continue
                raw, arguments = instruction['raw'], instruction['arguments']
                destinations = instruction['destinations']
                if (raw not in ([1], [2], [3], [4]) or len(arguments) != 1
                        or len(destinations) != raw[0] or instruction['vector']
                        or instruction['consume'] != arguments
                        or len({ref.slot for ref in destinations}) != len(destinations)
                        or any(not ref.temporary or ref.slot in function.cell_slots
                               for ref in (*arguments, *destinations))):
                    raise ValueError('patch fixed unpack operands differ')


def compile_policy(source, entries, imports):
    return Compiler(source, entries, imports)
