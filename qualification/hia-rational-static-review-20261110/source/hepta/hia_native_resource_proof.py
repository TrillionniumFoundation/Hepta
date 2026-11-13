"""Independent finite stack walk over bound SafeCore native instructions.

A conservative acyclic abstract interpretation, not an ISA kernel proof. The
bound ends before external abort executes and excludes caller/libc/loader,
signals, RSS and allocator memory. No receipt authorizes execution.
"""
from hashlib import sha256
from pathlib import Path

from .hia_safe_core import validate_safe_core_image, _profile, require
from .hia_safe_core_x64 import decode
from .hia_safe_core_elf import bind_final_image
from .hia_program import verify_program


def _stack_walk(binding, budget):
    """Track affine entry-RSP offsets independently of the symbolic executor.

    Both successors of every conditional are visited, including infeasible
    paths. Unknown writes to RSP and unknown stack restoration are rejected.
    Stack slots retain affine pointers only; scalar values are unknown.
    """
    code = decode(binding['text'])
    pending = [(binding['entry'], {4: 0}, {}, (), frozenset())]
    minimum, steps, terminals = 0, 0, 0
    while pending:
        pc, regs, slots, frames, visited = pending.pop()
        while True:
            steps += 1
            require(steps <= 65536 and len(pending) <= 4096, 'native stack walk budget exceeded')
            key = (pc, tuple(f[0] for f in frames))
            require(pc in code and key not in visited, 'cycle or unknown stack instruction entry')
            visited = visited | {key}
            instruction = code[pc]
            op, a, nxt = instruction.op, instruction.args, pc + instruction.size

            def reserve():
                nonlocal minimum
                require(4 in regs and -16384 <= regs[4] <= 8, 'unknown or unbounded RSP')
                minimum = min(minimum, regs[4])
                require(regs[4] >= -budget, 'native stack reserve exceeded')

            def assign(dst, value):
                if value is None:
                    regs.pop(dst, None)
                else:
                    regs[dst] = value
                reserve()

            def read(address, size):
                if address is None:
                    return None
                require(regs[4] <= address and address + size <= 8, 'stack read exceeds reserve')
                return slots.get((address, size))

            def write(address, size, value):
                if address is None:
                    return
                require(regs[4] <= address and address + size <= 0, 'stack write exceeds reserve')
                for start, width in list(slots):
                    if address < start + width and start < address + size:
                        del slots[start, width]
                if value is not None:
                    slots[address, size] = value

            reserve()
            if op == 'mov':
                assign(a[0], regs.get(a[1]))
            elif op == 'imm':
                assign(a[0], None)
            elif op in {'load', 'load8', 'lea'}:
                dst, base, disp = a
                address = None if base not in regs else regs[base] + disp
                value = address if op == 'lea' else read(address, 8 if op == 'load' else 1)
                assign(dst, None if op == 'load8' else value)
            elif op in {'store', 'store8'}:
                base, disp, src = a
                write(None if base not in regs else regs[base] + disp,
                      8 if op == 'store' else 1, regs.get(src) if op == 'store' else None)
            elif op == 'immediate_alu':
                kind, dst, value = a
                if kind != 'cmp':
                    assign(dst, regs[dst] + (value if kind == 'add' else -value)
                           if dst in regs and kind in {'add', 'sub'} else None)
            elif op in {'add', 'sub', 'and', 'or', 'xor', 'not', 'shl', 'shr'}:
                assign(a[0], None)
            elif op == 'setcc':
                assign(a[1], None)
            elif op == 'push':
                value = regs.get(a[0])
                regs[4] -= 8
                reserve()
                write(regs[4], 8, value)
            elif op in {'pop', 'leave'}:
                if op == 'leave':
                    assign(4, regs.get(5))
                value = read(regs[4], 8)
                regs[4] += 8
                assign(a[0] if op == 'pop' else 5, value)
            elif op == 'call':
                target = binding['calls'][pc]
                regs[4] -= 8
                reserve()
                write(regs[4], 8, None)
                if target == 'abort':
                    terminals += 1
                    break
                frames += ((nxt, regs[4]),)
                pc = target
                continue
            elif op == 'ret':
                read(regs[4], 8)
                if frames:
                    nxt, expected = frames[-1]
                    require(regs[4] == expected, 'local call stack is not balanced')
                    frames = frames[:-1]
                    regs[4] += 8
                else:
                    require(regs[4] == 0, 'entry return stack is not balanced')
                    terminals += 1
                    break
            elif op == 'jmp':
                nxt = a[0]
            elif op == 'jcc':
                pending.append((a[1], dict(regs), dict(slots), frames, visited))
            elif op == 'ud2':
                terminals += 1
                break
            else:
                require(op in {'nop', 'cmp', 'test'}, 'unreviewed stack instruction semantics')
            pc = nxt
    return {'maximum_reserved_bytes': -minimum, 'walk_steps': steps, 'terminal_paths': terminals}


def certify_native_stack(document, image, final_bytes, *, stack_budget, timeout_ms=15000):
    require(type(stack_budget) is int and 0 <= stack_budget <= 16384,
            'native stack budget must be an integer in [0,16384]')
    validation = validate_safe_core_image(document, image, final_bytes, timeout_ms=timeout_ms)
    checked = verify_program(document)
    fn, _ = _profile(checked, image)
    binding = bind_final_image(image.object_bytes, image.text_bytes, final_bytes, fn['name'],
                              exports=image.exports, function_count=len(checked.as_dict()['functions']))
    counts = _stack_walk(binding, stack_budget)
    return {'schema': 'hepta.hia.native-stack.v1', 'status': 'bounded_instruction_walk_validated',
            'stack_budget_bytes': stack_budget, **counts,
            'certificate_checker_sha256': sha256(Path(__file__).read_bytes()).hexdigest(),
            'image_binding': validation['image_binding'], 'source_identity': validation['source_identity'],
            'solver': validation['solver'], 'core_sha256': checked.sha256,
            'scope': 'entry RSP through acyclic local calls, before external abort execution',
            'caller_contract': validation['assumptions'],
            'claims': {'whole_process_stack_or_RSS_bound': False, 'OS_reserve_guaranteed': False,
                       'kernel_checked_formal_proof': False, 'serialized_receipt_authorizes_execution': False}}
