"""Frozen hidden cases and independent Python specifications.

The candidate executable receives inputs only. Expected answers stay in this
coordinator module and never share the candidate's address space.
"""
import random

SEED = 2026102401
MASK = (1 << 64) - 1
SENTINEL32 = 2779096485
SENTINEL64 = -6510615555426900571


def signed64(value):
    value &= MASK
    return value - (1 << 64) if value >= 1 << 63 else value


def expected(task, case):
    values, capacity = case['input'], case.get('capacity', 0)
    result = {'id': case['id'], 'guards': True}
    if task == 'compact_runs':
        runs = [v for i, v in enumerate(values) if i == 0 or v != values[i - 1]]
        alias = case.get('alias', False)
        storage = max(len(values), capacity) if alias else capacity
        output = (list(values) + [SENTINEL32] * (storage - len(values))) if alias else [SENTINEL32] * capacity
        written = min(len(runs), capacity)
        output[:written] = runs[:written]
        result.update(result=len(runs), output=output, input_after=output[:len(values)] if alias else list(values))
    elif task == 'rolling_sum':
        window = case['parameter']
        count = len(values) - window + 1 if 0 < window <= len(values) else 0
        output = [SENTINEL64] * capacity
        for i in range(min(count, capacity)):
            output[i] = signed64(sum(values[i:i + window]))
        result.update(result=count, output=output, input_after=list(values))
    elif task == 'lower_bound':
        import bisect
        result.update(result=bisect.bisect_left(values, case['parameter']), input_after=list(values))
    elif task == 'parse_decimal':
        n = len(values)
        i = 1 if n and values[0] == 43 else 0
        number = 0
        previous_digit = False
        code, consumed = 0, n
        if i == n:
            code, consumed = 1, i
        while not code and i < n:
            byte = values[i]
            if byte == 95:
                if not previous_digit or i + 1 >= n or not 48 <= values[i + 1] <= 57:
                    code, consumed = 1, i
                    break
                previous_digit = False
            elif 48 <= byte <= 57:
                digit = byte - 48
                if number > (MASK - digit) // 10:
                    code, consumed = 2, i
                    break
                number = number * 10 + digit
                previous_digit = True
            else:
                code, consumed = 1, i
                break
            i += 1
        result.update(value=0 if code else number, consumed=consumed, status=code, input_after=list(values))
    else:
        raise ValueError(task)
    return result


def public_cases(task):
    examples = {
        'compact_runs': [dict(input=[3, 3, 1, 1, 3], capacity=4, alias=False), dict(input=[], capacity=0, alias=False)],
        'rolling_sum': [dict(input=[2, -1, 4, 3], capacity=3, parameter=2), dict(input=[1], capacity=0, parameter=2)],
        'lower_bound': [dict(input=[1, 3, 3, 7], parameter=3), dict(input=[], parameter=0)],
        'parse_decimal': [dict(input=list(b'+12_345')), dict(input=list(b'7__2'))],
    }[task]
    return [dict(id=i, **case) for i, case in enumerate(examples)]


def hidden_cases(task):
    rng = random.Random(SEED + ['compact_runs', 'rolling_sum', 'lower_bound', 'parse_decimal'].index(task))
    cases = []
    if task == 'compact_runs':
        arrays = [[], [0], [7] * 32, list(range(64)), [0, 0xffffffff] * 64,
                  [3, 3, 1, 1, 3, 3, 1], [0xffffffff] * 8]
        arrays += [[rng.randrange(8) if rng.randrange(5) else 0xffffffff for _ in range(rng.randrange(256))] for _ in range(55)]
        for values in arrays:
            for capacity in sorted({0, 1, len(values) // 2, len(values), len(values) + 3}):
                for alias in (False, True):
                    cases.append(dict(input=values, capacity=capacity, alias=alias))
    elif task == 'rolling_sum':
        arrays = [[], [0], [1, -1] * 16, [MASK >> 1, 1, -(1 << 63), -1], [7] * 64]
        arrays += [[rng.randrange(-(1 << 63), 1 << 63) for _ in range(rng.randrange(96))] for _ in range(35)]
        for values in arrays:
            for window in sorted({0, 1, max(1, len(values) // 2), len(values), len(values) + 1}):
                cases.append(dict(input=values, parameter=window, capacity=rng.randrange(len(values) + 4)))
        cases.append(dict(input=[signed64(i * 997) for i in range(4096)], parameter=2048, capacity=16))
    elif task == 'lower_bound':
        arrays = [[], [0], [-1] * 64, [-(1 << 63), -1, 0, 0, (1 << 63) - 1]]
        arrays += [sorted(rng.randrange(-50, 51) for _ in range(rng.randrange(512))) for _ in range(50)]
        for values in arrays:
            keys = {-(1 << 63), (1 << 63) - 1, -51, 0, 51}
            if values:
                keys.update((values[0], values[len(values) // 2], values[-1]))
            for key in sorted(keys):
                cases.append(dict(input=values, parameter=key))
    else:
        strings = [b'', b'+', b'-1', b'0', b'+0', b'000000', b'_1', b'1_', b'1__2', b'+_1', b' 1',
                   b'1 ', b'1a2', b'1\x002', b'\xff', b'18446744073709551615', b'18446744073709551616',
                   b'+18_446_744_073_709_551_615', b'+18_446_744_073_709_551_616', b'9' * 90]
        for _ in range(100):
            value = rng.randrange(1 << 64)
            text = str(value)
            if rng.randrange(2):
                text = '_'.join(text[i:i + 3] for i in range(0, len(text), 3))
            if rng.randrange(2):
                text = '+' + text
            strings.append(text.encode())
            index = rng.randrange(len(text) + 1)
            strings.append(text[:index].encode() + rng.choice([b'_', b'x', b'-', b'\xff']) + text[index:].encode())
        cases = [dict(input=list(value)) for value in strings]
    return [dict(id=i + 1000, **case) for i, case in enumerate(cases)]
