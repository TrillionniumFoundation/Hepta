"""Independent grammar parser shared by read-only P2 review scripts."""
import numpy as np


def parse_grammar(tokens):
    """Independent adjacent-triple parser, without the campaign interpreter."""
    MAP, WRITE, ASK, RESET, READ, IGNORE = 3, 4, 5, 6, 2, 19
    KEY, VALUE, UNKNOWN = 11, 15, 4
    labels = np.full(len(tokens), -100, dtype=np.int64)
    writes = np.zeros(len(tokens), dtype=bool)
    query_last_binding = np.full(len(tokens), -1, dtype=np.int64)
    resets, state, locations = [], {}, {}
    i = 0
    while i < len(tokens):
        token = int(tokens[i])
        if token == MAP:
            state.clear(); locations.clear(); i += 1
        elif token == RESET:
            state.clear(); locations.clear(); resets.append(i); i += 1
        elif 7 <= token < KEY:
            i += 1
        elif token in (WRITE, ASK, IGNORE):
            assert i+2 < len(tokens)
            key, end = int(tokens[i+1]), int(tokens[i+2])
            assert KEY <= key < VALUE
            if token == ASK:
                assert end == READ
                labels[i+2] = state.get(key, UNKNOWN)
                query_last_binding[i+2] = locations.get(key, -1)
            else:
                assert VALUE <= end < VALUE+4
                if token == WRITE:
                    state[key] = end-VALUE; locations[key] = i+2; writes[i+2] = True
            i += 3
        else:
            raise AssertionError(f'unsupported or malformed raw grammar at {i}: {token}')
    return labels, writes, resets, query_last_binding

