def check_calls(w:mutbuf) -> u64:
    n = get(w, 64)
    step = 0
    f = 0
    target = 0
    ready = 0
    pending = 0
    while step < n:
        f = 0
        pending = 0
        while f < n:
            # First scan every row, including already marked rows: malformed
            # targets must never be hidden by caller-supplied readiness bytes.
            # Thereafter this immutable graph cannot gain an invalid target,
            # and readiness only changes from zero to one.
            if step == 0 or get(w, CSTATE + f * 8) == 0:
                ready = 1
                target = 0
                while target < 128:
                    if byte(w, CBASE + f * 128 + target) != 0:
                        if target >= n:
                            return fail(w, 55)
                        if get(w, CSTATE + target * 8) == 0:
                            ready = 0
                    target = target + 1
                if ready == 1:
                    put(w, CSTATE + f * 8, 1)
            if get(w, CSTATE + f * 8) == 0:
                pending = pending + 1
            f = f + 1
        if pending == 0:
            return 0
        step = step + 1
    f = 0
    while f < n:
        if get(w, CSTATE + f * 8) == 0:
            return fail(w, 56)
        f = f + 1
    return 0
