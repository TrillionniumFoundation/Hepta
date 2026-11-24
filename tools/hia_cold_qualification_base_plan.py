"""Serialize every retained base control into native qualification operations."""
from tools.hia_cold_qualification_plan_parts import (assert_gate, build, check_flat,
                                                     observe, utility)


def append_base(p, h, compilers, sample):
    from tools.qualify_hia_selfhost import invalid_sources, readonly_call_source
    from tools.hia_selfhost_cases import (backward_bytesum_source, backward_chain_source,
                                         call_graph_invalid_sources)
    observer, check, util = h['observer'], h['check'], h['util']
    initial = p.literal(b'\xa5' * (1 << 20), label='original-1MiB-transactional-preimage')
    names = []

    def returned(image, source, name, *, cap=1 << 20, work=1 << 20,
                 core=0xffffffff, preimage=initial, cap_word=None):
        result = observe(p, observer, image, source, cap=cap, work=work,
                         cap_word=cap_word, label=name)
        gate = check_flat(p, check, result, source, mode=1, cap=cap, work=work,
                          core=core, initial_handle=preimage, expected_handle=preimage,
                          cap_word=cap_word, label=name + ':unchanged-output-source-ABI')
        assert_gate(p, gate, label=name)
        p.drop(result)
        names.append(name)

    original = compilers[0][1]
    for name, bad in invalid_sources(sample).items():
        source = p.literal(bad, label='fixture:invalid-' + name)
        returned(original, source, 'reject-' + name)
        p.drop(source)

    source = p.literal(readonly_call_source(), label='fixture:readonly-call-alias')
    image = build(p, observer, check, original, source, label='readonly-call-build')
    inp = p.literal(b'readonly alias')
    empty = p.literal(b'')
    returned(image, inp, 'readonly-call-alias-remains-legal', cap=0, work=0,
             core=2 * len(b'readonly alias'), preimage=empty)
    p.drop(source, image, inp)

    for label, compiler in compilers:
        source = p.literal(backward_bytesum_source(sample), label='fixture:backward-bytesum')
        image = build(p, observer, check, compiler, source, label=label + ':backward-bytesum-build')
        for index, data in enumerate((b'', b'HIA backward calls', bytes(range(256)) * 4)):
            expected = 5381
            for byte in data:
                expected = ((expected * 33) ^ byte) & 0xffffffff
            inp = p.literal(data)
            name = label + ':backward-call-behavior-' + str(index)
            result = observe(p, observer, image, inp, cap=1, work=1, label=name)
            gate = check_flat(p, check, result, inp, mode=1, cap=1, work=1,
                              initial=b'\xa5', expected=bytes([expected & 255]),
                              core=expected, label=name + ':source-output-return')
            assert_gate(p, gate, label=name)
            p.drop(inp, result)
            names.append(name)
        p.drop(source, image)
        source = p.literal(backward_chain_source(), label='fixture:128-functions')
        image = build(p, observer, check, compiler, source, label=label + ':full-call-depth-build')
        returned(image, empty, label + ':128-function-backward-chain', cap=0,
                 work=0, core=127, preimage=empty)
        p.drop(source, image)
        for name, bad in call_graph_invalid_sources(sample).items():
            source = p.literal(bad, label='fixture:invalid-call-' + name)
            returned(compiler, source, label + ':reject-' + name)
            p.drop(source)

    actual = p.length(original)
    short = p.number(actual, 1, subtract=True, maximum=1 << 20)
    short_initial = utility(p, util, 0, arg_word=short, label='dynamic-short-output-preimage')
    returned(original, h['source'], 'short-output-is-transactional', cap_word=short,
             core=0xfffffffe, preimage=short_initial)
    returned(original, h['source'], 'short-workspace-rejected', work=1024,
             core=0xfffffffe)
    p.drop(actual, short, short_initial, initial, empty)
    return names
