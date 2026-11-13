"""Independent ordinary-Python oracles for shared HIA frame primitives.

No selector, compiler, source policy evaluator, or native fallback lives here.
The seven policy functions are compiled only by the explicit test fixture.
"""


from __future__ import annotations


import sys


import weakref


def validate_plan(context):
    return context.left and context.right()


def register_assignment_witness(context):
    return context.left or context.right()


def code_options(context):
    return bool(context.left and context.right())


def preservation_checks(context):
    return bool(context.left or context.right())


def _require(context):
    if context.arity == 0:
        return context.factory()()
    if context.arity == 1:
        return context.factory()(context.argument(0))
    if context.arity == 2:
        return context.factory()(context.argument(0), context.argument(1))
    if context.arity == 3:
        return context.factory()(context.argument(0), context.argument(1), context.argument(2))
    return context.factory()(context.argument(0), context.argument(1), context.argument(2), context.argument(3))


def _permutation(context):
    if context.arity == 0:
        return context.factory()(first=context.argument(0), text_alignment=context.argument(1))
    if context.arity == 1:
        return context.factory()(context.argument(0), text_alignment=context.argument(1))
    return context.factory()(context.argument(0), context.argument(1), context.argument(2), text_alignment=context.argument(3))


def _terminal_arguments(context):
    return context.factory()(context.shared, context.shared)


def ambient():
    error = sys.exception()
    return None if error is None else [type(error).__name__, list(error.args)]


class ProbeError(Exception):
    pass


class Truth:
    def __init__(self, trace, truth, fail):
        self.trace, self.truth, self.fail = trace, truth, fail

    def __bool__(self):
        self.trace.append(["truth", self.truth, ambient()])
        if self.fail:
            raise ProbeError("truth")
        return self.truth

    def __del__(self):
        self.trace.append(["left-del", ambient()])


class BoolContext:
    def __init__(self, truth, failure):
        self.trace, self.weak = [], {}
        self.truth, self.failure = truth, failure

    @property
    def left(self):
        self.trace.append(["left-get", ambient()])
        value = Truth(self.trace, self.truth, self.failure == "truth")
        self.weak["left"] = weakref.ref(value)
        return value

    def right(self):
        self.trace.append(["right", self.weak["left"]() is None, ambient()])
        if self.failure == "right":
            raise ProbeError("right")
        return 37


class Argument:
    def __init__(self, trace, index):
        self.trace, self.index = trace, index

    def __del__(self):
        self.trace.append(["argument-del", self.index, ambient()])


class Callable:
    def __init__(self, trace, weak, fail, clear):
        self.trace, self.weak, self.fail, self.clear = trace, weak, fail, clear

    def __call__(self, first=None, second=None, third=None, fourth=None, *, text_alignment=None):
        self.trace.append(["call", [None if item is None else item.index
                                    for item in (first, second, third, fourth, text_alignment)],
                           first is not None and first is second, ambient()])
        if self.clear:
            first = second = third = fourth = text_alignment = None
            self.trace.append(["after-parameter-clear", {
                name: ref() is not None for name, ref in self.weak.items()
                if name != "callee"}, ambient()])
        if self.fail:
            raise ProbeError("call")
        return 41

    def __del__(self):
        self.trace.append(["callee-del", ambient()])


class CallContext:
    def __init__(self, arity, fail, clear, alias=False):
        self.trace, self.weak = [], {}
        self.arity, self.fail, self.clear = arity, fail, clear
        self.shared = None
        if alias:
            self.shared = Argument(self.trace, 99)
            self.weak["shared"] = weakref.ref(self.shared)

    def factory(self):
        self.trace.append(["factory", ambient()])
        value = Callable(self.trace, self.weak, self.fail, self.clear)
        self.weak["callee"] = weakref.ref(value)
        return value

    def argument(self, index):
        self.trace.append(["argument", index, ambient()])
        value = Argument(self.trace, index)
        self.weak[str(index)] = weakref.ref(value)
        return value


def capture(operation, context):
    try:
        return True, operation(context)
    except BaseException as error:
        return False, error


def observe(operation, context):
    result = capture(operation, context)
    if result[0]:
        value = result[1]
        if type(value) is Truth:
            outcome = {"returned": "same-left", "identity": context.weak["left"]() is value}
        else:
            outcome = {"returned": type(value).__name__, "value": value}
        value = None
    else:
        outcome = {"error": type(result[1]).__name__, "args": list(result[1].args)}
    held = list(context.trace)
    alive_held = {name: ref() is not None for name, ref in context.weak.items()}
    result = None
    # Deliberately no gc.collect, traceback surgery, or error traceback detach.
    released = list(context.trace)
    alive_released = {name: ref() is not None for name, ref in context.weak.items()}
    if isinstance(context, CallContext):
        context.shared = None
    return {"outcome": outcome, "held": held, "alive_held": alive_held,
            "released": released, "alive_released": alive_released,
            "final": list(context.trace),
            "final_alive": {name: ref() is not None for name, ref in context.weak.items()}}


def with_ambient(operation, context, outer):
    if outer:
        try:
            raise LookupError("ambient")
        except LookupError:
            return observe(operation, context)
    return observe(operation, context)


def compare_case(owner, reference, mode, make_context, label, outer):
    original = with_ambient(reference, make_context(), outer)
    actual = with_ambient(lambda context: owner.run(mode, context), make_context(), outer)
    return {"case": label, "outer": outer, "mode": mode,
            "original": original, "native": actual, "equal": original == actual}


def run_cases(owner, oracle):
    cases = []
    for mode, name in enumerate(("validate_plan", "register_assignment_witness", "code_options", "preservation_checks"), 1):
        for truth in (False, True):
            for failure in (None, "truth", "right"):
                for outer in (False, True):
                    cases.append(compare_case(owner, getattr(oracle, name), mode,
                        lambda truth=truth, failure=failure: BoolContext(truth, failure),
                        f"{name}/truth={truth}/failure={failure}", outer))
    for mode, name, arities in ((5, "_require", range(5)), (6, "_permutation", (0, 1, 3)), (7, "_terminal_arguments", (2,))):
        for arity in arities:
            for fail in (False, True):
                for clear in (False, True):
                    for outer in (False, True):
                        cases.append(compare_case(owner, getattr(oracle, name), mode,
                            lambda arity=arity, fail=fail, clear=clear, mode=mode:
                                CallContext(arity, fail, clear, alias=mode == 7),
                            f"{name}/arity={arity}/fail={fail}/clear={clear}", outer))
    return cases


def observe_core_label(kind, fails, outer):
    events, refs = [], []

    def mark(event):
        active = sys.exception()
        events.append([event, None if active is None else type(active).__name__])

    class Name:
        def __init__(self):
            mark('name-created')
            refs.append(('name', weakref.ref(self)))
        def __del__(self):
            mark('name-del')

    class Suffix:
        def __radd__(self, prefix):
            if prefix != 'fn0_':
                raise AssertionError('retained Core label prefix changed')
            return Name()

    class Receiver:
        def __init__(self):
            mark('receiver-created')
            refs.append(('receiver', weakref.ref(self)))
        def label(self, name):
            if type(name) is not Name:
                raise AssertionError('original temporary argument not delivered')
            mark('callee-entered')
            if fails:
                raise ProbeError('actual original bound-method failure')
            return 37
        def __del__(self):
            mark('receiver-del')

    class Parent:
        @property
        def label(self):
            return Receiver().label

    instance = object.__new__(kind)
    instance.parent, instance.index = Parent(), 0

    def invoke():
        try:
            return True, instance.label(Suffix())
        except BaseException as error:
            return False, error

    def run():
        observed = invoke()
        result = (['value', observed[1]] if observed[0] else
                  ['error', type(observed[1]).__name__, list(observed[1].args)])
        alive_while_error_held = {name: ref() is not None for name, ref in refs}
        while_held = list(events)
        # No traceback is cleared and no GC is invoked. The invoke() handler
        # has already exited, so dropping this result drops its final holder.
        observed = None
        return {'outcome': result, 'while_held': while_held,
                'alive_while_held': alive_while_error_held,
                'after_release': list(events),
                'alive_after_release': {name: ref() is not None for name, ref in refs}}

    if outer:
        try:
            raise LookupError('actual outer handler')
        except LookupError:
            return run()
    return run()


def core_label_cases(owner, backend):
    native_class = owner.function_class(backend._Function)
    cases = []
    for fails in (False, True):
        for outer in (False, True):
            expected = observe_core_label(backend._Function, fails, outer)
            entries = owner.entries
            actual = observe_core_label(native_class, fails, outer)
            cases.append({'fails': fails, 'outer': outer, 'expected': expected,
                          'actual': actual, 'native_entries': owner.entries - entries,
                          'equal': expected == actual})
    return cases
