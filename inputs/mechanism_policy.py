"""Test-only ordinary Python policies for the shared HIA control compiler.

These seven names satisfy the finite compiler's original table shape. They are
independent mechanism oracles, not replacements for the four public plan APIs.
"""


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
