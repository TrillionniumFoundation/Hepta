# Shared Core and machine-plan frame primitives

The shared continuation executes the retained Core-lowering and four machine-plan
policies in HIA. Python services each exact issued primitive after the HIA claim,
and acknowledges its actual result. This component does not replace the remaining
backend owners or qualify a current cold build by itself.

## CALL operand ownership

The complete admitted Plan policy has 100 CALL instructions; Core lowering has
409. Every callee and argument is a unique temporary slot, is not a cell, and is
listed in that instruction's consume vector. The source control checks every
instruction, including the full literal keyword shape.

Once HIA has claimed a CALL, its transport moves each temporary reference into
CPython's ordinary CALL expression. The later HIA acknowledgement consumes the
logical births and retires already empty physical slots. A lost acknowledgement
retains unknown custody and cannot authorize replay. Named original locals and
shared cells remain under the existing HIA retirement protocol.

The five production keyword shapes are explicit direct calls: two positional
arguments plus `allow_leaf_registers`; no positional arguments plus `key`; no
positional arguments plus `caller_clobbered_leaf_registers` and
`leaf_opcode_inventory`; one positional argument plus `default`; and one
positional argument plus `word`. Three additional direct shapes support the
independent mechanism fixture (`first`/`text_alignment` with zero, one or three
positional arguments). Unreviewed private policy shapes are refused. Adding a
future policy requires its literal call shapes and actual lifecycle controls;
the transport does not substitute `*tuple`/`**dict` expansion.

## Value-context short circuit

On the onward edge of `left and right` or `left or right`, HIA issues RELEASE for
the consumed left temporary before evaluating the right expression. On the
short-circuit edge the exact left object remains the expression result. Its
identity and any later truth conversion are preserved. Conditional expressions
using the separate condition compiler retain their existing control flow.

## Permanent controls and qualification boundary

`tests.test_hia_machine_frame_shared_native` has two Source controls and three
Native controls. The Native fixture compiles its seven ordinary test-policy
functions into a separate real HIA image. It runs all 120 original comparisons:
short circuit and onward evaluation, left truth failures, right failures, result
identity, second truth, zero through four positional operands, fixed keywords,
aliases, retained errors, and two outer handled-exception states. Complete HIA
frames, input/output/workspace bytes and both canaries are independently compared
with the retained Core VM. A real post-CALL acknowledgement interruption verifies
once-only effects and unknown custody.

The additional Core-lowering test invokes the exact retained `_Function.label`
against selected native lowering with fresh temporary receiver and argument
objects. It holds the original error until its final release without detaching
the traceback or forcing collection. The original 22 Core controls remain; the
component now has 23, followed by the unchanged 51 machine and 50 Core callers.

The mechanism fixture uses `HEPTA_HIA_CORE_LOWERING_COLD_REPORT` for matching-source
cold admission, or the mutually exclusive explicit
`HEPTA_HIA_MACHINE_FRAME_DEVELOPMENT_COMPILER`. Its optional evidence directory is
`HEPTA_HIA_MACHINE_FRAME_EVIDENCE`, which must be new. The compile retains the
original 20-second limit and original compiler profile. No production manifest or
default selector is added by this test fixture.

Development observations and each CPython version remain separate. The original
R3 104/120 observation, the first moved-keyword 114/120 observation, and their
complete raw inputs are retained; later passing results do not overwrite them.
Current-source cold, the complete qualification runner, and whole-native status
require their own fresh evidence.
