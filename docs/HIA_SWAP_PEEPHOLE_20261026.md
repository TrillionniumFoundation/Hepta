# HIA v4 strict byte-swap peephole (opt-in)

New module \`hepta.hia_swap_opt.rewrite_byte_swap\` is a **non-authoritative
optimization pass**, not a new compiler or a replacement for the one HIA Core
verifier. It accepts independently verified v1–v4 Core and examines each
function's lexical operations with exact whole-function SSA use counts.

Only the **consecutive** pattern below may be rewritten:

\`\`\`text
a:u8 = buffer.load(loan, left)
b:u8 = buffer.load(loan, right)
buffer.store(loan, left, b)
buffer.store(loan, right, a)
\`\`\`

The two loads must originate from the **same** already-validated mutable
loan, and each loaded SSA result must have exactly one use, in the opposite
store. There can be no intervening operation, no additional output,
unknown attributes or external/CFG use of either loaded value. Both bounds
are checked before the original stores. The v4 target checks both bounds
before either load/store, so finite normal/trap behavior is preserved for
this bounded pattern, including identical indices and invalid offsets.
This is an implementation argument and testable hypothesis, **not a formal
source/native refinement proof**.

The pass does not mutate the caller's Core, silently change function ABI or
effects, or substitute an unverified IR. It sets schema v4 only if it actually
changed code, then **rechecks the entire candidate** with the existing
\`verify_program\`. If there is no exact match, the input's verified bytes
remain unchanged. LLVM consumes the resulting same verified HIA program.

### Verification

\`\`\`sh
python -m unittest tests.test_hia_swap_opt tests.test_hia_swap_v4 \
    tests.test_hia_program tests.test_hia_program_llvm -v
\`\`\`

Tests include an exact positive pattern, 20 finite interpreter comparisons,
owner/loan cleanup, extra SSA uses, wrong stores, rejected input and direct
LLVM native profile/identity checks. The standalone optimizer does not
establish general C/C++ equivalence, all-pointer aliasing, full Memory SSA,
formal proof, GPU acceleration, physical devices or production p99.
\`whole_project_blockers_closed=false\`.
