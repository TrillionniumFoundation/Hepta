# Historical upstream repair factorial

This prospective study adapts two actual integer-overflow fixes from
[stb's issue 741 fix](https://github.com/nothings/stb/commit/c38ec91d229cbe56167f8af865c05b3d92db705f)
into HIA assembly and Rust maintenance tasks. It compares each language under
complete-file and exact-patch responses, with the same model, request budget,
source information, public examples and terminal hidden oracle.

The floor-division guard and Euclidean-remainder fixes come from the same
header and historical change. They are correlated samples from one project;
they do not constitute a representative repository-maintenance corpus or show
stable Agent productivity by themselves. Training exposure is unknown.

The complete pinned upstream headers and license texts remain in
`tests/fixtures/c_migration/stb_divide{,_v0_93}`. `UPSTREAM_FIX.json` retains the
primary immutable commit/patch receipt. `UPSTREAM_TASKS.json` binds complete C
capture, selected functions and HIA representations. `tools/capture_hia_upstream_tasks.py`
checks the original functions and updated remainder's Core call-graph inlining
and primitive representation with the existing 10-second all-input validator;
this does not prove C-to-Core refinement. The new floor function's complete
inlining did not prove within that budget. Its proposed rewrite is not used as
an authorized executable. `floor_reference.hiaasm` is instead a separately
authored widened quotient/remainder repair, admitted by the canonical verifier
and the independent finite native/VM controls. This reference choice is fixed
before any model request, independent of subsequent solver outcomes.
The unknown result and the separate invalid-60-second-budget refusal remain
evidence; neither is a successful proof. The Lean budgets are unchanged.

Rust starts from reviewed manual ports of the same historical algorithms.
`tools/qualify_hia_upstream_ports.py` compiles the original upstream C with UBSan,
observes the old overflow, checks the fixed source against a mathematical
oracle, and executes both HIA/Rust ports. Ordinary signed-overflow C behavior is
never treated as a portable reference. Both task domains exclude zero divisors
and `INT_MIN / -1`; historical intermediate-overflow cases inside the intended
domain are exactly the defects being repaired.

`tools/qualify_hia_upstream_factorial.py prepare` verifies native reference and
historical-defect controls, hashes tools/models, and checks actual tokenizer
capacity before any generation. `run` accepts one immutable cohort only. Every
attempt, edit refusal, native failure, timeout, observed token count and model
cleanup is retained. An unobserved token total stays null. Reference controls
are not model answers; hidden evaluation is terminal and never enters feedback.

The current protocol retains the two previously pinned local GGUF models,
uses all four language/interface arms, and declares 16 cells before inference.
The initial 8192-context/4096-output proposal was refused by both actual
tokenizers with zero generations: the largest initial prompt had 6503 tokens
and the canonical floor patch answer needed 6263. Revision 2 gives every arm
the same 32768-token context and 7168-token output limit, retaining the 240-second
request wall limit and two-attempt ceiling. The engine retains 8192 as its old
default; this study explicitly selects 32768 and verifies the owned server's
actual context property and single slot. The original capacity refusal is not
discarded, counted as a completed task or reclassified as model success.
The result remains descriptive even if an arm improves. Human engineering time,
hardware energy and historical acquisition costs remain unknown unless a
separate observed ledger supplies them; they are not silently counted as zero.
