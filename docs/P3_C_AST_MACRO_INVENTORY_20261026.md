# P3 checked C migration: macro-origin inventory failure closure

A Clang \`-ast-dump=json\` top-level declaration may report
\`loc.spellingLoc\` and \`loc.expansionLoc\`, with **no ordinary byte
offset** on \`range.begin/end\`. Previously \`hepta.c_migrate.migrate_c\`
silently skipped such declarations. This could falsely accept a scalar C
file while silently discarding a macro-generated global, prototype or
function. An actually observed Clang17 AST of \`#define G int hidden=7;\`
followed by \`G\` has that exact shape.

The strict L1 scalar pilot now uses the expansion site to determine the
active translation unit, and **rejects** all macro-generated source-level
declarations with \`E_C_TOPLEVEL\`; unattributable main-file declarations
reject with \`E_C_AST_LOCATION\` rather than disappearing. The positive
\`<stdint.h>\` control retains its normal main-source offsets.

This change adapts the bounded fix from the parallel review PR #195 to the
**current** HIA integration branch, without importing unrelated old AST,
LLVM, Rust, publication or CI files. There is no claim to support arbitrary
preprocessor expansions or to prove a translation-unit inventory is
complete across unlisted build configurations.

Run on a full exact-source checkout:
\`\`\`sh
python -m unittest tests.test_c_migrate_adversarial tests.test_c_migrate -v
python -m unittest tests.test_hia_migrate tests.test_c_project -v
\`\`\`
The larger true \`c2hia\` / C project certification remains OPEN, as do
C++ L2/L3 and source-to-HIA refinement.
\`whole_project_blockers_closed=false\`.
