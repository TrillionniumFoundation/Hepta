# HIA Core version-upgrade authority (P0)

This narrow API is for existing **standalone executable byte-owner HIA**
programs; it does not import HSIR, Resource IR, C/C++ source, arbitrary
compiler output or the independently developed composite/task Core.

\`hepta.hia_core_upgrade.upgrade_core_to_v6(document)\` first passes its
complete input through the canonical \`hia_program.verify_program\`, updates
only the program \`schema\` field, then verifies the entire v6 program again.
It explicitly asserts that the full operational payload and CFG remained
unchanged. It returns an immutable VerifiedProgram plus a receipt containing
both byte hashes and appropriately false proof claims.

The historical \`hepta.hia.program.v2\` version is **not automatically
upgradeable**. At least two independent producer histories used this same
label for different semantics (bulk byte memory versus nominal/task types).
Even a well-formed local v2 program must reject with
\`E_HIA_VERSION_COLLISION\`. A future adapter must assign an unambiguous
wire version, independently establish the producer contract and explicitly
qualify every instruction and effect; merely rehashing bytes cannot do that.

Other versions admitted here: v1, v3, v4, v5 and v6 (idempotent).
Accepted source/target shapes are checked, but neither compiler refinement
nor cross-version runtime equivalence, source authentication or whole-language
soundness is proved by the upgrade receipt.

Reproduce in the full Hepta checkout:

\`\`\`sh
python -m unittest tests.test_hia_core_upgrade tests.test_hia_program \
  tests.test_hia_program_llvm -v
\`\`\`

The normal P1/P2 executable owner/memory SSA and exact native LLVM
differential tests, C/C++ broad migration and physical/Agent qualifications
remain open. \`whole_project_blockers_closed=false\`.
