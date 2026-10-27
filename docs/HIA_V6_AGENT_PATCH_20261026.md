# HIA v6 Agent mutation impact: strict schema and capability replay

Integrates the **existing** HIA Agent Patch Impact verifier from PR #190's
newer exact source, instead of leaving an older donor copy in the v5/v6
chain. A forged unhashable \`schema\` in a patch receipt is rejected as
\`E_HIA_IMPACT\` before dictionary membership or trusted report generation.
The reusable PatchResult schema/claim inventory remains exact, and
\`native_executed\`, \`external_callers_revalidated\` and behavioral
equivalence stay explicitly **false**.

The sole \`apply_program_patch\` mutation authority, \`verify_program\`
semantic verifier, and read-only \`analyze_patch_impact\` observer remain
unchanged. New \`tests/test_hia_v6_agent_patch.py\` exercises a v6
\`buffer.fill_range\` → v6 \`buffer.fill\` candidate with unchanged ABI,
stale/false proof nonclaims, actual VM change, and rejected owner capability
forgery; it also reruns the unhashable schema regression on the v6 carrier.

### Exact checkout validation

\`\`\`sh
python -m unittest tests.test_hia_v6_agent_patch tests.test_hia_patch_impact \
  tests.test_hia_v5_agent_convergence tests.test_hia_range_fill_v6 -v
\`\`\`

No Agent real-model/provider A/B or human-labor economics is established.
\`whole_project_blockers_closed=false\`.
