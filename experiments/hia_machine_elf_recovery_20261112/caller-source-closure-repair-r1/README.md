# Original compiler caller source closure repair

The original push and PR ELF caller gates remain **HOLD**. Their original
51-test reports each recorded 51 matching loaded/executed IDs, zero anomalies,
no retained-writer calls and a natural 180-second owner with 3-second cleanup.
The outer reader correctly rejected both at its unchanged source-membership
predicate: three actual caller modules were absent from the original cold
source declaration.

The candidate is `1fd48ee2f986009fd6f27289f952603ae36e7259`, exact tree
`c3ca94c57f9bd75f22f2c694e32bca2dfc6b329b`, based only on acffa. It changes
two source files and the support JSON. The exact three observed omissions and
four additional omissions found among the same compiler caller module graph
are recorded separately in REPAIR.json. No original caller source, HIA policy,
reader assertion, timeout, workflow or test denominator changed.

The source-only regression extends an existing method; all eighteen method
names remain. It follows the actual qualifier module providers as Python AST,
without importing or running their native tests. It checks the declaration,
release list, contract and actual bytes, and joins the four fixed ELF hashes.

The static source namespace grows from 779 to 786 files, or 780 to 787 including
the support JSON. The support document was derived by replacing only its
source_identity.files text span after reproducing the original span exactly;
other bytes, including integer literals outside JavaScript's exact numeric
range, were retained. The original coverage bytes and profile remain.

**No repair execution is claimed.** The original CI generator -> coverage ->
generator -> check -> git-diff path is the required independent validation
before the new source can qualify. The old two gates and all original failed
CI outcomes stay unchanged. Raw receipt copies are already durable in the
root's original-gates-root-readback-r1 checkpoint; this document adds the
independent diagnosis, source repair and bounded scope.
