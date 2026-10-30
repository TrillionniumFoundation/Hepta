# Scalar translation receipt dependency identity

The independent scalar translation validator previously set `validator_sha256`
to the hash of `hia_translation_validation.py` alone. A revision to a canonical
admission rule, the shared semantic kernel, or the interpreter could therefore
leave that recorded checker identity unchanged. This was a provenance and
freshness limitation: receipt consumption already reverified the actual Core
and reran the SMT query, so an old receipt was not independent authority to
approve a transformation.

The fingerprint now covers a versioned local source closure: the validator,
canonical Core verifier, schema registry, opcode rules, composite elaborator,
bounded JSON preflight, shared semantic kernel, concrete interpreter and its
bounded-memory implementation. Names and exact source bytes enter the digest.
Every dependency must be readable. A receipt from a different dependency
revision fails the existing identity comparison even if a fresh query still
proves the same program pair equivalent.

The accepted scalar profile, behavior comparison, canonical Core checks, SMT
query and fresh replay requirement are unchanged. No new instruction rewrite,
loop profile, resource transformation or backend proof is introduced. The
fingerprint describes repository source provenance; Python, Z3 and the host
remain trusted. It is not runtime attestation or an LLVM/machine-code refinement
theorem. In particular, the solver version field is not a new binary attestation
of Z3.

`tests/test_hia_translation_identity.py` independently walks the actual relative
import graph to check closure completeness, injects virtual source-read changes
without editing other modules, and checks missing dependencies and invalid Core
refuse proof. Its separate SMT test class uses real Z3 to confirm that changed
dependency identities invalidate old receipts after an actual successful proof
replay, and that a forged matching identity cannot turn an actual counterexample
into a proof. If Z3 is unavailable, those SMT tests are explicitly skipped and
must not be reported as passed qualification.

Run with the repository's optimization dependencies installed:

```sh
python -m unittest tests.test_hia_translation_identity -v
```

Evidence previously recorded under commit
`03c8205271dc5e8f9c5cad806e46056bffe2bc02` retains that original source identity.
The updated implementation must be published and registered before it supplies
new prospective experiment evidence.
