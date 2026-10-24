# Hepta agent interface v1

`python -m hepta inspect path.hepta` returns versioned JSON with actual types,
effects, resources, symbol/body spans, call names, source SHA-256, interface
SHA-256, compiler SHA-256 and actual native validation. It is a single-unit
interface, not a claim of whole-repository impact analysis.

## Body replacement

Save a request with the exact hashes returned by inspect:

```json
{
  "schema": "hepta.patch.v1",
  "expected_source_sha256": "COPY_THE_ACTUAL_SOURCE_HASH",
  "expected_interface_sha256": "COPY_THE_ACTUAL_INTERFACE_HASH",
  "symbol": "sum",
  "replacement_body": "{ return 0; }"
}
```

```sh
python -m hepta patch path.hepta --request request.json
python -m hepta patch path.hepta --request request.json --apply
```

The first call previews validation only. The second repeats validation and
applies the exact candidate if still current. The request accepts exactly the
listed keys. Replacement must be exactly one brace-delimited function body;
injecting extra declarations or changing interface/effect/resource contracts
is rejected. All bodies in the candidate compilation unit are checked.

The protocol does not execute the candidate, prove functional equivalence,
change tests, update contracts, grant external permissions, or roll back I/O.
Two implementations with the same signature may compute different results.
The response always carries functional_equivalence_proved=false. Functional
requirements still require independent tests or a future proof layer.

## Concurrency and evidence

Source and interface identities must match before verification. The source is
checked again after validation and immediately before replacement. Cooperating
writers take a sidecar lock and use atomic rename; ordinary file permissions
are retained. The guarantee is cooperative_writers_only, not a filesystem CAS
against every editor ignoring the protocol. A crash may leave a lock to inspect.

Successful validation binds the new candidate, emitted Rust, compiler sources,
rustc identity, target and flags. Backend success requires a nonempty metadata
artifact. Explicitly unavailable compiler paths and unexpected compiler
versions fail closed. This does not attest malicious toolchains or fully bind
arbitrary future link libraries. Link flags/artifact hashes are present in build
reports; accepted foreign assumptions remain visible.

The tool can expose `frontend_only`, `checked`,
`checked_with_external_assumptions`, `rejected` or backend `unknown` states.
`frontend_only` leaves Rust borrow checking not_run. Neither it nor an SMT-like
unknown state is equivalent to complete native validation. No SMT prover is
present in this release.

## Productivity research

The implementation supplies mechanisms, not an empirical productivity claim.
A future evaluation must compare Rust with ordinary tooling, Rust with similar
semantic tools, Hepta with ordinary tooling, and Hepta with this interface.
Measure hidden functional tests, resource/performance constraints, total tool
and token cost, multiple models/seeds, and multi-file changes. Freeze specs and
tests, and isolate projects between training/development/evaluation sets.
No results from that 2x2 study are claimed by the current tests.
