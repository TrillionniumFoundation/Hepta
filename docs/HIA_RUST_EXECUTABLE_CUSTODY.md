# Rust shadow executable custody

The Rust shadow runner previously verified the supplied executable bytes,
copied them into a private temporary directory, and then asked `Popen` to open
that pathname. Replacing the temporary file between the copy and execution
could select different bytes while the comparison still retained the original
`shadow_executable_sha256`. Private-directory permissions alone do not protect
against a process with the same filesystem authority.

A real local process control reproduced this boundary: admitted script bytes
printed `admitted`, but replacing the copy immediately before execution made
the child print `replacement` with exit status zero. The regression attempts
the same write at the execution boundary. It does not fabricate a passing
Rust verification or model observation.

## Implemented custody

`hia_rust_crosscheck._run_pinned_shadow` now retains the admitted immutable bytes
in a Linux `memfd`. It requires write, grow, shrink and seal seals, then checks
the full seal mask, exact size and byte readback before launching the child.
The child opens `/proc/self/fd/<descriptor>` with that descriptor explicitly
inherited. No mutable filesystem copy is executed.

The descriptor remains owned until the existing bounded runner finishes its
process-group signal and leader reap. The runner still bounds each captured
stream, enforces its deadline, retains the original leader through
`waitid(WNOWAIT)`, and refuses uncertain group cleanup. Success, nonzero exit,
timeout and output-budget failure all release the retained image. An uncertain
descriptor close cannot produce success and never retries the numeric
descriptor, which might already have been consumed and reused.

The same transport serves static shadow checks and execution protocols v1–v4.
Core verification, request/report formats, budget ceilings, resource ledgers
and production authority are unchanged. The independent Rust code is also
unchanged by this custody fix.

## Platform and trust boundary

This runner already required Linux process-group ownership and `WNOWAIT`.
It now additionally requires usable `memfd_create`, kernel file sealing and
the inherited `/proc/self/fd` execution route. A host or container denying
these mechanisms refuses the comparison; there is no temporary-file fallback.
Linux UAPI constants permit Python builds with older headers, but the actual
kernel operations and complete readback must still succeed.

The interpreter/ELF loader, dynamic libraries, kernel and trusted parent process
remain outside the executable-byte pin. This mechanism does not sandbox an
arbitrary hostile binary, defend a compromised parent, establish semantic
correctness, or promote Rust to production admission authority.

## Reproduction

```sh
python -m unittest tests.test_hia_rust_executable_custody -v
python -m unittest tests.test_hia_rust_crosscheck tests.test_hia_rust_api_v4 \
  tests.test_hia_rust_transport_lifecycle -v
```

These controls exercise real sealed-image execution, refused image writes,
missing sealing support, incomplete seals, changed byte readback, normal and
failed child outcomes, bounded output/deadline cleanup and uncertain final
release. Frozen-source integration results must name the resulting commit;
the historical reproduction and unrelated branch results do not qualify it.
