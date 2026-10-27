# HIA P7 shadow subprocess-group cleanup — 2026-10-26

**Scope:** small security-boundary correction on the existing *opt-in*, pinned
`hepta.hia_rust_crosscheck._run_bounded_shadow` transport. This is **not**
the production HIA/Core verifier, not a native sandbox, not a general OS
process-containment guarantee and not a full P0–P7 closeout.

## Failure condition

The original finally block only invoked `killpg` when
`proc.poll() is None`. A launcher that spawned a descendant with inherited
stdout/stderr, then exited successfully, made `proc.poll()` non-None while
the surviving descendant still kept the transport pipes open. A deadline
therefore rejected the shadow, but incorrectly left the descendant running.

The corrected code records successful **completion of the entire transport**
(including pipe EOF and `wait`), and on all unsuccessful exits kills the
fresh-session process group *before* reaping the leader. It never treats a
leader's exit status as evidence that descendants or their inherited pipes
are gone. The canonical Python `verify_program` remains mandatory and no
unproved safety claim is promoted.

## Regressions and local independent control

`tests/test_hia_rust_crosscheck.py` now includes an actual Linux subprocess
negative control: an exited Python launcher forks a 30-second descendant,
which inherits both pipes and records its PID. The test demands a deadline
rejection and confirms the descendant is no longer running, treating a
reparented zombie as terminated and cleaning up after itself even if the
assertion fails.

Separately in this authoring container, a small standalone Python control
using the same process-group lifecycle was executed against both cleanup
rules with a 3-second deadline:

| Cleanup condition | Deadline error | Descendant active after rejection |
| --- | --- | --- |
| Old `proc.poll() is None` | Observed | **Yes** |
| New `not completed` | Observed | **No** |

That standalone control proves the local Linux process-group bug and remedy,
not execution of the complete in-repository Hepta test file on the exact
committed SHA. The latter must be executed from a full checkout:

```sh
python -m unittest tests.test_hia_rust_crosscheck -v
python -m unittest tests.test_hia_rust_crosscheck_cli -v
```

## Remaining authority and OS limits

- The crosscheck runner accepts an explicitly supplied SHA-pinned executable;
  digest identity **does not make it a safe program**. It remains an opt-in
  developer tool, not a sandbox for attacker-controlled code.
- A descendant that intentionally creates a new session or closes both output
  pipes and remains alive after an otherwise successful transport is outside
  this *failure-path* fix. Production adversarial confinement needs kernel
  enforcement (cgroups/namespaces/seccomp and full-process-tree supervision).
- No pinned Rust toolchain, full Hepta parser, emitted LLVM binary, Agent model,
  physical GPU/DMA board, performance profile or OS fault injection was
  executed as part of this isolated change.

`whole_project_blockers_closed=false`.
