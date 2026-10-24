# Comparator transport composition after #26

This draft composes the separate `tools/c2hepta.py` comparator driver hardening
onto frozen #26 (`40744c9d35ddb6614eefe67f0851c71066cb4f68`). It does not
replace or modify `hepta/c_frontend.py` or the scalar same-instance helper.

## Exact donors and scope

- #25: `0f3ba9fe68c2bc1d0194520049fbb1c4e879309a`, based on #20
  `2e47da2c6cbb99506aab9a0b55dd5edbec80221a`.
- #27: `a6773cfa36ce0be6c602ed86c046315487707cf8`, child of #25.

The complete three-file implementation/test net change is transplanted; the
only test adjustment records observed descendant exit **before** fallback test
cleanup, so a harness SIGKILL cannot conceal a product failure. Donor workflow
allowlists for their own branches are intentionally not imported. Production
files are byte-identical to #27. Existing #19 direct-library path guards,
#24 C++ alias rejection, #26 helper cleanup and output publication stay intact.

The donor reproduced two lifecycle failures: timeout after an exited driver
left a pipe-inheriting child alive; successful driver exit with a child's stdio
redirected to DEVNULL also left that child running. Those original RED results
are historical donor evidence, not rerun or relabeled as new findings here.

The four comparator Clang invocations now share bounded capture with a combined
8,000,000-byte stdout/stderr limit checked while reading, existing timeouts,
empty stdin, and preserved successful output and checked exit status. Each
invocation starts its own POSIX session. Finally SIGKILLs any surviving members
of that process group even after successful completion, then reaps the direct
child. Non-POSIX fails closed for this comparator, unlike the scalar helper's
existing non-POSIX direct-child fallback. Descendants escaping the group are
not contained; descendants are not all reaped by the caller. This is not a
malicious-process sandbox, a hard total-memory bound, or universal subprocess
supervision. Tests start and terminate only their own children.

## Validation boundaries

Current exact-source focused/full results are recorded with this draft; donor
qualification, latest #14 features and remote CI claims are not inherited.
No remote CI query, merge, deployment, new tooling or security-setting change.
