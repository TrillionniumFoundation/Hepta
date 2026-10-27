# HIA P0/P7: descriptor-pinned HSIR wire audit intake

## Frozen starting point

Base: PR #296 exact `f51033e8848d2e0366e7a6eecb3321d442869101`.
No new HSIR producer, optimizer, adapter, compiler or source/native verifier
was introduced. This change hardens the existing
`tools.audit_hsir_wire.load` entry and preserves its historical two
incompatible `hepta.hsir.v0` producer-profile refusal semantics.

## Real bug

The historical audit called `open(path, "rb")` before enforcing the 8 MiB
limit. A path replaced with a FIFO could block forever inside `open()`,
while a symlink could silently redirect the file being audited. Reading a
regular file while another process changes its inode/bytes could also make
the report inconsistent with the selected source.

## Minimal fix

- Use `Path.lstat()` for a nonempty ordinary file with initial size at
  most 8,000,000 bytes. Refuse insecure platforms lacking
  `O_NOFOLLOW` or `O_NONBLOCK`, rather than claiming a pinned intake.
- `os.open(O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)` followed by
  `fstat`, bounded descriptor-only read, second `fstat`, and final
  `lstat`. Require stable device, inode, mode, size, mtime and ctime, and
  exact byte count before passing immutable bytes to the existing JSON
  validator.
- No following symlinks, no accepting FIFOs, no trusting a caller-provided
  hash or summary, no overwriting output. Do not infer producer authenticity
  from filesystem identity or SHA-256.

## Committed tests

```sh
python -m unittest tests.test_hsir_wire_audit -v
python -m unittest tests.test_hsir_wire_producers -v
python -m unittest tests.test_hia_schema_collision -v
```

Adversarial tests cover ordinary JSON acceptance, symlink and FIFO refusal,
zero/oversized file refusal *before open*, lstat→open symlink/FIFO substitution,
and replacement of the inspected pathname after opening a descriptor. The
pre-open FIFO race test asserts the nonblocking flag *before* touching the
FIFO, so removing the guard fails rather than hanging test execution.

Independent Linux CPython 3.13.5 descriptor-reader controls exercised three
basic outcomes (ordinary file accepted, symlink and FIFO rejected). This is
not execution of the complete exact-head Hepta suite. Cargo/rustc and a full
checkout are unavailable in this environment, so no native/LLVM or exact
repository full test pass is claimed.

## Remaining obligations

This P0/P7 input-hardening patch does **not** resolve the historical HSIR wire
collision, authorize unsafe branch merging, establish source→Core/LLVM
refinement, general Memory SSA, C/C++ L2–L3 translation, real-model Agent
benefit, cross-host ABI, physical hardware, or production performance.
`whole_project_blockers_closed=false`.
