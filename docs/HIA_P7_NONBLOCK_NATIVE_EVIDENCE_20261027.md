# HIA P7: nonblocking artifact and release-evidence readers

Parent: HIA P0 FIFO admission fix `0b071df8dcc2bafdd7ec8d80d19f6f66d1e141bf` (PR #290).

## Concrete issue and fix

Both `hepta.artifact_publication._read_exact` and
`tools.release_check._read_regular_evidence` previously performed `lstat`
and then `os.open(O_RDONLY | O_NOFOLLOW)` on a mutable pathname. A FIFO
replacing the checked regular inode could block the latter call *before*
`fstat` could reject it. These existing admission readers now require
`O_NONBLOCK` with `O_NOFOLLOW`, retaining the full original inode, type,
size and timestamp identity rechecks and no-replace publication behavior.

Qualification JSON evidence additionally has a 64 MiB upper limit and
cannot be empty. Oversized sparse files are refused before opening;
reading at most `MAX_RELEASE_EVIDENCE_BYTES + 1` bytes enforces a bounded
allocation and the exact extent must match the original stat. Large
binary artifacts are not release JSON reports and remain separate.

## Regression controls

The two original in-repository suites now swap an initially regular
pathname with an actual FIFO after the preliminary stat. The mocked
`os.open` entry asserts `O_NONBLOCK` *before opening*; a regression
fails as a test assertion instead of hanging. Other tests cover a
sparse oversized evidence file that must never be opened, and an
empty evidence file that must not qualify.

```sh
python -m unittest tests.test_artifact_publication tests.test_release_file_identity -v
python -m unittest tests.test_release_evidence tests.test_release_collection -v
```

An independent Linux subprocess control reproduced FIFO blocking without
`O_NONBLOCK` and immediate return when it was present. The complete
exact-HEAD Hepta suites, pinned native toolchain and Rust/Cargo paths
have not executed in this environment. This is a narrow filesystem
admission/availability fix, not a proof of compiler or source-to-native
correctness. `whole_project_blockers_closed=false`.
