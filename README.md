# Fixed source admission diagnostic

This isolated helper observes CPython 3.14.4 against immutable product commit
`abeef212e34023534d91f8f952280e2a8d0cbde6`, tree
`f2bc61c11104136d3f56e3c4aefa00a4dada910b` (3,055 files).

It verifies all source bytes and modes before and after eight fresh scans and
one instrumented scan. It records standard Path protocol capture, actual scan
maps, timings and complete cProfile data. The source snapshots warm filesystem
caches; fixed-order timings and instrumented times are descriptive.

No product source is changed, and no generator, original business method or native
compiler is executed. All original deadline failures remain unchanged. A successful
helper run means observations were preserved and fixed source remained unchanged;
it is not a Source, Native or whole-program qualification result.

This helper does not write Git objects, statuses, comments or product/audit refs.
Its workflow uses read-only repository permissions and always retains raw evidence.
