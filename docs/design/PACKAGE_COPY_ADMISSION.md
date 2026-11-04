# Restricted Package deepcopy invocation admission

This isolated `experiments.package_copy.Owner` extends the shallow-authority profile on frozen #632 (`d05992d401e4d1faa0a40ac6e1c615a8234ff727`). It changes no production code, existing owner profile, or default. The original fourth one-argument `copy.deepcopy` remains the actual copier. No merge or deployment is implied.

## Runtime and input boundary

Only CPython 3.11/3.12 on POSIX is admitted. Inputs are None or exact `Package` objects with the eight canonical state keys: root, name, version, entry, kind, source_root, dependencies, manifest_bytes. Three path fields must be exact native `PosixPath`; name/version/kind exact strings; manifest exact bytes or None; dependencies exact string-keyed dictionaries with exact Package children. Instance protocol shadows and extra fields are rejected. Shared Package, Path, state dictionaries and dependency dictionaries are allowed. Cycles are memoized; real source-package cycles still reject at the earlier source-loader stage. A dictionary reused across state/dependency roles rejects before a memo shortcut.

On 3.11 the consumed `_parts` slot must be an exact list of exact strings. On 3.12 all consumed `_drv`, `_root`, `_tail_cached` slots must already exist; drive/root are exact strings, tail an exact list of exact strings. A cold or partial Path rejects without warming it or invoking its properties. Unused slots are not inspected or traversed. An admitted warm 3.12 Path is copied by the original protocol to an ordinary cold Path containing `_raw_paths`. Legacy owners retain their original cold/partial/monkeypatch behavior.

## Narrow unit and memo algorithm

`package_copy_calls` defaults to 200,000; `package_copy_depth` to 128. Both are positive exact integers. Calls count projected actual `copy.deepcopy` invocations on the validated input, including atomic values and memo hits. Depth counts parent/child deepcopy invocation edges with root depth one, not Python stack frames. Standalone None costs one call.

An iterative streaming preflight uses a fresh simulated memo for each fourth copy. Cumulative counters are not refunded on failure:

- Charge each attempt and its depth before schema inspection, memo lookup and retained child frame.
- On first Package visit, project the atomic class-argument call and its state-dictionary call. Mark Package memoized before traversing state, as genuine reconstruction does.
- On first dictionary visit, memoize before children; stream values before keys in actual `_deepcopy_dict` order. Verify dictionary role before any memo shortcut.
- On first Path visit, charge each constructor argument string. Repeated Path visits cost only the memo-hit call. Marking the Path before components is safe because admitted components are exact atomic strings.
- Exact strings/bytes/None and the internal class argument are not memoized because actual deepcopy returns the same object. The reducer argument tuple does not itself cause a deepcopy invocation.
- 3.12 anchor charging uses a virtual string event, avoiding anchor concatenation or parts-tuple creation in preflight.

For admitted canonical graphs, `N = 1 + 2U + 16S + 2E + C`, where U counts distinct Package identities, S distinct state dictionaries, E entries across distinct dependency dictionaries, C constructor components across distinct Path identities. `1 + 18U + 2E + C` is only the S=U special case. Tests instrument the genuine copier, rather than treating this formula as proof for arbitrary protocols.

Shared state dictionaries can cause a second copied Package to receive only the fields already copied when it is reconstructed. Its output dictionary need not alias the root's dictionary. The profile deliberately preserves this legacy partial-state result, not a normalized clone. Equal but distinct Paths remain distinct; repeated Paths remain aliased within each fresh-memo copy.

## Finite protocol pins

Inspection uses captured static descriptors and identity comparisons. It checks original Package/pathlib class aliases, exact metaclasses, actual MRO element identities, Package copy/reduce/state/new/attribute hooks and state descriptor, and no Package slots except the ordinary empty/missing/None slot-name cache. State keys are checked for exact string type before membership or dictionary lookup.

Copy dispatch/reducer dictionaries must have original identities and exact dict type, including `copyreg.dispatch_table` alias. Entries for Package, native PosixPath, dict, str, bytes, NoneType and type are pinned. Captured helpers include deepcopy, `_deepcopy_dict`, `_deepcopy_atomic`, `_reconstruct`, `_keep_alive`, and copyreg `__newobj__`, `__newobj_ex__`, `_slotnames`. Invoked function positional and keyword defaults are checked, including `_deepcopy_dict`'s captured deepcopy and `_reconstruct`'s keyword-only deepcopy. Static classmethod descriptors and property getters retain function-default checks too.

Path common pins cover the PosixPath/Path/PurePosixPath/PurePath hierarchy, effective copy/reduce/class/attribute/new/init hooks, consumed and constructor-written slots, pathlib's os alias and `os.fspath` (called even for exact string constructor arguments).

- 3.12 additionally pins parts/drive/root/_tail properties and the Path/PurePath construction chain. Warm-only inspection ensures lazy parsing, `_load_parts`, `_parse_path`, flavour operations and `with_segments` are not reached. They are not represented as protected execution surfaces.
- 3.11 additionally pins `_from_parts`, `_parse_args`, flavour identity and exact class/MRO, effective instance and class `parse_parts`, `splitroot`, `sep`, `altsep`, `is_supported` and attribute hooks, pathlib's sys alias and `sys.intern`. The splitroot separator default is checked. Public `parts` is not the consumed reducer property on this version.

References: [CPython 3.11.14 pathlib](https://github.com/python/cpython/blob/v3.11.14/Lib/pathlib.py), [CPython 3.12.14 pathlib](https://github.com/python/cpython/blob/v3.12.14/Lib/pathlib.py), and [copy implementation](https://github.com/python/cpython/blob/v3.12.14/Lib/copy.py).

## Ordering, failure and exclusions

An entry checkpoint runs before finite pins and preflight. There is no callback until the original copy completes; the exit checkpoint may reject without publishing a new handle. No refund follows a failure. Failed quota prevents this fourth real copy, though the loader, shallow copy and three map copies have already occurred. Private seam calls also refuse terminal contexts. Earlier profile and legacy callable/argument lifetimes remain unchanged; the new wrapper clears captured callable and value in `finally`.

This is not an arbitrary-injected-object API, sandbox or atomic snapshot. Finite pins do not protect earlier package-loader operations or arbitrary private code/global mutations, concurrent threads, tracing/signal callbacks, finalizers or interpreter tampering during the callback-free phase. An ordinary trusted runtime is required.

This is **not a hard heap, bytes, allocator, Python-frame, CPU or time bound**. Root/schema/pin validation, memo and traversal storage, string lengths/hashing/concatenation/interning, reducer argument tuples, constructor-created lists, eager 3.11 parsing, actual recursion and native/OS work remain separately unmetered. Path is a protocol with projected constructor argument calls, never an atomic cost leaf.

## Verification

Core tests compare genuine calls and logical depths, exact/one-below and cumulative limits, fresh memos, DAG/cycles, shared state and dependencies, Path aliases/equal-distinct paths, cold/partial refusal, unused slots, schema/subclass rejection, callback failure and no partial handle. Seeded graphs exercise mixed alias topologies. Independent regressions exercise each mutable finite pin and function defaults, constructor/hierarchy mutation in isolated processes, foreign slots without hooks, and legacy partial-state behavior.

The new gate includes every previous 617 hosted control plus new controls; it rejects skips, expected failures and duplicate test identities. The hosted workflow checks both exact candidate and frozen base SHA, runs the 99-case parser and 80-case normal-loader differentials, and executes Python 3.11/3.12 with the pinned Rust toolchain and explicit CC/RUSTC bindings. Merely declaring that workflow is not execution evidence. Local Python 3.12 evidence does not establish Python 3.11 execution; consult the exact-head run result.
