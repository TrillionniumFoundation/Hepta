# Explicit Capture admission I/O

Status: STATIC CANDIDATE. No new product, oracle, generator, VM, Native, SQL, or test execution is claimed by this package. The Capture corpus and its qualification budgets are unchanged.

## Two observable responsibilities

The selected Capture entry checks a manifest, the authored HIA source, and the image before it can execute business control. Each entry still reads all three files and rereads all three at the end. Every file read still opens a real descriptor, checks regular type and its pre/post identity, applies the same byte bound, and closes its own descriptor. The image cache can reuse an immutable mapping; it cannot replace these fresh file observations.

Those checks belong to executable admission. The business stable_read and capture_path ports continue to evaluate the original dynamic os, Path, stream, and namespace expressions. The admission module captures POSIX builtins directly from the built-in posix module. It neither captures business-patched os functions late nor routes admission through the user's business provider.

This is a declared capability boundary, not absence of I/O. The new controls record the actual admission open/read/fstat/close operations alongside the unchanged business OS observations. There are still six admission reads and twelve admission fstat returns per installed_store_file_capture call, in addition to business effects. No syscall, elapsed time, descriptor use, or source drift check is described as nonexistent.

R14a exposed the distinction: the unchanged directory-renamed-after-open control observed two original business fstat calls versus twenty-six selected calls. The extra twenty-four came from two admissions (outer capture and its stable_read child), each with six double-fstat file reads. A same-size mutation hook can consequently fire on an executable input before the business file's first stat. Reducing a counter or prewarming imports would not repair that timing.

## Resolver and default source lookup

Binding Path.resolve alone would leave realpath's os.lstat, os.readlink, and os.getcwd lookups dynamic. The new capsule owns the complete resolver traversal. It uses captured builtin POSIX operations, and adapts the actual CPython 3.12 and 3.13/3.14 algorithms and pathlib conventions. The source includes the PSF license and describes the adaptation.

Only the bool strict modes used by the existing admission/source paths are provided. The private API does not promise pathlib's arbitrary subclass overrides or ALLOW_MISSING. Native Capture remains a Linux executable contract. The ordinary source resource helper retains the original Path-based branch on non-POSIX hosts; this package does not claim non-POSIX Native qualification.

The shared _source_resource_path continues to use its own hia_json_preflight_native.__file__ anchor. Checkout selection still means a regular pyproject.toml at that resolved root; otherwise resources remain under the installed hepta/_data root, even when an individual resource is missing. Cwd or HOME never becomes an alternate resource authority. The adaptation preserves <=3.12 symlink-loop RuntimeError handling and the <=3.13 versus >=3.14 is_file OSError rule. These compatibility branches require execution on each claimed runtime; reading the stdlib source is not runtime qualification.

The shared source-path hunk is separate because cold Capture imports json_preflight, emission and Store lifecycle modules, each of which computes source paths. Fixing only Capture.SOURCE after those imports would leave the cold path unresolved. The separate hia_native_helpers.pinned_image extension accepts an owner-supplied admission resolver after the existing scope/PID/thread checks. Every existing caller that omits it retains its original branch. The exact four-part image key, administrator bundle membership, view object, and creator checks remain intact. No helper registry key or administrator bundle version is added.

## Read and failure ownership

A successful builtin open returns a descriptor to one try/finally close. Pre/post fstat, the read bound, and the existing metadata tuple (device, inode, size, mtime_ns, ctime_ns) remain mandatory. The loader's exact digest validation and terminal byte rereads remain in their previous order. Source and image leaf reads retain O_NOFOLLOW; the manifest path still resolves its symlinks first.

Close is attempted once. A failing close is propagated and not retried; its result may be unknown. If a provider opens and then raises before returning the descriptor, the caller cannot invent that descriptor. The new finite fault controls explicitly record these two unknown endpoints. Test-owned cleanup occurs only after the observed endpoint and is never counted as the capsule closing it. This package does not claim arbitrary asynchronous interruption, allocator failure at every bytecode, process loss, or unknown close results are leak-free. It adds no effect replay or business cleanup policy.

## Complete controls and old gates

The new Source class contains five complete methods: same-runtime original path/source-root comparisons, the independently pinned original regular-reader comparison, forty real-descriptor failures, twenty-four resolver failure/control rows, and a fresh cold source/Capture import with business os hooks refusing any call. On <=3.12 the four strerror rows retain the original absent cutpoint rather than pretending the original resolver calls strerror.

The new Native class contains four complete methods: fresh six-read admission and exact terminal drift, a cold selected public route plus all unchanged twelve OS and three race controls, an actual administrator bundle view with fresh admission, and the complete existing installed-worker fixture. The installed wheel must include the exact new module. All new child records bind their process IDs, command, source bytes, raw observations, stdout/stderr, and owned process cleanup. Each consumed byte stream is checked against its original producer pin and reread at the terminal boundary.

No existing Capture Source3, Native8, FD-v2 Native2, original ordinary112 caller, strict-nine574, worker-helper, source/package, or installed-resource method is replaced. Their budgets and expected fields stay unchanged. The old 5101 complete observations remain mandatory and retain all four known GC differences until an actual new full comparison resolves them. Static separation of admission I/O does not prove those differences have changed.

Run the full existing package/source scopes because the shared source-path primitive affects every direct consumer listed in the package's RESOURCE-CONSUMERS.json, plus the new Verification owner after R15 integration. In particular, retain the entire installed-resource module, worker-helper module, JSON preflight Source/Native and ordinary modules, complete Capture gates, and complete source/contract checks on one final source. Do not borrow prior PASS results after changing this dependency.

## Integration

Apply the named exact layers. The three shared registration review copies (helpers, source contract, workflow) are rebased to the actual frozen R15a bytes, independently hash-checked. They preserve all forty-nine helper entries and the original forty-eight-key prefix, Verification's trailing key, every Proof input/CI increment, and the FD v2 gates. The core admission design and private reference functions come from R14a; the other three changed files are byte-identical between those bases. Each shared change is also supplied as a separate exact function/append patch. Apply those hunks if the final tree has moved again; never overwrite later unrelated increments with a review copy.

The new hepta Python module is collected by the existing automatic production-source inventory and normal wheel package discovery. It is also an explicit Capture builder input. The new tests, reader, fixtures, and this document are explicit source-contract inputs. No redundant hepta/*.py SOURCE_FILES registration and no unrelated MANIFEST or NATIVE_SOURCE_FILES item is introduced. The PSF license is present in the installed module itself.

All new CI steps are additional complete classes with independent evidence directories. The existing steps, conditions, original 1800-second module limits, per-command limits, cases, tests, and raw paths remain intact. Dedicated new admission controls use 60-second owned children; the new installed outer owner uses 600 seconds for the entire existing sequence, whose original nested 60-second command limits remain unchanged. Neither is a replacement for an old gate.
