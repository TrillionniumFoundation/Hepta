# Complete CLI JSON boundary audit

**Conclusion:** the frozen r4 HIA formatter is a reusable layout owner for its declared compact-byte input. It is **not a drop-in replacement** for either whole CLI JSON helper when composed with the current `bounded_json_wire`. Object serialization, Unicode/nonfinite policy, original key sorting and type support, exception priority, and the output-effect boundary still need an owner with the original semantics.

This is a source audit of exact product commit **9704596acc4470bd0042838586602e26bac7b3d1**, tree **c3ca94c57f9bd75f22f2c694e32bca2dfc6b329b**, and r4 formatter source commit **8357db004130819a82f44451e8b6e552aa93f100**. The audit changed no product, profile, gate, selector, workflow or original result. There was no local/remote Python, HIA compilation, CLI execution, Actions trigger, or new product test. One small V8 byte-arithmetic calculation is separately recorded as analysis, with its first failed character-class guard and corrected result both retained.

The complete source identities are in [SOURCE-PINS.json](SOURCE-PINS.json), structured findings and all 15 action mappings in [AUDIT.json](AUDIT.json), and the unexecuted differential plan in [PROSPECTIVE-CONTROLS.json](PROSPECTIVE-CONTROLS.json). Original HOLD/FAIL/UNKNOWN and current CI results remain unchanged.

## 1. The two actual entry contracts

The exact [cli.py](https://github.com/TrillionniumFoundation/Hepta/blob/9704596acc4470bd0042838586602e26bac7b3d1/hepta/cli.py) has two different calls to the standard library:

| Property | `output_json(value)` | `publish_json_view(value, destination)` |
|---|---|---|
| Object serialization | `json.dumps` | `json.dumps` |
| `ensure_ascii` | Explicitly `False` | Default `True` |
| `allow_nan` | Default `True` | Explicitly `False` |
| Key ordering | `sort_keys=True` | `sort_keys=True` |
| Layout | `indent=2` | `indent=2` |
| Intermediate result | Python Unicode string | Python Unicode string |
| Final newline | Added by `print` | Added before encoding/staging |
| External representation | The selected Python text stream decides encoding/error behavior | `.encode()`, hence UTF-8, after ASCII escaping |
| Explicit output byte/node/depth ceiling | None | None |
| Successful result | `None` from the helper | Publication receipt, including a late `value["schema"]` read |

The defaults are confirmed against official [CPython 3.14.4 json package source](https://github.com/python/cpython/blob/v3.14.4/Lib/json/__init__.py) and [encoder source](https://github.com/python/cpython/blob/v3.14.4/Lib/json/encoder.py). No explicit product ceiling does not imply infinite memory or recursion: the original interpreter's allocation limits, recursion behavior and integer-to-decimal digit limit still apply.

The selected CLI does not remove these calls. In [hia_cli_native.py](https://github.com/TrillionniumFoundation/Hepta/blob/9704596acc4470bd0042838586602e26bac7b3d1/hepta/hia_cli_native.py), effect 20 invokes `self.cli.publish_json_view` and effect 22 invokes `self.cli.output_json`. The separately native driver-error formatter is already a narrower path; it must not be used as evidence that arbitrary ordinary result serialization is native.

### Actual action routes

All 15 routes are recorded explicitly in AUDIT.json. The size-relevant grouping is:

| Actions | Value sent to the JSON helper | Separate publication behavior |
|---|---|---|
| capabilities, catalog, verify | Generated capability/catalog/report dictionaries | No JSON-view publication |
| inspect | Newly constructed indexed operation view | No explicit pretty-output ceiling |
| import-assembly, normalize | Full program without `-o`; program publication receipt with `-o` | `publish_program` writes canonical program bytes |
| patch, edit-apply, edit-batch-apply | Receipt containing a full revised program without `-o` | `publish_program` writes canonical bytes with `-o` |
| impact | Combined patch and impact view | Ordinary JSON stdout |
| edit-query, edit-batch-query | Prepared query, or JSON-view publication receipt | These are the two callers of `publish_json_view` |
| build, check-assembly | Result dictionary before the exit-status truth decision | Existing tests require this observation order |
| render-assembly | Assembly text directly without `-o`; JSON publication receipt with `-o` | Assembly text is a distinct non-JSON output |

The program publication and assembly publication paths should not be silently rerouted through the JSON-view serializer.

## 2. Why the current bounded wire cannot be substituted wholesale

The relevant existing code is [bounded_json_wire and its reference](https://github.com/TrillionniumFoundation/Hepta/blob/9704596acc4470bd0042838586602e26bac7b3d1/hepta/hia_program_tools.py) and [the selected native wire adapter](https://github.com/TrillionniumFoundation/Hepta/blob/9704596acc4470bd0042838586602e26bac7b3d1/hepta/hia_json_wire_native.py).

That API already has its own public bounded contract: an exact integer maximum through 8 MiB, a node ceiling of `min(maximum, 262144)`, depth 128, reverse-DFS preflight, exact builtin values, key-conversion collision checks, rejection of isolated surrogates even with ASCII escaping, and nonfinite-number refusal. Those are deliberate semantics of bounded Agent wire. They are not implicit semantics of the two CLI helpers.

There are concrete, independent mismatches:

1. **Nonfinite numbers.** Ordinary stdout `json.dumps` can emit `NaN`, `Infinity` and `-Infinity`. Publication refuses them. The current wire has no corresponding `allow_nan=True` behavior. Passing a literal through r4 because its scanner happens to copy it would not satisfy r4's declared valid-JSON input precondition.

2. **Isolated surrogates.** The publication helper's default ASCII escaping can encode an isolated surrogate as an ASCII escape and publish the result. The wire explicitly refuses every surrogate. The stdout helper retains a Python Unicode string: a StringIO-like writer can accept the surrogate, while a strict UTF-8 stdout may raise later. Premature UTF-8 conversion changes where, and sometimes whether, the operation fails.

3. **Standard type support.** The original JSON encoder accepts standard builtin subclasses, including integer enums, whereas the wire observer classifies exact builtin types and treats other values as opaque. The audit does not require claiming arbitrary replacement of private encoder monkeypatches; ordinary subtype behavior alone establishes that the existing exact-type profile is narrower.

4. **Key ordering.** Original dictionary keys are sorted before their conversion to JSON strings. Numeric keys 2 and 10 therefore sort numerically; sorting their rendered strings would reverse them. Mixed incomparable keys fail during sorting. The bounded wire's preflight can reject key collisions or invalid values before that original sorting failure. The claim is not that every mixed-key collision would otherwise serialize successfully: with the CLI's `sort_keys=True`, many such inputs already raise TypeError, at a different boundary.

5. **Error order and type.** Reverse DFS can inspect a later value before the first value the original encoder would reach. Wrapping TypeError/RecursionError into `HIAEditRejected` also matters: `_reference_hia_main` catches ValueError-family errors but not those original exception classes. A wrapper can change propagation into an `E_DRIVER` report and exit 2.

6. **Resource domain.** An ordinary helper value can exceed 8 MiB, 262144 nodes, or the wire's depth 128 and still be inside the original interpreter's domain. A new bounded refusal at these helpers would be a behavior change. Existing bounded input gates should remain where they already are.

Existing wire tests establish equivalence to `_reference_bounded_json_wire`. They do not establish equivalence to `json.dumps(..., indent=2)` in either CLI helper.

## 3. Effect and exception order must survive the migration

### Stdout

The entire `json.dumps` result is evaluated before `print` begins. A serializer failure cannot have emitted a JSON prefix to stdout through this helper. Conversely, once printing begins, the text stream can fail after part of the output. The newline remains a print effect rather than an extra byte silently appended to a raw-fd write.

The concrete boundary includes the text stream's write calls and exception objects. Replacing `print` with `os.write`, `sys.stdout.buffer.write`, or token-by-token stdout streaming changes supported destinations and error timing. A missing stdout is also not permission to skip argument serialization; function arguments are evaluated first.

### JSON-view publication

The original order in cli.py is:

1. Import/bind `publish_verified`.
2. Convert the destination to an absolute Path.
3. Refuse an existing destination or destination symlink.
4. Create parent directories.
5. Refuse a parent whose resolved path differs.
6. Serialize with ASCII escaping and nonfinite refusal.
7. Append one newline and encode the complete payload.
8. Create the temporary staging directory and exclusive staging file.
9. Write, flush, and fsync the full payload.
10. Call the existing no-replace byte-verifying publisher.
11. Exit the temporary-directory context.
12. Read `value["schema"]` while constructing the returned receipt.

An existing target therefore wins over an invalid value. A new parent can remain after a later serialization failure. A serializable dictionary without `schema` can publish successfully and only then raise KeyError. Moving validation or serialization ahead of these steps would change actual behavior, even if that alternative ordering appears tidier.

The [existing artifact publisher](https://github.com/TrillionniumFoundation/Hepta/blob/9704596acc4470bd0042838586602e26bac7b3d1/hepta/artifact_publication.py) verifies exact bytes and inode identity, uses a no-replace link, and removes only its own link on an identified publication failure. It has no universal JSON 8 MiB limit to inherit. Its selected-owner lookup and existing tests remain separate responsibilities; the JSON change must not bypass them.

## 4. Input bounds do not establish a pretty-output bound

The actual [program admission](https://github.com/TrillionniumFoundation/Hepta/blob/9704596acc4470bd0042838586602e26bac7b3d1/hepta/hia_program.py) limits canonical compact program bytes to 8 MiB, nodes to 262144, and depth to 64. Identifiers have at most 128 ASCII characters. The source has no additional number-of-operations ceiling in ordinary function-shape checking. Compiler-specific SSA limits do not turn into a limit on ordinary normalize output.

[Single-query preparation](https://github.com/TrillionniumFoundation/Hepta/blob/9704596acc4470bd0042838586602e26bac7b3d1/hepta/hia_edit_query.py) and [batch-query preparation](https://github.com/TrillionniumFoundation/Hepta/blob/9704596acc4470bd0042838586602e26bac7b3d1/hepta/hia_edit_batch.py) already call bounded wire with a 1 MiB compact-query limit. The respective response inputs are 16 KiB and 64 KiB. These are useful established bounds for those producers, but are not a universal limit on the rendered CLI output.

The audit includes a deliberately simple ASCII size witness:

- One v1 function, one entry block, no parameters, effects or resource values.
- 25000 independent `const u32 = 0` instructions, each with a unique 128-character SSA identifier.
- Return the final scalar. Earlier scalar values can remain unused under the inspected checker rules.
- All dictionary keys are constructed in the same sorted order used by the original encoder.

The separate V8 arithmetic result is:

| Quantity | Bytes/count |
|---|---:|
| Compact ASCII program | 5,150,357 |
| Structural nodes, excluding dictionary keys just as the original counter does | 225,020 |
| Maximum value depth | 9 |
| Indent-2 ASCII text, no newline | 10,450,598 |
| Stdout text including final newline | 10,450,599 |

For this fixed shape the formulas are compact bytes `357 + 206*n`, pretty bytes `598 + 418*n`, and nodes `20 + 9*n`. This is **byte arithmetic and source reasoning, not a successful Hepta validation run**. Before promoting it into a product regression case, execute the original program admission and retain that real result. The arithmetic program's first incorrectly escaped ASCII guard aborted; both that input/error and the corrected calculation are retained instead of being called product test results.

There is a necessary distinction concerning r4: **its 8 MiB check is on input, not output**. The HIA output routines use the supplied capacity. The witness's compact representation is below that input cap; an appropriately sized measured output buffer is not ruled out by the formatter source. The witness demonstrates why a bridge must not allocate or cap every output at 8 MiB. It does not claim an existing r4 output rejection.

More generally, inspect adds operation indexes and normalization metadata, and patch/edit receipts may embed the entire program. A full-result or pretty-size guarantee cannot be inferred merely from a source program's canonical byte limit.

## 5. What r4 can own now, and what remains

The exact [r4 design](https://github.com/TrillionniumFoundation/Hepta/blob/8357db004130819a82f44451e8b6e552aa93f100/experiments/hia_json_pretty_20261112/bulk-source-r4/DESIGN.json) and [HIA source](https://github.com/TrillionniumFoundation/Hepta/blob/8357db004130819a82f44451e8b6e552aa93f100/experiments/hia_json_pretty_20261112/bulk-source-r4/json_pretty.hiaasm) define valid compact UTF-8 JSON already admitted by the bounded wire profile as the input.

| Responsibility | Current r4 |
|---|---|
| Recognize structural punctuation outside strings for formatting | HIA |
| Preserve existing key order and scalar/string lexemes | HIA |
| Two-space indentation and structural whitespace | HIA |
| Measure length and emit with supplied capacity | HIA |
| Bulk span copy and space fill | HIA |
| Traverse Python values or observe subclass behavior | Absent |
| Choose ASCII escapes versus original Unicode | Absent |
| Sort keys, format integers/floats, decide NaN policy | Absent |
| Apply original JSON exception priority and recursion behavior | Absent |
| Decide CLI publication and stdout effects | Absent |
| Full independent JSON parsing | Explicitly outside scope |

Mode 0 measures; mode 1 emits. The ordinary workspace has a 32-byte header and a 129-byte stack. Only status 0 admits a result. Failed output prefixes/lengths are not usable results. There is no final newline in this kernel.

A narrow bridge can close this layout boundary with immutable, disjoint buffers and a measured allocation. The existing HIA string escaper, finite binary64 formatter, integer handling, graph observer concepts, and key-comparison machinery are reusable sources for the later object owner. Their entry-point restrictions and traversal order cannot simply be inherited by the wider CLI API.

Calling host `json.dumps` in compact mode and then r4 leaves the serializer in Python. It also requires a separate compatibility check: [CPython 3.12.0](https://github.com/python/cpython/blob/v3.12.0/Lib/json/encoder.py) only selects its C encoder for one-shot calls with `indent is None`, while the original CLI uses indent 2. Thus switching to a compact intermediate changes its implementation path. Official 3.14.4 and 3.14.10 encoder.py are byte-identical and can use the C encoder with indent 2; their C list/dict traversal bodies differ in retaining references across foreign callbacks. That difference is recorded as source evidence, not a new observed failure.

## 6. Existing tests: what they actually cover

The exact [native CLI module](https://github.com/TrillionniumFoundation/Hepta/blob/9704596acc4470bd0042838586602e26bac7b3d1/tests/test_hia_cli_native.py) contains 17 methods; the [ordinary entry module](https://github.com/TrillionniumFoundation/Hepta/blob/9704596acc4470bd0042838586602e26bac7b3d1/tests/test_hia_agent_entry.py) contains six. This audit neither ran nor changed them.

| Existing control | Relevant evidence and limit |
|---|---|
| All 15 real actions and publication branches | 23 small-fixture comparisons of outcomes and files; not every possible result graph |
| Native error JSON and active exception context | Includes Unicode and an isolated surrogate; deliberately forbids general output_json on that narrower selected error path |
| Parser stream write failures/missing stdout | Important text effects, but exercises help/version rather than arbitrary result serialization |
| Output before result truth | Explicitly covers check-assembly/build ordering |
| Read ceilings and Unicode-error publication | Input 8 MiB, response 16/64 KiB, invalid UTF-8/symlink/missing reads; does not impose an output 8 MiB bound |
| Six original entry cases | Real operations, publication preservation, refusal and native object path; no direct arbitrary JSON-value matrix |
| Installed wheel | Real isolated CLI installation and declared-resource checks; general JSON serialization is still hosted |
| Bounded-wire tests | Surrogate, key collision, budget, reverse DFS, number and native-wire equivalence to its bounded reference |
| Publication tests | No-replace, exact-byte/inode and failure ownership; no assertion that JSON serialization can move before path effects |

Do not remove or reinterpret these original cases. The new prospective controls in PROSPECTIVE-CONTROLS.json add the concrete mismatches listed above and preserve all original methods.

## 7. Recommended next implementation

### First finish the byte-only owner

Implement the isolated r4 bridge as currently planned, without a public CLI hook. Admit its fixed input representation, freeze the buffer, run measure then emit with the actual measured capacity, and check status, length, source immutability and buffer bounds. Keep newline and external output out of it. This produces a precise reusable component without claiming the object-to-JSON problem is solved.

### Add the missing serialization owner with the original two option sets

The next owner needs to choose JSON structure, key order, strings, numbers and traversal in HIA while asking the host for individual mechanical observations and necessary foreign operations. It must account for:

- The original supported builtin and subtype domain.
- Original-key sorting, including comparison failures before value encoding.
- Active-path cycles versus shared aliases.
- Nonfinite stdout values and publication refusal.
- Isolated-surrogate Unicode text and ASCII-escaped publication.
- Finite float spelling, large integer conversion/digit-limit behavior.
- Original error classes, args, context/notes and first-error order.
- Existing interpreter resource behavior without adding the Agent wire's 8 MiB/node/depth policy.

The public stdout representation cannot be restricted to valid UTF-8 bytes: Python Unicode can contain isolated surrogates. A codepoint-oriented result or equivalent lossless representation can preserve that domain until the existing text-stream operation. Publication can produce ASCII escaped JSON before its existing UTF-8 encode step.

Avoid a graph preflight followed by a second independent observation pass. If layout needs two passes, capture the original traversal once and replay immutable tokens or bytes. For outputs whose compact representation exceeds r4's current input domain, a future continuation/chunk representation can reuse its layout primitives; silently rejecting or retrying through the old serializer after callbacks is not a complete replacement.

### Integrate at the existing helper/effect boundaries

Only after the object domain is accounted for should the ordinary helpers select the new owner. Preserve the file preflight and mkdir ordering, post-publication schema read, string-before-print boundary, and output-before-result-truth behavior. Keep the existing no-replace publication owner and its actual selector/readback point.

Finally run the direct helper controls, unchanged 17-method CLI module and six-method ordinary module, source/image admission and installed-wheel controls on the actual supported interpreters under the original gates. Layout-only source spies and a later whole-serializer spy are different evidence: banning Python's encoder is appropriate only when its responsibility has actually moved. No native or whole-CLI closure is claimed by this audit.
