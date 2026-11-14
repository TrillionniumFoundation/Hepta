# CLI op8: an existing HIA policy reaches its actual caller

Status: **author only**. No project module, candidate test, HIA compiler, native
image, VM, default entry or CI has been executed by this authoring task.

## Exact base and change

The base is the actual restored/quarantine-generation source at
`/workspace/hia-patch-terminal-quarantine-execution-r1-dda7/source`.
Only the three existing paths in `AUTHORING.json` are proposed product changes.
Full original bytes are in `before/`; new bytes are in `overlay/`.
The candidate has not been applied to that source or to a separate 3210-file
product view. Its external test is not a product file and must remain outside
either view. The three-path overlay preserves the file count of its eventual
base; it does not grant that base a qualification result.

`NativeReportCli.prepare` already installs a weak-reference closure for op9.
The candidate adds only op8 to that same explicitly selected owner. The op8
prefix preserves the original discovery-capability path, including the second
permission read when consuming that port. Without that permission, it creates
`value`, `register`, `field`, and `argument` in the original order and retains
all four bound methods for the original effect interval. It also retains the
original `zero` local. It then performs the actual `value(a).as_dict` lookup
once and hands the resulting callable to `invoke_bound_as_dict`.

The new bound entry is an explicit copy of the already reviewed report entry,
with only the method name and `report`/`as_dict` literals changed in its AST.
It selects mode 6 only for the exact original `VerifiedProgram`, unchanged
method descriptor/function/code, original MRO and attribute protocol, and no
instance shadow. A foreign/replaced/captured-late callable is invoked once as
the actual operand. It is not looked up again or queried for metadata. The
same operand-stack transfer used by `invoke_bound_report` clears the local
callable owner before the foreign call; the native branch clears it after
transferring the receiver to the actual frame.

The op9 body, original report helper, original seven `VerifiedProgram` bodies,
original CLI control image and claim/ACK/fence/retirement machinery are
unchanged. The Inspect closure can still recognize the report closure's two
free variables (`held_session`, `report_owner`); no new closure cell is added.
Inspect op10 and Patch op13 are not rewritten or qualified here.

## Compatibility pins and generated identities

All 11 fixed host pins in the base registry were independently recomputed from
the actual files before authoring and matched their declared bytes. The two
old pins are:

| Path | Original SHA-256 |
|---|---|
| `hepta/hia_verified_report_native.py` | `76ccaee0b457cb9d0abe6606a0f8aa60e6813a1aaf66bc065ae0a853fb5690f2` |
| `hepta/hia_cli_verified_report_native.py` | `a98703b045c25a7cd293789aa950f569a059f19d87608d65ec3d9e5a2bb0b55b` |

Only these two host hashes in `VERIFIED_REPORT_HOST_PINS` change, to the actual
new complete-file bytes. No registry resource set, source pin, profile name or
fixed worker role changes. The registry file itself remains part of current
source admission and is not self-hashed inside that table.

`verified_report.hepta` already contains as_dict mode 6. Its bytes remain
118,278 / SHA-256
`2d3e5a21227ccdc6f40cbbfd9b72c8d1eacbdca0b24c40fc64937506a55af048`.
`hia_verified_report_ports.py`, the policy, generator, function table and mode
order also remain exact. No new HIA source/table/image identity is invented or
statically rewritten. The existing generator `--check` is a retained test,
not a test executed during authoring.

An old six-image manifest still names old `host_sources` and source closure.
It must not be accepted as matching this candidate. The actual existing
builder must emit a new manifest/build report from a new isolated candidate,
and any production run still needs a matching current-source cold report.
The original six-compilation builder limits remain 20 seconds, 10 CPU seconds,
1 MiB output per compile. Development observations cannot replace that cold
authority. No future compiler/image/manifest/result hash has been filled in.

## Required existing and new controls

`TEST-INVENTORY.json` contains the complete original ordered 43 CLI method IDs,
both report Native method IDs, all 12 report Source method IDs, and all 140
retained observation names. Those files and method bodies are not patched.
The two original Native report methods must still run all 140 observations and
the warm-versus-strict image check. The original 43 must be driven through the
new actual six-image bundle, including their real installed-wheel case; a
five-image run is not a substitute.

The new fixed external file is `external_tests/test_as_dict_boundary.py`.
It contains eight methods and requires the existing fixture-selection API.
It records every actual report-image call's complete six buffers, including
the exception path, and records all loaded/start/stop IDs. Missing fixtures,
skips and incomplete counts cannot produce a pass. It covers:

1. Actual mode 6, original policy frame absence, and exact decoder argument
   identity/keyword order.
2. A public forged `VerifiedProgram` carrying malformed UTF-8/JSON, plus an
   array payload: the original decoder behavior is observed without inventing
   verifier authority.
3. A captured foreign callable invoked once, without probing its metadata.
4. Descriptor replacement and function-code replacement after capture. The
   original operand is consumed; a second lookup is forbidden.
5. Subclass instance shadows and custom attribute hooks remaining foreign.
6. The real CLI op8 branch, with unchanged separate `--output` publication.
7. Decoder exception context and the native result's retirement after output.
8. Completed op8 session retirement without GC or an added owner cycle.

Existing claim loss, ACK loss, reentry and foreign finalizer controls are kept
in the full original 43; no weaker copies replace them. The new file only adds
the new binding-specific observations. Its source is authored and AST-parsed,
not executed. The real launcher must retain original group 180+3 ownership,
source/input guards, actual 3.14.4 context and complete partial evidence.

Example child arguments after a separate reviewed source view and real bundle
exist (placeholders are intentionally not future pins):

```text
<actual-python3.14> -B <author-root>/external_tests/test_as_dict_boundary.py \
  --source-root <new-exact-candidate-view> --evidence <exclusive-new-output>
```

Select either the real original cold fixture or explicit development manifest
using the existing report environment variables. Do not use `-I` for the
original CLI43 child: its Python color-environment checks retain `-B` behavior.
The new file does not build, choose a compiler, recreate cold inputs or retry.

## What this removes, and default activation gaps

This removes the direct Python `VerifiedProgram.as_dict` policy body from a
claimed op8 in the explicitly held report CLI route. It does not remove the
real `decode_internal_canonical` provider, Python foreign-object transport,
`output_json`, `publish_program`, the verifier, Worker, Service, or SQLite.

The ordinary `hia_main` default still enters `_reference_hia_main` when no
`HEPTA_HIA_CLI_MANIFEST` is selected. Default activation additionally needs an
operator-owned installed artifact selection contract, complete current-source
cold qualification and original installed/absence/error behavior decisions.
The package still supports default Python environments outside the selected
report ports' reviewed CPython 3.12/3.13/3.14 ABI. This candidate does not silently
map an image on that path or convert absence into a new error.

The currently restored original interpreter has stdlib only. The focused op8
policy/provider checks are not a claim that the complete build/wheel and
original full-CLI prerequisites (including packaging dependencies and any
backend tools demanded by the original tests) are now restored. Z3/pytest are
not inferred from a version string or historical result.
