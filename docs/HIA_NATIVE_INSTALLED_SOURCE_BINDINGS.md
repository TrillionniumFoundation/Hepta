# Installed native source custody

Every native image adapter with an owned HIA source uses the same explicit
checkout-or-package resource path. All current adapter source assets are listed
in `NATIVE_SOURCE_FILES`, copied byte-for-byte into the wheel, included explicitly
in the sdist, and included in the installed worker identity. A missing packaged
source fails custody; there is no cwd, HOME or alternate-checkout fallback.

Actual installed-worker tests exercise the native Core declaration and local
instruction policies with their foreign counterparts disabled. A separate installed
case selects the full primitive Core kernel with the host body checker disabled;
body/resource obligations and missing-source refusals remain mandatory. Tests also verify every installed source binding,
missing-source refusals, and exact wheel/sdist/source bytes.

This closes a source-resource binding defect, not native-only installation:
wheel construction, object/custody bridges, composite normalization, persistence,
native executable installation and other unfinished runtime work remain open.
Existing runtime installation hashes must be deliberately rebound when deployed;
this change does not update or restart any live Runtime, select defaults or
remove the previous implementation.

The optional artifact publisher/store additionally packages four explicit build
inputs (policy/packer HIA, syscall adapter assembly and generator source). The
streaming SHA HIA source is already in the complete adapter resource list. These
four files are custody data, not installed/importable build-tool modules.

Checkout admission still validates the complete actual source tree. Installed
admission validates every actual production Python module, all discovery/native
resources and the exact five publisher inputs against its package-owned source
contract. The selected executable manifest must match that full build contract
and each input digest, and the executable still runs only from a sealed memfd.
Missing or changed assets, extra production modules, contract/manifest drift and
changed executable bytes refuse without host payload fallback or replay.

Actual isolated wheel tests block all `tools` imports, use empty PATH, exercise
native publish/verify/withdraw and put/get/dedup/restart, and retain body/source
refusals. Python custody, object encoding, SQLite and the journal remain hosted;
this is not native-only installation or default activation.

The ordinary `hia_candidate` patch branch now uses the selected patch manifest
to obtain both candidate and complete diagnostic bytes from HIA. An actual
isolated wheel test disables the hosted program loader, payload checker, patch
editor and receipt construction while running that ordinary request. Missing
installed source, invalid manifests and changed image bytes in a fresh process
refuse. Existing pinned RX images retain their documented immutable lifetime.
Context, issued refs, attempts, SQLite intent/response commits and artifact
publication retain their existing owners. Four real process-kill cut points
cover unfinished intents and exact completed-response replay.

The explicitly selected composite type resolver also owns its installed HIA
source. Its real wheel control runs ordinary partial-record normalization with
the hosted type resolver disabled and build-tool imports forbidden. Missing or
changed source, invalid manifests and a changed image in a fresh process refuse;
type declarations, layouts and symbolic partial obligations come from HIA.
Nominal operation lowering and the remaining worker responsibilities stay with
their existing owners. This source addition does not activate a default image.

## Standalone source builder and raw nominal input codec

The raw nominal JSON adapter owns `nominal_json.hepta` through the same
`NATIVE_SOURCE_FILES` binding. Its isolated installed control forbids checkout
build imports and the host payload parser/transport, compares complete wrapper
packet bytes, and requires missing or changed source to refuse. This is the
explicit codec API; the public normalizer and its diagnostic strings remain
with their existing owners.

`SOURCE_BUILD_FILES` separately lists the source-builder policy, compiler and
packer. These three `.hepta` files are build inputs, not Python native-image
adapters. The sdist includes their exact bytes; wheel construction copies them
into `hepta/_data`, and installed identity/custody covers them. The installed
control feeds these actual package bytes to an explicitly bootstrapped native
`hia-source-build`, executes `build`, then executes `pack` on its six-entry
source/image result and compares the complete reconstructed ELF. It also
requires all three missing/changed input controls to refuse. The same real
sdist/wheel fixture is reused for these controls.

`COMPILER_BUILD_FILES` separately lists the standalone Core JSON compiler's
`core_json_cli_packer.hepta` input. It remains an exact packaged and
identity-bound resource, but it is not a fourth source-builder repack role or
a loadable single-image native adapter. Package construction, installed custody
and complete installed fixtures include both groups. The source-builder role
tuple remains exactly policy, compiler and source-builder packer; its native
six-entry repack contract is unchanged.

With a matching-source cold report, both component fixtures call their strict
builders with the report's actual nested compiler in separate output directories.
Without that report they explicitly perform fresh native bootstrap development.
Neither path installs a default executable, removes the Python wheel/bootstrap
boundary, or qualifies the whole native stack. The source builder accepts the
existing assembly compiler profile; JSON Core documents with `.hepta` suffixes
remain outside that compiler's input profile.
