# Installed native source custody

Every native image adapter with an owned HIA source uses the same explicit
checkout-or-package resource path. All twenty-three current source assets are listed
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
streaming SHA HIA source is already in the twenty-three adapter resources. These
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
