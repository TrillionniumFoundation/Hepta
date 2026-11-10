# Installed native source custody

Every native image adapter with an owned HIA source uses the same explicit
checkout-or-package resource path. All twenty current source assets are listed
in `NATIVE_SOURCE_FILES`, copied byte-for-byte into the wheel, included explicitly
in the sdist, and included in the installed worker identity. A missing packaged
source fails custody; there is no cwd, HOME or alternate-checkout fallback.

Actual installed-worker tests exercise the native Core declaration and local
instruction policies with their foreign counterparts disabled. Body/resource
obligations remain mandatory. Tests also verify every installed source binding,
missing-source refusals, and exact wheel/sdist/source bytes.

This closes a source-resource binding defect, not native-only installation:
wheel construction, object/custody bridges, Core body checking, persistence,
native executable installation and other unfinished runtime work remain open.
Existing runtime installation hashes must be deliberately rebound when deployed;
this change does not update or restart any live Runtime, select defaults or
remove the previous implementation.
