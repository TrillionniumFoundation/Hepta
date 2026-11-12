# Frozen proof foreign mechanisms

This isolated observation executes the unmodified 7532-byte proof foreign
module frozen by the parent component R3 (SHA256 e07eac32ef9915346ad132c3c753ba56cc730d6a5ce073a4e063a5d42b6665a7).
It does not execute HIA, proof policy, a solver, or a prior qualification suite.
Seventeen independent physical controls cover six fixed CALL shapes, original
IMPORT_NAME and IMPORT_FROM fields, DICT_UPDATE, formatting and BUILD_STRING,
plus malformed-template refusal controls. A top-level guard refusal is a real
failure before those controls, never a skip or a passed observation.

The actual candidate import and a separate definition-only diagnostic preserve
co_consts, complete code bytes, exception tables and disassembly. The diagnostic
does not substitute a permissive module or run denied code. On a refusal it only
supplies the physical interpreter facts needed to design a later revision.

The workflow pins CPython 3.14.4 and the full exact 4b product checkout, validates
Ubuntu 24.04 x86_64 and all 3153 source bytes/modes/Git blobs, and retains all raw
results. The frozen source is unmodified. The actual local 3.12.14 preparation
result is separate and grants no 3.14 result. All whole-stack/current-cold/default
activation and deletion claims remain false.
