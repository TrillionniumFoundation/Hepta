# Fixed combined source static checks R2

This isolated read-only harness composes 22 immutable source packets into 251
reviewed files, including 234 Python sources. Its only three overrides are
explicitly pinned old-selfhost to latest-main source updates. Every packet and
every resulting source is checked against its original Git blob identity.

Python 3.11 and 3.14.4 independently parse and compile the combined Python source
without executing product code. Pure AST comparisons retain the seven original
regression modules, byte policy reference bodies, source identity provider
protocols, original contract fields, source-build bounds and strict cold observer
functions. The older selfhost R1 validator is rerun separately on its unchanged
packet and exact original preimages; its result does not qualify the four newer
selfhost sources. Those final sources receive their own syntax and explicitly
listed structural checks.

This is SOURCE STATIC ONLY: zero product tests, zero HIA generation, zero native
execution, and zero cold or whole-native qualification. New backend R4 and the
pending checker are excluded from this frozen revision. No product branch,
default, budget or deletion decision changes. All failures and source bytes are
retained as run artifacts, including the exact validator source.
