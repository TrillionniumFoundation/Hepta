# Bind the imported reader before its first admission

Independent review of 1380c14a reproduced a real false acceptance: after importing
the reader, changing both the executing module file and the selected root's
reader to the same later bytes still passed a first prepare and terminal verify.
The complete original independent counterexample is retained here unchanged
(4518 bytes; SHA256 0e1dde73abbf57a5156bb8e8888d3d6e08b60ff6598ff094d71bc3631da15e59).

The reader now snapshots only its own module bytes during import. No selected
root or fixture is read during import. Initial admission, terminal reread and
adjustment binding require those same imported bytes. They never refresh the
expected reader from a later file. The new actual regression changes both
copies after import and before the first prepare, verifies refusal, restores
them and verifies admission, then changes both again and verifies refusal at
terminal.

All 17 complete controls passed on Python 3.14 in 0.425 seconds (0.564 seconds
including process startup). Complete raw output and unchanged before/after
source pins are retained. The 131 caller images, two fixed authorities,
authoring helper and old frozen engine remain unchanged. The original full
seven-method integration failure recorded in the parent remains an explicit
parent-integration gate; this change does not claim native delivery or that
unwired gate has passed.
