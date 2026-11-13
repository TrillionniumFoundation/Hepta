# Fixed merge draft syntax and AST custody

This isolated five-file harness checks the exact authored Byte R1, backend R2,
and selfhost/lifecycle R1 packets pinned in inputs/FIXED-INPUTS.json.
It parses and compiles each Python source without executing its code.
The selfhost validator compares full original AST fields and retained test
methods against exact Git blob preimages, and preserves the original cold
supervisor bytes. It does not import product modules, generate HIA, run product
tests, execute native images, or confer cold or whole-native qualification.

Python 3.11 and 3.14.4 run independently. Every failure, every original packet,
every admitted source blob, and every static result is retained in the artifact.
The GitHub token has contents-read permission only; runner requests are GETs.
No product branch, source default, test threshold, or retirement decision changes.

This is an authoring check for partial integration sources. Passing it does not
establish cross-module compatibility or qualification for later modifications.
The Byte custody follow-up and backend public integration are outside these
fixed packet identities and must receive their own checks after integration.
