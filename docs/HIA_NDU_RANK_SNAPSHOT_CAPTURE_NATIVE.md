# Native caller snapshot with typed JSON capture

This source-qualified leaf preserves the original caller-owned dict/list snapshot
order for the fresh native typed JSON capture profile. Number nodes whose raw
lexemes contain N or I are floats, as are decimal-point/exponent tokens. NaN,
Infinity and -Infinity are therefore rejected at the same left-to-right snapshot
position as other floats. The strict Core/proof JSON decoder is unchanged.

Actual qualification: 523 cases, comprising 339 report constructors, 4 escaped
and dynamic report cases, 20 private guards, 139 snapshot cases, 10 original
node/depth limits, 9 queued/left-to-right priority cases, and 2 selected subtrees.
The original 262144-node and 64-depth limits are unchanged. Validation used the
actual native capture flat, native snapshot flat, and original caller snapshot.
This is a leaf qualification; full rank/runtime/background activation is separate.

Six-Q ABI: input HIANVS01, 128-byte header, root at 8, raw byte count at 16,
arena byte count at 24, remaining header words zero; raw JSON then fresh owned
arena. Work is 131072 plus global node count. Output is HIANVR01/128 plus
exception JSON: status at 8, error id 16, root kind 24, visited 32, queued 40,
error JSON count 48, root index 56, decoded string offset/count at 64/72.
A root outside dict/list does not acquire an additional snapshot restriction.
Business refusal is return 0 with status 1; invalid ABI is 0xfffffffd.

Native snapshot flat: 95497 bytes,
c6ab6ba1f7c89117ac687665b2c0489f27ca54740dc900bcd2501f41b99fbf64.
Complete source/role pins and actual cases accompany this document.
