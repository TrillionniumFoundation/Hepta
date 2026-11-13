# Fixed CPython note adapter emitted by HIA

This development component replaces C compilation of the fixed exception note
and delivery mechanism with an HIA packer. It retains the same hosted CPython
3.14.4 ABI dependency; it does not establish whole normalization or whole HIA
runtime qualification.

The production input is `cpython_note_packer.hiaasm`. Its entry accepts an empty
source buffer and emits a complete position independent machine image. Nonempty
input is refused before writing output. A short output buffer is refused before
any write. The generated image starts at offset zero, contains its own three
fixed format strings, preserves SysV callee saved registers, aligns the stack
for every indirect call, and uses no relocations, imports, dynamic loader, or
global writable state.

Runtime inputs are the already admitted four-pointer interpreter table, a real
exception object, a fixed kind, borrowed container/key pointers, and a signed
index. It rejects a null API table or exception, kinds outside 1..4, illegal
indices, and nonnull container/key for delivery before touching interpreter
error state. Kind 1 adds the mapping note, 2 the sequence note, and 3 the object
note. Kind 4 gives the current raised slot one owned reference and returns NULL;
the existing PYFUNCTYPE bridge propagates the actual exception. The mechanism
does not traverse JSON, classify payloads, choose unwind order, repair Python
exception chains, or change recursion limits.

The Python generator is authoring support. The GNU assembly and linker script
are independent test references. They are not production build dependencies.
Before native packer compilation, an ordinary Core VM must compare every emitted
byte with the independently assembled image, including all three strings and
every branch displacement. Exact size, short output, nonempty source, refusal
precedence, and output tail preservation are also checked. A retained compiler
run, if performed, is development evidence only. Existing note, delivery,
handled-exception, lifetime, and ACK controls remain required against the
HIA-produced image; a byte match alone is not an all-input proof.

Whole native delivery, default selection, live migration, and legacy deletion
remain false until the separate completion gates actually pass.
