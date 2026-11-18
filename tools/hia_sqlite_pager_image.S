/* The included body is the intact B3 output for sqlite_pager_retained.hepta.
 * The build verifies its source and image identity; the wrapper does not
 * strip, patch or reinterpret the image.
 */
.intel_syntax noprefix
.section .text.pager_hia,"ax",@progbits
.balign 16
.global pager_hia_entry
.type pager_hia_entry,@function
pager_hia_entry:
.incbin "pager_read_owner.image.bin"
.size pager_hia_entry,.-pager_hia_entry
.section .note.GNU-stack,"",@progbits
