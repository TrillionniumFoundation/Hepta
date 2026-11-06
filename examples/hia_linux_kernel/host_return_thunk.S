/* SPDX-License-Identifier: GPL-2.0 */
/* Hosted differential-test glue only. The actual kernel links its own thunk. */
.text
.globl __x86_return_thunk
.type __x86_return_thunk,@function
__x86_return_thunk:
    ret
.size __x86_return_thunk,.-__x86_return_thunk
.section .note.GNU-stack,"",@progbits
