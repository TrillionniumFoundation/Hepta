struct sample_layout { char first; long field; };
void asm_offsets(void)
{
    __asm__ volatile("\n.ascii \"->SAMPLE_B %c0 field\""
                     : : "i"(__builtin_offsetof(struct sample_layout, field)));
}
