extern int raw_answer(void);
__attribute__((noinline)) unsigned calculation(unsigned value)
{
    unsigned result = 0;
    for (unsigned i = 0; i < 1000; ++i)
        result += i ^ value;
    return result;
}
int main(void)
{
    return calculation(17) != 499628u || raw_answer() != 13;
}
