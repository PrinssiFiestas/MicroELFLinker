int shared_foo(void)
{
    asm ( // just something that is easy to see from disassembly/machine code
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop");
    return 7;
}
