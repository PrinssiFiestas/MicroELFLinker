#if 1 /* const char pointers */

const char* foo_pad = "pad";
const char* foo_msg = "I am foo!\n";

extern const char foobar_walrus[];
extern long bar_puts(const char* msg);

long foo_walrus(void)
{
    return 0
        + bar_puts(foo_msg)
        + bar_puts("I am the ")
        + bar_puts(foobar_walrus);
        ;
}

#else /* const char arrays */

const char foo_pad[] = "pad";
const char foo_msg[] = "I am foo!\n";

extern const char foobar_walrus[];
extern long bar_puts(const char* msg);

const char foo_i_am_the[] = "I am the ";

long foo_walrus(void)
{
    return 0
        + bar_puts(foo_msg)
        + bar_puts(foo_i_am_the)
        + bar_puts(foobar_walrus)
        ;
}

#endif
