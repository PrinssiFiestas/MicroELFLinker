// MIT License
// Copyright (c) 2025 Lauri Lorenzo Fiestas
// https://github.com/PrinssiFiestas/MicroELFLinker/blob/main/LICENSE

#ifndef UTILS_H_INCLUDED
#define UTILS_H_INCLUDED 1

#include <stdio.h>
#include <stdlib.h>

#define TO_STRING(X) #X
#define TO_STRING_INDIRECT(X) TO_STRING(X)
#define LINE_STR TO_STRING_INDIRECT(__LINE__)

#define Assert(COND,/* fmt_string = "", */...) \
(                                              \
    (COND) ?                                   \
        (void)0                                \
    : (                                        \
        fprintf(stderr,                        \
            "Condition (" #COND ") "           \
            "\e[31mFAILED!\e[0m "              \
            "Line " LINE_STR ".\n"             \
            __VA_ARGS__),                      \
        abort()                                \
    )                                          \
)

#define xmalloc(SIZE)                  \
({                                     \
    void* p;                           \
    Assert((p = malloc(SIZE)) != NULL, \
        "%s\n", strerror(errno));      \
    p;                                 \
})

#define xrealloc(PTR, SIZE)                  \
({                                           \
    void* p;                                 \
    Assert((p = realloc(PTR, SIZE)) != NULL, \
        "%s\n", strerror(errno));            \
    p;                                       \
})

static inline size_t round_to_aligned(size_t x, size_t align)
{
    Assert((align & (align - 1)) == 0, "Alignment must be a power of 2.\n");
    --align;
    return x + align - ((x - 1) & align);
}

#endif // UTILS_H_INCLUDED
