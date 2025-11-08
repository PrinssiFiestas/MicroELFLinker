// MIT License
// Copyright (c) 2025 Lauri Lorenzo Fiestas
// https://github.com/PrinssiFiestas/MicroELFLinker/blob/main/LICENSE

#ifndef UTILS_H_INCLUDED
#define UTILS_H_INCLUDED 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define DynArr(TYPE) struct   \
{                             \
    size_t length;            \
    size_t capacity;          \
    typeof((TYPE){0}) data[]; \
}*

#define dynarr_push(DARR_PTR, ELEM) \
( \
    dynarr_add_reserve( \
        sizeof (*(DARR_PTR))->data[0], (DARR_PTR), 1), \
    (*(DARR_PTR))->data[(*(DARR_PTR))->length++] = (ELEM) \
)

#define dynarr_append(DARR_PTR, ELEMS, ELEMS_LENGTH) \
( \
    dynarr_add_reserve( \
        sizeof (*(DARR_PTR))->data[0], (DARR_PTR), (ELEMS_LENGTH)), \
    memcpy( \
        (*(DARR_PTR))->data + (*(DARR_PTR))->length, \
        (ELEMS), \
        sizeof((*(DARR_PTR))->data[0]) * (ELEMS_LENGTH)) \
)

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

static inline void dynarr_add_reserve(size_t elem_size, void* darr_ptr, size_t nelems)
{
    DynArr(char)* darr = darr_ptr;
    if (*darr == NULL) {
        const size_t init_cap = 16;
        *darr = xmalloc(sizeof(**darr) + elem_size * init_cap);
        (*darr)->length = 0;
        (*darr)->capacity = init_cap;
    }

    if ((*darr)->length + nelems <= (*darr)->capacity)
        return;
    do {
        (*darr)->capacity <<= 1;
    } while ((*darr)->capacity < nelems);
    *darr = xrealloc(*darr, elem_size * (*darr)->capacity);
}

#endif // UTILS_H_INCLUDED
