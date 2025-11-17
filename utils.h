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
    dynarr_add_reserve(                                   \
        sizeof (*(DARR_PTR))->data[0], DARR_PTR, 1),      \
    (*(DARR_PTR))->data[(*(DARR_PTR))->length++] = (ELEM) \
)

#define dynarr_append(DARR_PTR, ELEMS, ELEMS_LENGTH) \
( \
    dynarr_add_reserve(                                           \
        sizeof (*(DARR_PTR))->data[0], DARR_PTR, (ELEMS_LENGTH)), \
    memcpy(                                                       \
        (*(DARR_PTR))->data + (*(DARR_PTR))->length,              \
        (ELEMS),                                                  \
        sizeof((*(DARR_PTR))->data[0]) * (size_t){ELEMS_LENGTH}), \
    (*(DARR_PTR))->length += (ELEMS_LENGTH)                       \
)

// Make array length a multiple of alignment by adding zeroes if necessary.
#define dynarr_align(DARR_PTR, ALIGNMENT) \
({ \
    _Static_assert(sizeof(typeof((*(DARR_PTR))->data[0])) == 1,      \
        "dynarr_align(): Expected byte array.");                     \
    typeof(DARR_PTR) _darr_ptr = (DARR_PTR);                         \
    size_t _alignment = (ALIGNMENT);                                 \
    _alignment += !_alignment;                                       \
    if (*_darr_ptr == NULL)                                          \
        dynarr_add_reserve(1, _darr_ptr, 1);                         \
    size_t diff = round_to_aligned((*_darr_ptr)->length, _alignment) \
        - (*_darr_ptr)->length;                                      \
    dynarr_add_reserve(1, _darr_ptr, diff);                          \
    memset((*_darr_ptr)->data + (*_darr_ptr)->length, 0, diff);      \
    (*_darr_ptr)->length += diff;                                    \
    (void)0;                                                         \
})

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

#define xcalloc(NMEMB, SIZE)                  \
({                                            \
    void* p;                                  \
    Assert((p = calloc(NMEMB, SIZE)) != NULL, \
        "%s\n", strerror(errno));             \
    p;                                        \
})

#define xrealloc(PTR, SIZE)                  \
({                                           \
    void* p;                                 \
    Assert((p = realloc(PTR, SIZE)) != NULL, \
        "%s\n", strerror(errno));            \
    p;                                       \
})

#define round_to_aligned(X, ALIGN)                              \
({                                                              \
    size_t _x     = (X);                                        \
    size_t _align = (ALIGN);                                    \
    Assert((_align & (_align - 1)) == 0,                        \
        "round_to_aligned(): Alignment must be a power of 2.\n" \
        "Passed alignment: %zu\n", _align);                     \
    --_align;                                                   \
     _x + _align - ((_x - 1) & _align);                         \
})

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
    } while ((*darr)->capacity < (*darr)->length + nelems);

    *darr = xrealloc(*darr, sizeof(**darr) + elem_size * (*darr)->capacity);
}

#endif // UTILS_H_INCLUDED
