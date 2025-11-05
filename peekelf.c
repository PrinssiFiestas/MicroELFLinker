// MIT License
// Copyright (c) 2025 Lauri Lorenzo Fiestas
// https://github.com/PrinssiFiestas/MicroELFLinker/blob/main/LICENSE

#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

// ----------------------------------------------------------------------------
// Utilities

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

size_t round_to_aligned(size_t x, size_t align)
{
    Assert((align & (align - 1)) == 0, "Alignment must be a power of 2.\n");
    --align;
    return x + align - ((x - 1) & align);
}

// ----------------------------------------------------------------------------
// Functions for Exercises

extern int shared_foo(void);

int static_foo(void) // static as in statically linked, not C `static`
{
    bool b = true; // prevent removing inline assembly below
    if (b)
        return 19;
    asm ( // just something that is easy to see from disassembly/machine code
        "ret\n\t"
        "ret\n\t"
        "ret\n\t"
        "ret");
    return 19;
}

int call_shared_foo(void)
{
    int result = shared_foo();
    result *= 5;
    return result;
}

int call_static_foo(void)
{
    int result = static_foo();
    result *= 3;
    return result;
}

// ----------------------------------------------------------------------------
// Main (as you might be able to tell)

int main(int argc, char* argv[])
{
    // Dummy calls to prevent garbage collector removing these from executable.
    // Of course, the calls made in exercises would be enough, only 1 reference
    // needed, but having these here too is nice so we can comment things out or
    // whatever without removing these from binary.
    (void)static_foo();
    (void)shared_foo();
    (void)call_static_foo();
    (void)call_shared_foo();

    Assert(argc <= 2, "Pass a single ELF file or none for self.\n");
    const char* elf_path = argv[0];
    if (argc > 1)
        elf_path = argv[1];

    struct stat self_stat;
    Assert(stat(elf_path, &self_stat) != -1, "%s\n", strerror(errno));

    void* elf     = xmalloc(self_stat.st_size);
    FILE* self_fp = fopen(elf_path, "rb");
    Assert(self_fp != NULL, "%s\n", strerror(errno));
    Assert(fread(elf, 1, self_stat.st_size, self_fp) == (size_t)self_stat.st_size, "%s\n", strerror(errno));
    fclose(self_fp);
    Assert(memcmp(elf, "\x7F""ELF", 4) == 0, "%s is not an ELF binary.\n", elf_path);

    const Elf64_Ehdr  ehdr      = *(Elf64_Ehdr*)elf;
    const Elf64_Shdr* shdrs     = elf + ehdr.e_shoff;
    const Elf64_Phdr* phdrs     = elf + ehdr.e_phoff;
    const char*       shstrtab  = elf + shdrs[ehdr.e_shstrndx].sh_offset;
    size_t executable_segment_size = 0;

    Assert(ehdr.e_type == ET_EXEC || ehdr.e_type == ET_DYN || ehdr.e_type == ET_REL,
        "This executable has some basic code to test ELF files with machine code.\n"
        "Only pass executables, object files, or shared libraries.\n");

    // ------------------------------------------------------------------------
    puts("---------------------------------------");
    printf("Reading %s\n\n", elf_path);

    if (ehdr.e_type == ET_EXEC || ehdr.e_type == ET_DYN)
        puts("Segments:");
    for (size_t i = 0; i < ehdr.e_phnum; ++i)
    {
        static const char* pt_flag_strs[] = {
            [0] = "No premissions",
            [              PF_X] = "E"   ,
            [       PF_W       ] = "W"   ,
            [       PF_W | PF_X] = "E W" ,
            [PF_R              ] = "R"   ,
            [PF_R |        PF_X] = "R E" ,
            [PF_R | PF_W       ] = "R W" ,
            [PF_R | PF_W | PF_X] = "R W E"
        };
        const char* flags_str = pt_flag_strs[phdrs[i].p_flags & (PF_X|PF_W|PF_R)]; // filter out OS-specific
        if (phdrs[i].p_flags & PF_X)
            executable_segment_size += phdrs[i].p_memsz;

        printf("Segment[%2zu]: ", i);
        switch (phdrs[i].p_type) {
        case PT_NULL    : printf("PT_NULL:    %s\n", flags_str); break;
        case PT_LOAD    : printf("PT_LOAD:    %s\n", flags_str); break;
        case PT_DYNAMIC : printf("PT_DYNAMIC: %s\n", flags_str); break;
        case PT_INTERP  : printf("PT_INTERP:  %s\n", flags_str); break;
        case PT_NOTE    : printf("PT_NOTE:    %s\n", flags_str); break;
        case PT_SHLIB   : printf("PT_SHLIB:   %s\n", flags_str); break;
        case PT_PHDR    : printf("PT_PHDR:    %s\n", flags_str); break;
        case PT_TLS     : printf("PT_TLS:     %s\n", flags_str); break;
        case PT_NUM     : printf("PT_NUM:     %s\n", flags_str); break;
        default:
            if (PT_LOPROC <= phdrs[i].p_type && phdrs[i].p_type <= PT_HIPROC)
                printf("Processor specific (%u): %s\n", phdrs[i].p_type, flags_str);
            else
                printf("Other:      %s\n", flags_str);
        }
    }
    puts("");

    puts("Sections:");
    for (size_t i = 0; i < ehdr.e_shnum; ++i)
        printf("Section[%zu]: %s\n", i, shstrtab + shdrs[i].sh_name);
    puts("");

    size_t           symtab_length   = 0    ;
    const Elf64_Sym* symtab          = NULL ;
    size_t           dynsyms_length  = 0    ;
    const Elf64_Sym* dynsyms         = NULL ;
    const char*      dynstr          = NULL ;
    const char*      strtab          = NULL ;
    size_t           relocs_capacity = 64   ; // arbitrary
    size_t           relocs_length   = 0    ;
    void*            text_data       = NULL ; // .text
    Elf64_Rela*      relocs          = xmalloc(relocs_capacity * sizeof relocs[0]);

    for (size_t i = 0; i < ehdr.e_shnum; ++i) switch (shdrs[i].sh_type)
    {
    case SHT_PROGBITS:
        if ( ! text_data && strcmp(".text", shstrtab + shdrs[i].sh_name) == 0)
            text_data = elf + shdrs[i].sh_offset;
        executable_segment_size += shdrs[i].sh_size;
        break;

    case SHT_SYMTAB:
        symtab = elf + shdrs[i].sh_offset;
        symtab_length = shdrs[i].sh_size / shdrs[i].sh_entsize;
        break;

    case SHT_STRTAB:
        if (strcmp(shstrtab + shdrs[i].sh_name, ".dynstr") == 0)
            dynstr = elf + shdrs[i].sh_offset;
        else if (strcmp(shstrtab + shdrs[i].sh_name, ".strtab") == 0)
            strtab = elf + shdrs[i].sh_offset;
        break;

    case SHT_DYNSYM:
        dynsyms = elf + shdrs[i].sh_offset;
        dynsyms_length = shdrs[i].sh_size / shdrs[i].sh_entsize;
        break;

    case SHT_REL:; // convert to Rela for convenience
        Elf64_Rel* rels = (Elf64_Rel*)(elf + shdrs[i].sh_offset);
        for (size_t j = 0; j < shdrs[i].sh_size; ++j) {
            Elf64_Rela rela = { .r_offset = rels[j].r_offset, .r_info = rels[j].r_info, .r_addend = 0 };
            if (relocs_length + 1 > relocs_capacity)
                relocs = xrealloc(relocs, (relocs_capacity <<= 1) * sizeof relocs[0]);
            relocs[relocs_length++] = rela;
        }
        break;

    case SHT_RELA:
        if (relocs_length + shdrs[i].sh_size > relocs_capacity) {
            do {
                relocs_capacity <<= 1;
            } while (relocs_capacity < relocs_length + shdrs[i].sh_size);
            relocs = xrealloc(relocs, relocs_capacity * sizeof relocs[0]);
        }
        memcpy(
            relocs + relocs_length,
            elf + shdrs[i].sh_offset,
            shdrs[i].sh_size);
        relocs_length += shdrs[i].sh_size;
        break;
    }

    if (ehdr.e_type == ET_EXEC || ehdr.e_type == ET_DYN) {
        Assert(dynsyms_length != 0);
        Assert(dynstr != NULL);
        Assert(dynsyms != NULL);
    }
    Assert(symtab_length != 0);
    Assert(symtab != NULL);

    size_t i_shared_foo = 0;
    size_t i_static_foo = 0;
    size_t i_call_static_foo = 0;
    size_t i_call_shared_foo = 0;

    puts("All symbols:");
    for (size_t i = 0; i < symtab_length; ++i) {
        if ( ! i_static_foo && strcmp(strtab + symtab[i].st_name, "static_foo") == 0)
            i_static_foo = i;
        if ( ! i_shared_foo && strcmp(strtab + symtab[i].st_name, "shared_foo") == 0)
            i_shared_foo = i;
        else if ( ! i_call_static_foo && strcmp(strtab + symtab[i].st_name, "call_static_foo") == 0)
            i_call_static_foo = i;
        else if ( ! i_call_shared_foo && strcmp(strtab + symtab[i].st_name, "call_shared_foo") == 0)
            i_call_shared_foo = i;
        printf("Symbol[%zu]: %s\n", i, strtab + symtab[i].st_name);
    }
    puts("");

    if (ehdr.e_type == ET_EXEC || ehdr.e_type == ET_DYN)
        puts("Dynamic linking symbols:");
    for (size_t i = 0; i < dynsyms_length; ++i) {
        printf("DL Symbol[%zu]: %s\n", i, dynstr + dynsyms[i].st_name);
    }
    puts("");

    // ------------------------------------------------------------------------
    // BEGIN EXERCISES CODE

    // Exercises assume input to be this executable or this object file.
    if (argc == 1)
        exit(EXIT_SUCCESS);
    else { // Check if program name matches object file. Why didn't I just hard
           // code this...
        const char* progname = argv[0];
        for (const char* p = progname; (p = strchr(progname, '/')) != NULL; )
            progname = p += strlen("/");
        size_t l = strlen(argv[1]);
        if (strstr(argv[1], progname) == NULL
            || l <= 2 || argv[1][l - 2] != '.' || argv[1][l - 1] != 'o')
            exit(EXIT_SUCCESS);
    }

    Assert(i_static_foo != 0);
    Assert(i_shared_foo != 0);
    Assert(i_call_static_foo != 0);
    Assert(i_call_shared_foo != 0);

    void*const executable_mem = mmap(
        NULL,
        executable_segment_size,
        PROT_READ | PROT_WRITE | PROT_EXEC, // note PROT_EXEC!
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1, 0);
    Assert((intptr_t)executable_mem > 0, "%s\n", strerror(errno));
    // Executable arena pointer. Move this to allocate memory instead of calling
    // mmap() for all functions.
    void* executable_ptr = executable_mem;

    // ------------------------------------------------------------------------
    // Exercise: Find static_foo() machine code data and copy it to executable
    // memory block. Then call the copied function.

    const Elf64_Sym sym_static_foo = symtab[i_static_foo];
    int(*static_foo_clone)(void) = executable_ptr;
    executable_ptr += round_to_aligned(sym_static_foo.st_size, 8);
    void* code_base = ehdr.e_type == ET_REL ? text_data : elf;
    memcpy(static_foo_clone, code_base + sym_static_foo.st_value, sym_static_foo.st_size);
    int static_foo_return = static_foo_clone();
    Assert(static_foo_return == static_foo());

    // ------------------------------------------------------------------------
    // Exercise: same as before, except with call_static_foo(), which includes a
    // call to static_foo(), which has to be resolved. Note: offsets are 32-bits
    // so you really have to call static_foo_clone().

    if (ehdr.e_type != ET_REL) // relocations already handled by static linker
        goto skip_static_reloc_exercise;

    const Elf64_Sym sym_call_static_foo = symtab[i_call_static_foo];
    int(*call_static_foo_clone)(void) = executable_ptr;
    executable_ptr += round_to_aligned(sym_call_static_foo.st_size, 8);
    memcpy(
        call_static_foo_clone,
        elf + sym_call_static_foo.st_value,
        sym_call_static_foo.st_size);

    Elf64_Rela rel_static_foo = {0};
    for (size_t i = 0; i < relocs_length; ++i) {
        Elf64_Addr call_foo = sym_call_static_foo.st_value;
        Elf64_Addr roff = relocs[i].r_offset;
        if (call_foo <= roff && roff < call_foo + sym_call_static_foo.st_size) {
            rel_static_foo = relocs[i];
            break;
        }
    }
    Assert(rel_static_foo.r_offset != 0);

    int call_static_foo_return = call_static_foo_clone();
    Assert(call_static_foo_return == call_static_foo());

    skip_static_reloc_exercise:

    // ------------------------------------------------------------------------
    // Exercise: same as before, except with call_shared_foo(), which includes a
    // call to shared_foo(), which has to be resolved.

    // TODO

    // END EXERCISES CODE
    // ------------------------------------------------------------------------
    // Pedantic cleanup to shut up analyzers
    free(elf);
    free(relocs);
    munmap(executable_mem, executable_segment_size);
    puts("\e[32mAll gucci.\e[0m");
}
