// MIT License
// Copyright (c) 2025 Lauri Lorenzo Fiestas
// https://github.com/PrinssiFiestas/MicroELFLinker/blob/main/LICENSE

#include <elf.h>
#include "utils.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdalign.h>

#ifdef __SANITIZE_ADDRESS__
#include <sanitizer/asan_interface.h>
#include <sanitizer/common_interface_defs.h>
#endif

// ----------------------------------------------------------------------------
// Utilities

// Global arena used only for memory that is needed for the full lifetime of
// the program.
void* g_arena_memory;
_Atomic size_t g_arena_index;
size_t g_arena_size;

static void g_arena_init(size_t size)
{
    size = round_to_aligned(size, 0x1000);
    g_arena_memory = xmalloc(size);
    g_arena_size = size;
}

static void g_arena_destroy(void)
{
    free(g_arena_memory);
}

// Allocate memory that is needed for the full lifetime of the program. No need
// to free pointers returned by this function.
static void* g_alloc(size_t size)
{
    size = round_to_aligned(size, alignof(max_align_t));
    #ifdef __SANITIZE_ADDRESS__
    #define POISON_BOUNDARY_SIZE alignof(max_align_t)
    size += POISON_BOUNDARY_SIZE; // for poison boundary
    #endif
    size_t old_index = atomic_fetch_add(&g_arena_index, size);
    Assert(
        old_index + size < g_arena_size,
        "Global arena out of memory. Size: %zu\n",
        g_arena_size);
    #ifdef __SANITIZE_ADDRESS__
    ASAN_POISON_MEMORY_REGION(
        g_arena_memory + old_index + size - POISON_BOUNDARY_SIZE,
        POISON_BOUNDARY_SIZE);
    #endif
    return g_arena_memory + old_index;
}

// If COND fails, prints error message and exits.
// Unlike Assert(), which is used to detect bugs, this is used to handle fatal
// user errors.
#define user_assert(COND,/* fmt_string, */...) \
(                                              \
    (COND) ?                                   \
        (void)0                                \
    : (                                        \
        fprintf(stderr, "%s: ", argv[0]),      \
        fprintf(stderr, ""__VA_ARGS__),        \
        exit(EXIT_FAILURE)                     \
    )                                          \
)

// Automatic heap deallocation on scope exit.
#define CLEANUP __attribute__((cleanup(cleanup_free)))

// Free a pointer by address. Used for CLEANUP macro. Not very useful for
// anything else.
static void cleanup_free(void* ptr_address)
{
    if (ptr_address == NULL)
        return;
    void* ptr = *(void**)ptr_address;
    free(ptr);
}

static uint64_t str_hash(const char* str)
{
    const uint64_t FNV_prime        = 0x00000100000001B3;
    const uint64_t FNV_offset_basis = 0xcbf29ce484222325;
    const uint8_t* ustr = (uint8_t*)str;
    size_t length = strlen(str);
    uint64_t hash = FNV_offset_basis;
    for (size_t i = 0; i < length; ++i)
    {
        hash ^= ustr[i];
        hash *= FNV_prime;
    }
    return hash;
}

// ----------------------------------------------------------------------------

typedef struct segment
{
    Elf64_Phdr            header;
    DynArr(unsigned char) contents;
} Segment;

typedef struct section
{
    const char* name;
    uint64_t    hash; // name hashed
    const char* link; // section of associated string/symbol table
    size_t      segment_index;
    Elf64_Off   segment_offset;
    Elf64_Shdr  header;
    void*       contents;
} Section;

void* read_elf_file(const char* path)
{
    struct stat st;
    Assert(stat(path, &st) != -1, "%s\n", strerror(errno));

    void* elf = g_alloc(st.st_size);
    FILE* fp  = fopen(path, "rb");
    Assert(fp != NULL, "%s\n", strerror(errno));
    Assert(fread(elf, 1, st.st_size, fp) == (size_t)st.st_size, "%s\n", strerror(errno));
    fclose(fp);
    Assert(memcmp(elf, "\x7F""ELF", 4) == 0, "%s is not an ELF binary.\n", path);

    return elf;
}

// Get index of hash table entry by name.
#define index_of(DYNARR_SECTIONS, START, CHAR_PTR_NAME, HASH_OUT) \
({                                                                \
    uint64_t _hash = str_hash(CHAR_PTR_NAME);                     \
    typeof(DYNARR_SECTIONS) _sections = (DYNARR_SECTIONS);        \
    uint64_t* _hash_out = (HASH_OUT);                             \
    size_t _i = (START);                                          \
    for (; _i < _sections->length; ++_i)                          \
        if (_hash == _sections->data[_i].hash)                    \
            break;                                                \
    if (_hash_out != NULL)                                        \
        *_hash_out = _hash;                                       \
    /* return */_i;                                               \
})

// Concatenating sections moves indices for symbols, relocations, and other
// data. Use this to calculate new indices.
size_t section_offset(Elf64_Shdr** in_shdrs, size_t i_file, size_t i_sect)
{
    size_t section_offset = 0;
    for (size_t i = 0; i < i_file; ++i) {
        section_offset += in_shdrs[i][i_sect].sh_size;
        // Note that alignment of the same section might differ for each input.
        // For example GCC has 8 for char arrays, GNU assembler only has 1.
        if (in_shdrs[i + 1][i_sect].sh_addralign != 0)
            section_offset = round_to_aligned(
                section_offset, in_shdrs[i + 1][i_sect].sh_addralign);
    }
    return section_offset;
}

// ----------------------------------------------------------------------------
// main (duh...)

int main(int argc, char* argv[])
{
    // ------------------------------------------------------------------------
    // Check args

    if (argc == 1) {
        fprintf(stderr, "%s: No input files.\nUsage: %s [file(s)]\n", argv[0], argv[0]);
        exit(EXIT_FAILURE);
    }

    const char* out_path = "a.out";
    char** in_paths = argv + 1;

    // Check -o flag
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-o") != 0)
            continue;
        // else got -o flag
        user_assert(argv[i + 1] != NULL, "-o requires an output path argument.\n");
        out_path = argv[i + 1];
        memmove(argv + i, argv + i + 2, (argc - (i + 2)) * sizeof(char*));
        argc -= 2;
        break;
    }
    const size_t in_paths_length = argc - 1;
    const size_t in_elfs_length  = in_paths_length;

    // ------------------------------------------------------------------------
    // Initialize memory

    // Initialize global arena with size calculated from the sum of input file
    // sizes.
    for (size_t i = 0; i < in_paths_length; ++i) {
        struct stat st;
        user_assert(stat(in_paths[i], &st) != -1, "Failed to open %s: %s\n", in_paths[i], strerror(errno));
        g_arena_size += round_to_aligned(st.st_size, 0x1000);
    }
    g_arena_size *= // preallocate memory by listing needs here.
        + 1 // input files
        + 1 // input sections data
        + 1 // output sections data
        + 1 // output file
        + 1 // just in case
        ;
    g_arena_init(g_arena_size);
    atexit(g_arena_destroy);

    // in_ehdrs and in_elfs will be the same pointers, but have different types
    // for convenience.
    const Elf64_Ehdr** in_ehdrs = g_alloc(in_elfs_length * sizeof in_ehdrs[0]);
    const void**       in_elfs  = g_alloc(in_elfs_length * sizeof in_elfs [0]);

    // Input sections sorted by input files and output sections indices. First
    // index is the input file index, second one is determined by out_sections
    // and will match it's indices. This means that some input sections will be
    // empty, but consistent indices is going to be much more useful.
    Elf64_Shdr**  in_shdrs            = g_alloc(in_elfs_length * sizeof in_shdrs[0]);
    const void*** in_section_contents = g_alloc(in_elfs_length * sizeof in_section_contents[0]);
    const char**  in_shstrtabs        = g_alloc(in_elfs_length * sizeof in_shstrtabs[0]);
    const char**  in_symstrtabs       = g_alloc(in_elfs_length * sizeof in_symstrtabs[0]);

    CLEANUP DynArr(Section) out_sections = NULL;
    dynarr_push(&out_sections, ((Section){.name = "", .hash = str_hash(""), .link = ""}));

    // Most section contents will be appended, but these will be built from
    // scratch.
    CLEANUP DynArr(char)      out_shstrtab  = NULL;
    CLEANUP DynArr(char)      out_symstrtab = NULL;
    CLEANUP DynArr(Elf64_Sym) out_symtab    = NULL;
    dynarr_push(&out_shstrtab,  '\0');
    dynarr_push(&out_symstrtab, '\0');
    dynarr_push(&out_symtab, (Elf64_Sym){0});

    size_t    rel_indices_length = 0;
    unsigned* rel_indices        = NULL;

    // ------------------------------------------------------------------------
    // Section sorting

    // Read input files and create initial output sections.
    for (size_t i_file = 0; i_file < in_elfs_length; ++i_file)
    {
        in_ehdrs[i_file] = in_elfs[i_file] = read_elf_file(in_paths[i_file]);
        const Elf64_Ehdr  ehdr     = *(in_ehdrs[i_file]);
        const Elf64_Shdr* shdrs    = in_elfs[i_file] + ehdr.e_shoff;
        const char*       shstrtab = in_elfs[i_file] + shdrs[ehdr.e_shstrndx].sh_offset;
        in_shstrtabs[i_file] = shstrtab;

        for (size_t i_in_sect = 0; i_in_sect < ehdr.e_shnum; ++i_in_sect) {
            const Elf64_Shdr shdr = shdrs[i_in_sect];
            uint64_t hash;
            size_t i_out_sect = index_of(out_sections, 0, shstrtab + shdr.sh_name, &hash);
            if (i_out_sect == out_sections->length) {
                dynarr_push(&out_sections, ((Section) {
                    .name   = shstrtab + shdr.sh_name,
                    .hash   = hash,
                    .link   = shstrtab + shdrs[shdr.sh_link].sh_name,
                    .header = shdr}));
                out_sections->data[i_out_sect].header.sh_size = 0; // to be filled later
                out_sections->data[i_out_sect].header.sh_link = 0; // to be filled later

                if (shdr.sh_type == SHT_RELA)
                    ++rel_indices_length;
            }
            else {
                user_assert(out_sections->data[i_out_sect].header.sh_type == shdr.sh_type,
                    "Expected matching types for %s section.\n", out_sections->data[i_out_sect].name);
                user_assert(out_sections->data[i_out_sect].header.sh_flags == shdr.sh_flags,
                    "Expected matching flags for %s section.\n", out_sections->data[i_out_sect].name);
                user_assert(out_sections->data[i_out_sect].header.sh_entsize == shdr.sh_entsize,
                    "Expected matching entry sizes for %s section.\n", out_sections->data[i_out_sect].name);

                if (shdr.sh_addralign > out_sections->data[i_out_sect].header.sh_addralign)
                    out_sections->data[i_out_sect].header.sh_addralign = shdr.sh_addralign;
            }
        }
    }

    // Use this to find output section index given any input file's section
    // index.
    unsigned(*in_to_out_section_index)[out_sections->length]
        = g_alloc(in_elfs_length * sizeof in_to_out_section_index[0]);

    // Sort input sections to match output section indices.
    for (size_t i_file = 0; i_file < in_elfs_length; ++i_file)
    {
        const Elf64_Ehdr  ehdr     = *(in_ehdrs[i_file]);
        const Elf64_Shdr* shdrs    = in_elfs[i_file] + ehdr.e_shoff;
        const char*       shstrtab = in_shstrtabs[i_file];;

        in_shdrs[i_file]             = g_alloc(out_sections->length * sizeof in_shdrs[i_file][0]);
        in_section_contents[i_file]  = g_alloc(out_sections->length * sizeof in_section_contents[i_file][0]);
        memset(in_shdrs[i_file],            0, out_sections->length * sizeof in_shdrs[i_file][0]);
        memset(in_section_contents[i_file], 0, out_sections->length * sizeof in_section_contents[i_file][0]);

        for (size_t i_in_sect = 0; i_in_sect < ehdr.e_shnum; ++i_in_sect) {
            size_t i_out_sect = index_of(
                out_sections, 0, shstrtab + shdrs[i_in_sect].sh_name, NULL);
            Assert(i_out_sect < out_sections->length,
                "Sanity check: output sections were created based on input sections.\n");
            in_shdrs[i_file][i_out_sect]                = shdrs[i_in_sect];
            in_section_contents[i_file][i_out_sect]     = in_elfs[i_file] + shdrs[i_in_sect].sh_offset;
            in_to_out_section_index[i_file][i_in_sect] = i_out_sect;

            if (shdrs[i_in_sect].sh_type == SHT_STRTAB
                && strcmp(shstrtab + shdrs[i_in_sect].sh_name, ".strtab") == 0)
                in_symstrtabs[i_file] = in_elfs[i_file] + shdrs[i_in_sect].sh_offset;
        }
    }

    // Update sh_link and sh_info.
    for (size_t i = 0; i < out_sections->length; ++i)
    {
        Section* sect = &out_sections->data[i];
        sect->header.sh_link = index_of(out_sections, 0, sect->link, NULL);

        if (sect->header.sh_type == SHT_RELA)
            sect->header.sh_info = index_of(out_sections, 0, sect->name + strlen(".rela"), NULL);
    }

    // ------------------------------------------------------------------------
    // Section header string table merging.

    size_t shstrtab_index  = index_of(out_sections, 0, ".shstrtab", NULL);
    size_t symstrtab_index = index_of(out_sections, 0, ".strtab",   NULL);
    size_t symtab_index    = index_of(out_sections, 0, ".symtab",   NULL);
    user_assert(shstrtab_index  != out_sections->length, "No section header string table found.");
    user_assert(symstrtab_index != out_sections->length, "No symbol string table found.");
    user_assert(symtab_index    != out_sections->length, "No symbol table found.");

    // Merge section header string tables, fill relocation table indices, and
    // simplify alignments.
    rel_indices = g_alloc(rel_indices_length * sizeof rel_indices[0]);
    rel_indices_length = 0;
    for (size_t i = 0; i < out_sections->length; ++i)
    {
        Section* sect = &out_sections->data[i];
        sect->header.sh_name = out_shstrtab->length;
        dynarr_append(&out_shstrtab, sect->name, strlen(sect->name) + sizeof"");

        if (sect->header.sh_type == SHT_RELA)
            rel_indices[rel_indices_length++] = i;

        // Alignment of 0 is the same as 1, make it explicit and prevent
        // zero divisions.
        if (sect->header.sh_addralign == 0)
            sect->header.sh_addralign  = 1;
    }
    out_sections->data[shstrtab_index].header.sh_size = out_shstrtab->length;
    out_sections->data[shstrtab_index].contents       = out_shstrtab->data;

    // ------------------------------------------------------------------------
    // Merge symbol table and symbol string table. We assume that the assembler
    // put locals first, then globals. This is enforced somewhere below. Weak
    // symbols not handled for now.

    for (size_t i_file = 0; i_file < in_elfs_length; ++i_file) // locals first
    {
        const Elf64_Sym* syms = in_section_contents[i_file][symtab_index];
        size_t locals_length = in_shdrs[i_file][symtab_index].sh_info;

        // Different translation units may have local (C static) symbols with
        // the same name. We have to be able to identify them during relocation.
        // A file symbol before other locals allows us to do this.
        dynarr_push(&out_symtab, ((Elf64_Sym) {
            .st_name  = out_symstrtab->length,
            .st_info  = ELF64_ST_INFO(STB_LOCAL, STT_FILE),
            .st_other = STV_DEFAULT,
            .st_shndx = SHN_ABS,
        }));
        dynarr_append(&out_symstrtab, in_paths[i_file], strlen(in_paths[i_file]) + sizeof"");

        // Update and push all local symbols.
        for (size_t j = 1/*skip empty*/; j < locals_length; ++j)
        {
            Elf64_Sym sym = syms[j];
            const char* sym_name = in_section_contents[i_file][symstrtab_index] + sym.st_name;
            if (sym_name[0] == '\0' && ELF64_ST_TYPE(sym.st_info) == STT_SECTION)
            {   // GNU assembler does not assign a name for section symbols
                // presumably to save memory. This will be inconvenient for us
                // during relocations, let's fix that.
                size_t k = in_to_out_section_index[i_file][sym.st_shndx];
                sym_name = out_sections->data[k].name;
            }
            sym.st_name = out_symstrtab->length;
            dynarr_append(&out_symstrtab, sym_name, strlen(sym_name) + sizeof"");

            // Update section index and symbol value
            if (sym.st_shndx < SHN_LORESERVE) {
                size_t i_sym_sect = in_to_out_section_index[i_file][sym.st_shndx];
                sym.st_shndx = i_sym_sect;

                if (ELF64_ST_TYPE(sym.st_info) != STT_SECTION)
                    sym.st_value += section_offset(in_shdrs, i_file, i_sym_sect);
            }

            dynarr_push(&out_symtab, sym);
        }
    }
    out_sections->data[symtab_index].header.sh_info = out_symtab->length;
    for (size_t i_file = 0; i_file < in_elfs_length; ++i_file) // globals last
    {
        const Elf64_Sym* syms = in_section_contents[i_file][symtab_index];
        size_t syms_length = in_shdrs[i_file][symtab_index].sh_size / sizeof syms[0];
        size_t locals_length = in_shdrs[i_file][symtab_index].sh_info;
        for (size_t j = locals_length; j < syms_length; ++j)
        {
            Elf64_Sym sym = syms[j];
            const char* sym_name = in_section_contents[i_file][symstrtab_index] + sym.st_name;
            user_assert(ELF64_ST_BIND(sym.st_info) != STB_LOCAL,
                "Local symbol %s found after sh_info %zu in %s.\n",
                sym_name, locals_length, in_paths[i_file]);
            if (sym.st_shndx == SHN_UNDEF) // symbol undefined
                continue;

            sym.st_name = out_symstrtab->length;
            dynarr_append(&out_symstrtab, sym_name, strlen(sym_name) + sizeof"");

            if (sym.st_shndx < SHN_LORESERVE) {
                size_t i_sym_sect = in_to_out_section_index[i_file][sym.st_shndx];
                sym.st_shndx = i_sym_sect;
                sym.st_value += section_offset(in_shdrs, i_file, i_sym_sect);
            }

            dynarr_push(&out_symtab, sym);
        }
    }
    out_sections->data[symtab_index].header.sh_size    = out_symtab->length * sizeof(Elf64_Sym);
    out_sections->data[symtab_index].contents          = out_symtab->data;
    out_sections->data[symstrtab_index].header.sh_size = out_symstrtab->length;
    out_sections->data[symstrtab_index].contents       = out_symstrtab->data;

    // Create symbol hash map. We use DynArr and a struct that can be used for
    // index_of() macro.
    CLEANUP DynArr(struct { const char* name; uint64_t hash; }) sym_map = NULL;
    dynarr_add_reserve(sizeof sym_map->data[0], &sym_map, out_symtab->length);
    for (size_t i = 0; i < out_symtab->length; ++i) {
        const char* name = out_symstrtab->data + out_symtab->data[i].st_name;
        sym_map->data[i].name = name;
        sym_map->data[i].hash = str_hash(name);
    }
    sym_map->length = out_symtab->length;

    // ------------------------------------------------------------------------
    // Merge relocation tables.

    for (size_t i_rel = 0; i_rel < rel_indices_length; ++i_rel)
    {
        Section* sect = &out_sections->data[rel_indices[i_rel]];
        Assert(sect->contents == NULL,    "Sanity check.");
        Assert(sect->header.sh_size == 0, "Sanity check.");
        for (size_t j = 0; j < in_elfs_length; ++j)
            sect->header.sh_size += in_shdrs[j][rel_indices[i_rel]].sh_size;
        Elf64_Rela* out = sect->contents = g_alloc(sect->header.sh_size);
        size_t out_length = 0;

        for (size_t i_file = 0; i_file < in_elfs_length; ++i_file)
        {
            Elf64_Shdr        rels_shdr   = in_shdrs[i_file][rel_indices[i_rel]];
            const Elf64_Rela* rels        = in_section_contents[i_file][rel_indices[i_rel]];
            size_t            rels_length = rels_shdr.sh_size / sizeof rels[0];
            for (size_t k = 0; k < rels_length; ++k)
            {
                Elf64_Rela rel = rels[k];

                // Update r_offset
                size_t i_target = in_to_out_section_index[i_file][rels_shdr.sh_info];
                rel.r_offset += section_offset(in_shdrs, i_file, i_target);

                // Input symbol
                Elf64_Xword i_sym = ELF64_R_SYM(rel.r_info);
                Elf64_Xword type = ELF64_R_TYPE(rel.r_info);
                const Elf64_Sym* syms = in_section_contents[i_file][symtab_index];
                Elf64_Sym sym = syms[i_sym];
                const char* name = in_section_contents[i_file][symstrtab_index] + sym.st_name;
                if (name[0] == '\0' && ELF64_ST_TYPE(sym.st_info) == STT_SECTION)
                {   // Again, section symbols have no name, let's fix that.
                    size_t k = in_to_out_section_index[i_file][sym.st_shndx];
                    name = out_sections->data[k].name;
                }

                // Output symbol
                size_t map_offset = 1; // cannot be empty, start from 1
                if (ELF64_ST_TYPE(sym.st_info) == STT_SECTION)
                    ; // sections are classified as locals, but we don't care
                else if (ELF64_ST_BIND(sym.st_info) == STB_GLOBAL)
                    map_offset = out_sections->data[symtab_index].header.sh_info;
                else for (size_t h = 0; h < i_file; ++h)
                    map_offset += in_shdrs[h][symtab_index].sh_info
                        + 1 // skip the file symbol that we added
                        ;
                i_sym = index_of(sym_map, map_offset, name, NULL);
                user_assert(i_sym < sym_map->length, "Undefined reference to %s.\n", name);

                // GNU assembler sometimes replaces data symbols with section
                // symbols with addends for whatever reason.
                if (ELF64_ST_TYPE(sym.st_info) == STT_SECTION) {
                    size_t i_sect = in_to_out_section_index[i_file][sym.st_shndx];
                    rel.r_addend += section_offset(in_shdrs, i_file, i_sect);
                }

                rel.r_info = ELF64_R_INFO(i_sym, type);
                out[out_length++] = rel;
            }
        }
    }

    // ------------------------------------------------------------------------
    // Merging rest of the sections.

    // Concatenate all other input sections contents to output sections
    // contents.
    for (size_t i_sect = 0; i_sect < out_sections->length; ++i_sect)
    {
        Section* sect = &out_sections->data[i_sect];

        // Skip manually filled sections.
        if (i_sect == shstrtab_index || i_sect == symstrtab_index || i_sect == symtab_index)
            continue;
        if (sect->header.sh_type == SHT_RELA)
            continue;

        // Allocate memory
        size_t total_size = 0;
        for (size_t i_file = 0; i_file < in_elfs_length; ++i_file) {
            Elf64_Shdr shdr = in_shdrs[i_file][i_sect];
            // Rounding for allocation must be done on max alignment, which is
            // output alignment.
            total_size += round_to_aligned(shdr.sh_size, sect->header.sh_addralign);
        }
        sect->contents = g_alloc(total_size);

        // Concatenate
        for (size_t j = 0; j < in_elfs_length; ++j) {
            Elf64_Shdr shdr = in_shdrs[j][i_sect];
            sect->header.sh_size = round_to_aligned(
                sect->header.sh_size, shdr.sh_addralign + !shdr.sh_addralign);
            memcpy(
                sect->contents + sect->header.sh_size,
                in_section_contents[j][i_sect],
                shdr.sh_size);
            sect->header.sh_size += shdr.sh_size;
        }
    }

    // ------------------------------------------------------------------------
    // Create segments

    CLEANUP DynArr(Segment) segments = NULL;
    const Elf64_Addr base_address = 0x400000; // ld default value, somewhat arbitrary
    dynarr_push(&segments, ((Segment) { // The first segment for debuggers and
        .header = {                     // other tooling contains ELF header and
            .p_type  = PT_LOAD,         // program headers.
            .p_flags = PF_R,
            .p_vaddr = base_address,
            .p_paddr = base_address
        }
    }));
    dynarr_add_reserve(
        sizeof(unsigned char),
        &segments->data[0].contents,
        sizeof(Elf64_Ehdr)
            + 4/* guess */         * sizeof(Elf64_Phdr)
            + out_sections->length * sizeof(Elf64_Shdr)
            + out_sections->data[shstrtab_index].header.sh_size
            + out_sections->data[symstrtab_index].header.sh_size
            + out_sections->data[symtab_index].header.sh_size
            + 64/* other stuff */);

    // Sort sections to segments
    for (size_t i_sect = 0; i_sect < out_sections->length; ++i_sect)
    {
        Section* sect = &out_sections->data[i_sect];
        size_t  i_seg = 0;

        if (sect->header.sh_type == SHT_PROGBITS) // find segment
        {
            static const
            Elf64_Xword shf_to_pf[SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR] = {
                [SHF_ALLOC | SHF_EXECINSTR] = PF_R | PF_X,
                [SHF_ALLOC | SHF_WRITE    ] = PF_R | PF_W,
                [SHF_ALLOC                ] = PF_R
            };
            Elf64_Xword flags = shf_to_pf[
                sect->header.sh_flags & (SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR)];

            for (i_seg = 1; i_seg < segments->length; ++i_seg)
                if (segments->data[i_seg].header.p_flags == flags)
                    break;

            dynarr_push(&segments, ((Segment) {
                .header = {
                    .p_type  = PT_LOAD,
                    .p_flags = flags,
                    .p_vaddr = base_address,
                    .p_paddr = base_address,
                    .p_align = 0x1000
                }
            }));
        } // else dump everything to 0 segment.

        dynarr_align(&segments->data[i_seg].contents, sect->header.sh_addralign);
        sect->segment_index  = i_seg;
        sect->segment_offset = segments->data[i_seg].contents->length;
        // Note: segment offset for first segment is incorrect here (missing
        // program header table size and section header table size) because we
        // don't know the number of segments yet, so it has to be compensated
        // later.

        dynarr_append(
            &segments->data[i_seg].contents, sect->contents, sect->header.sh_size);
    }
    segments->data[0].header.p_filesz = segments->data[0].header.p_memsz =
        sizeof(Elf64_Ehdr) + segments->length * sizeof(Elf64_Phdr);

    // ------------------------------------------------------------------------
    // Create output

    Elf64_Ehdr out_ehdr = {
        .e_ident     = { 0x7F, 'E', 'L', 'F', ELFCLASS64, ELFDATA2LSB, EV_CURRENT },
        .e_type      = ET_EXEC,
        .e_machine   = EM_X86_64,
        .e_version   = EV_CURRENT,
        .e_shoff     = sizeof out_ehdr + segments->length * sizeof(Elf64_Phdr),
        .e_phoff     = sizeof out_ehdr,
        .e_flags     = 0,
        .e_ehsize    = sizeof out_ehdr,
        .e_phentsize = sizeof(Elf64_Phdr),
        .e_phnum     = segments->length,
        .e_shentsize = sizeof(Elf64_Shdr),
        .e_shnum     = out_sections->length,
        .e_shstrndx  = shstrtab_index,
    };

    CLEANUP DynArr(unsigned char) out_data = NULL;
    dynarr_append(&out_data, &out_ehdr, sizeof out_ehdr);

    // Append segment and section header tables
    // Note: the headers have some incorrect addresses at this point, but we
    // find and update them later.
    for (size_t i = 0; i < segments->length; ++i)
        dynarr_append(
            &out_data,
            &segments->data[i].header,
            sizeof segments->data[i].header);
    for (size_t i = 0; i < out_sections->length; ++i)
        dynarr_append(
            &out_data,
            &out_sections->data[i].header,
            sizeof out_sections->data[i].header);

    // Append all segment contents. At this point we also know file offsets,
    // update those as well.
    dynarr_append(
        &out_data, segments->data[0].contents->data, segments->data[0].contents->length);
    // Section headers not counted since loader does not need them.
    Elf64_Xword seg0size = sizeof(Elf64_Ehdr) + segments->length * sizeof(Elf64_Phdr);
    ((Elf64_Phdr*)(out_data->data + out_ehdr.e_phoff))->p_filesz = seg0size;
    ((Elf64_Phdr*)(out_data->data + out_ehdr.e_phoff))->p_memsz  = seg0size;
    ((Elf64_Phdr*)(out_data->data + out_ehdr.e_phoff))->p_align  = 0x1000;

    for (size_t i = 1; i < segments->length; ++i)
    {
        Segment seg = segments->data[i];
        if (seg.contents == NULL) // prevent NULL dereference
            dynarr_add_reserve(sizeof seg.contents->data[0], &seg.contents, 1);

        dynarr_align(&out_data, seg.header.p_align);
        Elf64_Phdr* phdrs = (Elf64_Phdr*)(out_data->data + out_ehdr.e_phoff);
        phdrs[i].p_filesz = seg.contents->length;
        phdrs[i].p_memsz  = seg.contents->length;
        phdrs[i].p_offset = out_data->length;
        phdrs[i].p_vaddr += out_data->length;
        phdrs[i].p_paddr += out_data->length;
        dynarr_append(&out_data, seg.contents->data, seg.contents->length);
        if (seg.contents->length == 0) // force unique offset for empty segments
            dynarr_push(&out_data, '\0');
    }

    // All data has been written so we know all file offsets, so now we can
    // update the offsets of the final section headers.
    Elf64_Phdr* segs = (Elf64_Phdr*)(out_data->data + out_ehdr.e_phoff);
    Elf64_Shdr* secs = (Elf64_Shdr*)(out_data->data + out_ehdr.e_shoff);
    for (size_t i = 0; i < out_sections->length; ++i)
    {
        Section sect = out_sections->data[i];
        size_t  k    = sect.segment_index;
        secs[i].sh_offset = segs[k].p_offset + sect.segment_offset;
        if (k == 0) // do the header tables size compensation mentioned in a comment way above
            secs[i].sh_offset +=     1 * sizeof(Elf64_Ehdr)
                + segments->length     * sizeof(Elf64_Phdr)
                + out_sections->length * sizeof(Elf64_Shdr);

        if (secs[i].sh_flags & SHF_ALLOC)
            secs[i].sh_addr = secs[i].sh_offset + base_address;
        else
            secs[i].sh_addr = 0;
    }

    // Update symbols too
    Elf64_Sym* syms = (Elf64_Sym*)(out_data->data + secs[symtab_index].sh_offset);
    for (size_t i = 0; i < sym_map->length; ++i) {
        if (syms[i].st_shndx < SHN_LORESERVE)
            syms[i].st_value += secs[syms[i].st_shndx].sh_addr;
        if (strcmp(out_symstrtab->data + syms[i].st_name, "_start") == 0)
            ((Elf64_Ehdr*)out_data->data)->e_entry = syms[i].st_value;
    }

    // ------------------------------------------------------------------------
    // Apply relocations

    for (size_t rel_index = 0; rel_index < rel_indices_length; ++rel_index)
    {
        size_t i_rel_sect = rel_indices[rel_index];

        const char* rel_sect_name = out_sections->data[i_rel_sect].name;
        size_t i_sect_target = index_of(out_sections, 0, rel_sect_name + strlen(".rela"), NULL);
        Assert(i_sect_target != out_sections->length);
        void* rel_sect_data = out_data->data + secs[i_sect_target].sh_offset;

        Elf64_Shdr  rels_shdr = secs[i_rel_sect];
        Elf64_Rela* rels = (Elf64_Rela*)(out_data->data + rels_shdr.sh_offset);
        for (size_t i_rel = 0; i_rel < rels_shdr.sh_size/rels_shdr.sh_entsize; ++i_rel)
        {
            uint32_t dword;
            uint64_t qword;
            Elf64_Rela rel = rels[i_rel];
            Elf64_Xword type = ELF64_R_TYPE(rel.r_info);
            Elf64_Xword i_sym = ELF64_R_SYM(rel.r_info);
            Elf64_Sym sym = syms[i_sym];
            void* target = rel_sect_data + rel.r_offset;

            switch (type)
            {
            case R_X86_64_NONE:
                break;

            case R_X86_64_32: case R_X86_64_32S:
                dword = sym.st_value + rel.r_addend;
                memcpy(target, &dword, sizeof dword);
                break;

            case R_X86_64_64:
                qword = sym.st_value + rel.r_addend;
                memcpy(target, &qword, sizeof qword);
                break;

            case R_X86_64_PLT32:
                dword = sym.st_value + rel.r_addend - (rel.r_offset + secs[sym.st_shndx].sh_addr);
                memcpy(target, &dword, sizeof dword);
                break;

            case R_X86_64_PC32:
                dword = sym.st_value + rel.r_addend - (rel.r_offset + secs[i_sect_target].sh_addr);
                memcpy(target, &dword, sizeof dword);
                break;

            case R_X86_64_PC64:
                qword = sym.st_value + rel.r_addend - (rel.r_offset + secs[i_sect_target].sh_addr);
                memcpy(target, &qword, sizeof qword);
                break;

            default:
                user_assert(0, "Unsupported relocation type: %lu\n", type);
            }
        }

        // Prevent loader from doing relocation fixups at load time.
        secs[i_rel_sect].sh_size = 0;
    }

    // ------------------------------------------------------------------------
    // Finally, write the actual output file.

    FILE* out_fp = fopen(out_path, "wb");
    user_assert(out_fp != NULL, "Cannot create %s: fopen(): %s\n", out_path, strerror(errno));
    user_assert(
        fwrite(out_data->data, 1, out_data->length, out_fp) == out_data->length,
        "Cannot write to %s: fwrite(): %s\n", out_path, strerror(errno));
    fclose(out_fp);
    Assert(chmod(out_path, 0755) != -1, "%s\n", strerror(errno));

    // pedantic cleanup
    for (size_t i = 0; i < segments->length; ++i)
        free(segments->data[i].contents);
}
