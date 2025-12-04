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

typedef struct segment
{
    Elf64_Phdr            header;
    DynArr(unsigned char) contents;
} Segment;

typedef struct section
{
    const char*           name;
    const char*           link; // section of associated string/symbol table
    size_t                segment_index;
    Elf64_Off             segment_offset;
    Elf64_Off             section_offset; // previous length in merging loop
    Elf64_Shdr            header;
    DynArr(unsigned char) contents;
} Section;

void* read_elf_file(const char* path)
{
    struct stat st;
    Assert(stat(path, &st) != -1, "%s\n", strerror(errno));

    void* elf = xmalloc(st.st_size);
    FILE* fp  = fopen(path, "rb");
    Assert(fp != NULL, "%s\n", strerror(errno));
    Assert(fread(elf, 1, st.st_size, fp) == (size_t)st.st_size, "%s\n", strerror(errno));
    fclose(fp);
    Assert(memcmp(elf, "\x7F""ELF", 4) == 0, "%s is not an ELF binary.\n", path);

    return elf;
}

// Find segment of specific type with given flags. Create one if not found.
size_t get_make_segment_index(
    void*_segments,
    Elf64_Word type,
    Elf64_Word flags,
    Elf64_Addr voffset, // used if new created
    Elf64_Xword align)  // used if new created
{
    DynArr(Segment)* segs_ptr = _segments;
    typeof(*segs_ptr) segs = *segs_ptr;

    size_t k = 0;
    for (; k < segs->length; ++k)
        if (segs->data[k].header.p_type == type && segs->data[k].header.p_flags == flags)
            break;

    if (k == segs->length) {
        Segment s = {
            .header = {
                .p_type  = type,
                .p_flags = flags,
                .p_vaddr = voffset, // file offsets added later
                .p_paddr = voffset,
                .p_align = align
            }
        };
        dynarr_push(segs_ptr, s);
    }
    return k;
}

int main(int argc, char* argv[])
{
    if (argc == 1) {
        fprintf(stderr, "Usage: %s [file(s)]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    DynArr(Section) sections = NULL;

    size_t elfs_length = argc - 1;
    void** elfs = xmalloc(elfs_length * sizeof elfs[0]);
    Elf64_Ehdr** ehdrs = xmalloc(elfs_length * sizeof(void*)); // same as elfs casted for convenience

    // ------------------------------------------------------------------------
    // Read input files and merge sections

    DynArr(char) out_symstrtab = NULL;
    dynarr_append(&out_symstrtab, "", sizeof"");
    DynArr(const char*) rel_sym_links = NULL;

    dynarr_push(&sections, ((Section){.name = "", .link = ""})); // empty section at the start is common
    for (size_t i = 0; i < elfs_length; ++i)
    {
        ehdrs[i] = elfs[i] = read_elf_file(argv[i + 1]);
        Elf64_Ehdr  ehdr      = *(ehdrs[i]);
        Elf64_Shdr* shdrs     = elfs[i] + ehdr.e_shoff;
        const char* shstrtab  = elfs[i] + shdrs[ehdr.e_shstrndx].sh_offset;
        size_t      i_symtab  = 0;
        const char* symstrtab = NULL;
        for (size_t j = 0; j < ehdr.e_shnum; ++j) {
            if (shdrs[j].sh_type == SHT_STRTAB
                && strcmp(shstrtab + shdrs[j].sh_name, ".strtab") == 0)
            {
                symstrtab = elfs[i] + shdrs[j].sh_offset;
                break;
            }
        }
        Assert(symstrtab != NULL, "No .strtab found in %s\n", argv[i + 1]);

        for (size_t j = 0; j < ehdr.e_shnum; ++j)
        {
            Elf64_Shdr shdr = shdrs[j];

            // Find output section
            size_t k = 0;
            for (; k < sections->length; ++k)
                if (strcmp(sections->data[k].name, shstrtab + shdr.sh_name) == 0)
                    break;

            if (k == sections->length) { // no output section found, create
                Section section = {
                    .name = shstrtab + shdr.sh_name,
                    .link = shstrtab + shdrs[shdr.sh_link].sh_name,
                    .header = shdr
                };
                dynarr_push(&sections, section);
            } else {
                Assert(shdr.sh_type == sections->data[k].header.sh_type,
                       "Expected matching types for %s.\n", sections->data[k].name);
                Assert(shdr.sh_flags == sections->data[k].header.sh_flags,
                       "Expected matching flags for %s.\n", sections->data[k].name);
                Assert(shdr.sh_addralign == sections->data[k].header.sh_addralign,
                       "Expected matching alignment for %s\n", sections->data[k].name);
                Assert(shdr.sh_entsize == sections->data[k].header.sh_entsize,
                       "Expected matching entry sizes for %s\n", sections->data[k].name);
            }
            Section* out_sect = sections->data + k;
            if (shdr.sh_type == SHT_SYMTAB)
                i_symtab = k;
            else if (shdr.sh_type == SHT_RELA)
            {
                Elf64_Rela* rels = elfs[i] + shdr.sh_offset;
                Elf64_Sym*  syms = NULL;
                for (size_t h = 0; h < ehdr.e_shnum; ++h) {
                    if (shdrs[h].sh_type == SHT_SYMTAB) {
                        syms = elfs[i] + shdrs[h].sh_offset;
                        break;
                    }
                }
                Assert(syms != NULL, "No symbol table found.\n");

                for (size_t i_rel = 0; i_rel < shdr.sh_size / shdr.sh_entsize; ++i_rel)
                {
                    size_t i_sym = ELF64_R_SYM(rels[i_rel].r_info);
                    if (ELF64_ST_TYPE(syms[i_sym].st_info) == STT_SECTION)
                        dynarr_push(
                            &rel_sym_links, shstrtab + shdrs[syms[i_sym].st_shndx].sh_name);
                    else
                        dynarr_push(&rel_sym_links, symstrtab + syms[i_sym].st_name);
                }
            }

            size_t i_syms_start = 0;
            if (out_sect->contents != NULL) {
                i_syms_start = out_sect->contents->length / (shdr.sh_entsize + !shdr.sh_entsize);
                out_sect->section_offset = out_sect->contents->length;
            }
            size_t i_sym = i_syms_start;

            dynarr_align(&out_sect->contents, shdr.sh_addralign);
            dynarr_append(
                &out_sect->contents, elfs[i] + shdr.sh_offset, shdr.sh_size);
            out_sect->header.sh_size = out_sect->contents->length;

            size_t i_syms_end = out_sect->contents->length
                / (shdr.sh_entsize + !shdr.sh_entsize);

            if (shdr.sh_type == SHT_SYMTAB) for (; i_sym < i_syms_end; ++i_sym)
            { // update all st_name
                Elf64_Sym* syms = (Elf64_Sym*)(out_sect->contents->data);
                Elf64_Sym* sym  = syms + i_sym;
                size_t i_strtab = 0;
                for (size_t len; i_strtab < out_symstrtab->length; i_strtab += len + sizeof"")
                {
                    len = strlen(out_symstrtab->data + i_strtab);
                    if (strcmp(
                            out_symstrtab->data + i_strtab,
                            symstrtab + sym->st_name) == 0)
                        break;
                }

                if (i_strtab == out_symstrtab->length) // no strtab entry found, create
                    dynarr_append(
                        &out_symstrtab,
                        symstrtab + sym->st_name,
                        strlen(symstrtab + sym->st_name) + sizeof"");
                sym->st_name = i_strtab;
            }
        } // for (size_t j = 0; j < ehdr.e_shnum; ++j)

        // Update all st_shndx and st_value
        Section* syms = &sections->data[i_symtab];
        for (size_t j = syms->section_offset;
            j < syms->contents->length;
            j += syms->header.sh_entsize)
        {
            Elf64_Sym* sym = (Elf64_Sym*)(syms->contents->data + j);
            if (sym->st_shndx >= SHN_LOPROC)
                continue;

            size_t k = 0;
            for (; k < sections->length; ++k)
                if (strcmp(
                    sections->data[k].name,
                    shstrtab + shdrs[sym->st_shndx].sh_name) == 0)
                break;

            sym->st_shndx = k;
            if (ELF64_ST_TYPE(sym->st_info) != STT_SECTION)
                sym->st_value += sections->data[k].section_offset;
        }






        #if 0
        // Update all r_offset, ELF64_R_SYM(r_info), and r_addend
        for (size_t i_sect = 0; i_sect < sections->length; ++i_sect)
        {
            Section* rels = &sections->data[i_sect];
            if (rels->header.sh_type != SHT_RELA)
                continue;

            size_t section_offset = 0;
            for (size_t k = 0; k < sections->length; ++k) {
                if (strcmp(
                        sections->data[k].name,
                        rels->name + strlen(".rela")) == 0)
                {
                    section_offset = sections->data[k].section_offset;
                    break;
                }
            }

            for (size_t j = rels->section_offset;
                j < rels->contents->length;
                j += rels->header.sh_entsize)
            {
                Elf64_Rela* rel = (Elf64_Rela*)(rels->contents->data + j);
                rel->r_offset += section_offset;

                Elf64_Xword i_sym = ELF64_R_SYM(rel->r_info);
                Elf64_Xword type = ELF64_R_TYPE(rel->r_info);
                Elf64_Xword i_sym_offset = syms->section_offset/syms->header.sh_entsize;
                Elf64_Sym*  symtab = (Elf64_Sym*)syms->contents->data;
                Elf64_Sym   sym    = symtab[i_sym_offset + i_sym];

                // as uses sections with addends for known data instead of
                // symbols directly for whatever reason.
                if (ELF64_ST_TYPE(sym.st_info) == STT_SECTION)
                    rel->r_addend += sections->data[sym.st_shndx].section_offset;

                i_sym += i_sym_offset;
                rel->r_info = ELF64_R_INFO(i_sym, type);
            }
        }
        #endif








    } // for (size_t i = 0; i < elfs_length; ++i)

    // Replace symbol string table contents
    for (size_t i = 0; i < sections->length; ++i) {
        Section* sect = sections->data + i;
        if (sect->header.sh_type == SHT_STRTAB && strcmp(sect->name, ".strtab") == 0)
        {
            free(sect->contents);
            sect->contents = (typeof(sect->contents))out_symstrtab;
            break;
        }
    }

    // Update sh_link
    for (size_t i = 0; i < sections->length; ++i) {
        for (size_t j = 0; j < sections->length; ++j) {
            Section* sect_i = &sections->data[i];
            Section  sect_j =  sections->data[j];
            if (strcmp(sect_i->link, sect_j.name) == 0) {
                sect_i->header.sh_link = j;
                goto next;
            }
        }
        next:;
    }

    // Resolve undefined symbols
    for (size_t i = 0; i < sections->length; ++i) {
        Section* sect = &sections->data[i];
        if (sect->header.sh_type != SHT_SYMTAB)
            continue;

        Elf64_Sym* syms = (Elf64_Sym*)(sect->contents->data);
        size_t syms_length = sect->header.sh_size / sect->header.sh_entsize;
        for (size_t j = 0; j < syms_length; ++j)
        {
            // Silence readelf warnings. (don't do this)
            if (ELF64_ST_BIND(syms[j].st_info) == STB_LOCAL)
                sect->header.sh_info = j + 1;

            // Enforce ODR
            if (ELF64_ST_BIND(syms[j].st_info) == STB_GLOBAL && syms[j].st_shndx != SHN_UNDEF)
                for (size_t k = j + 1; k < syms_length; ++k)
                    if (syms[k].st_shndx != SHN_UNDEF && strcmp(
                        out_symstrtab->data + syms[j].st_name,
                        out_symstrtab->data + syms[k].st_name) == 0
                    )
                        Assert(
                            ELF64_ST_BIND(syms[k].st_info) != STB_GLOBAL,
                               "Multiple definitions of %s\n",
                               out_symstrtab->data + syms[j].st_name);

            if (syms[j].st_shndx != SHN_UNDEF)
                continue;
            if (out_symstrtab->data[syms[j].st_name] == '\0') // empty symbol
                continue;

            // Find first defined
            size_t k = 0;
            for (; k < syms_length; ++k)
                if (syms[k].st_shndx != SHN_UNDEF
                    && ELF64_ST_BIND(syms[k].st_info) != STB_LOCAL
                    && strcmp(
                        out_symstrtab->data + syms[j].st_name,
                        out_symstrtab->data + syms[k].st_name) == 0)
                    break;
            Assert(k != syms_length, "Undefined reference to %s\n",
                out_symstrtab->data + syms[j].st_name);

            // Final symbol resolution. We'll have duplicate symbols at this
            // point, which is fine, they can be cleaned up later (if we care).
            syms[j] = syms[k];
        }


        // Update relocation symbol indices
        for (size_t j = 0, i = 0; i < sections->length; ++i)
        {
            if (sections->data[i].header.sh_type != SHT_RELA)
                continue;

            Section* sect = &sections->data[i];
            size_t rels_length = sect->header.sh_size / sect->header.sh_entsize;
            Elf64_Rela* rels = (Elf64_Rela*)sect->contents->data;

            for (size_t k = 0; k < rels_length; ++j, ++k) {
                Elf64_Xword type = ELF64_R_TYPE(rels[k].r_info);
                Elf64_Xword sym = 0;
                // First try find symbol by name. This will fail when symbol is
                // a section due to empty name.
                for (; sym < syms_length; ++sym)
                    if (strcmp(
                            out_symstrtab->data + syms[sym].st_name,
                            rel_sym_links->data[j]) == 0)
                        break;
                // Try find section symbol.
                if (sym == syms_length) for (sym = 0; sym < syms_length; ++sym)
                    if (strcmp(
                            sections->data[syms[sym].st_shndx].name,
                            rel_sym_links->data[j]) == 0)
                        break;
                Assert(sym != syms_length, "Where did our symbol name go??\n");

                rels[k].r_info = ELF64_R_INFO(sym, type);
            }
        }
    }












    // ------------------------------------------------------------------------
    // Create segments

    DynArr(Segment) segments = NULL;
    DynArr(char) out_shstrtab = NULL;
    dynarr_add_reserve(sizeof(char), &out_shstrtab, 1);
    size_t out_shstrtab_index = 0;

    // We'll just do what ld does.
    // https://stackoverflow.com/questions/14314021/why-linux-gnu-linker-chose-address-0x400000
    const Elf64_Addr voffset = 0x400000;

    // The first segment for debuggers and other tooling contains ELF header and
    // program headers.
    Segment header_segment = {
        .header = {
            .p_type   = PT_LOAD,
            .p_flags  = PF_R,
            .p_vaddr  = voffset,
            .p_paddr  = voffset,
        }
    };
    dynarr_push(&segments, header_segment);

    // Build section header string table
    for (size_t i = 0; i < sections->length; ++i)
    {
        Section* sect = &sections->data[i];
        sect->header.sh_name = out_shstrtab->length;
        const char* name = sect->name;
        dynarr_append(&out_shstrtab, name, strlen(name) + sizeof"");

        if (sect->header.sh_type == SHT_STRTAB && strcmp(sect->name, ".shstrtab") == 0)
            out_shstrtab_index = i;
    }
    // Replace section header string table contents
    {
        Section* sect = &sections->data[out_shstrtab_index];
        free(sect->contents);
        sect->contents = (typeof(sect->contents))out_shstrtab;
        sect->header.sh_size = out_shstrtab->length;
    }

    static const
    Elf64_Xword translate_flags[SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR] = {
        [SHF_ALLOC | SHF_EXECINSTR] = PF_R | PF_X,
        [SHF_ALLOC | SHF_WRITE    ] = PF_R | PF_W,
        [SHF_ALLOC                ] = PF_R
    };

    // Sort sections to segments
    for (size_t i = 0; i < sections->length; ++i)
    {
        Section* sect = &sections->data[i];
        size_t k = 0;

        if (sect->header.sh_type == SHT_PROGBITS)
        {
            Elf64_Xword flags = translate_flags[
                sect->header.sh_flags & (SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR)];
            if (flags == 0)
                flags = PF_R;
             k = get_make_segment_index(
                &segments,
                PT_LOAD,
                flags,
                voffset,
                0x1000);
        }

        dynarr_align(&segments->data[k].contents, sect->header.sh_addralign);

        // Note: segment offset for first segment is incorrect here (missing
        // program header table size and section header table size) because we
        // don't know the number of segments yet, so it has to be compensated
        // later.
        if (segments->data[k].contents != NULL)
            sect->segment_offset = segments->data[k].contents->length;
        else
            sect->segment_offset = 0;
        sect->segment_index = k;

        dynarr_append(
            &segments->data[k].contents, sect->contents->data, sect->contents->length);
    }

    segments->data[0].header.p_filesz = segments->data[0].header.p_memsz =
        sizeof(Elf64_Ehdr) + segments->length * sizeof(Elf64_Phdr);

    // ------------------------------------------------------------------------
    // Create final output

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
        .e_shnum     = sections->length,
        .e_shstrndx  = out_shstrtab_index,
    };

    DynArr(unsigned char) out_data = NULL;
    dynarr_append(&out_data, &out_ehdr, sizeof out_ehdr);

    // Append segment and section header tables
    // Note: the headers have some incorrect addresses at this point, but we
    // find and update them later.
    for (size_t i = 0; i < segments->length; ++i)
        dynarr_append(
            &out_data,
            &segments->data[i].header,
            sizeof segments->data[i].header);
    for (size_t i = 0; i < sections->length; ++i)
        dynarr_append(
            &out_data,
            &sections->data[i].header,
            sizeof sections->data[i].header);

    // Append all segment contents. At this point we also know file offsets,
    // update those as well.
    dynarr_append(
        &out_data, segments->data[0].contents->data, segments->data[0].contents->length);
    Elf64_Xword seg0size = sizeof(Elf64_Ehdr) + segments->length * sizeof(Elf64_Phdr);
    ((Elf64_Phdr*)(out_data->data + out_ehdr.e_phoff))->p_filesz = seg0size;
    ((Elf64_Phdr*)(out_data->data + out_ehdr.e_phoff))->p_memsz  = seg0size;
    ((Elf64_Phdr*)(out_data->data + out_ehdr.e_phoff))->p_align  = 0x1000;
    for (size_t i = 1; i < segments->length; ++i)
    {
        Segment seg = segments->data[i];

        dynarr_align(&out_data, seg.header.p_align);
        Elf64_Phdr* phdrs = (Elf64_Phdr*)(out_data->data + out_ehdr.e_phoff);
        phdrs[i].p_filesz = seg.contents->length;
        phdrs[i].p_memsz  = seg.contents->length;
        phdrs[i].p_offset = out_data->length;
        phdrs[i].p_vaddr += out_data->length;
        phdrs[i].p_paddr += out_data->length;
        dynarr_append(&out_data, seg.contents->data, seg.contents->length);
    }

    // All data has been written so we know all file offsets, so now we can
    // update the offsets of the final section headers.
    Elf64_Phdr* segs = (Elf64_Phdr*)(out_data->data + out_ehdr.e_phoff);
    Elf64_Shdr* secs = (Elf64_Shdr*)(out_data->data + out_ehdr.e_shoff);
    for (size_t i = 0; i < sections->length; ++i)
    {
        Section sect = sections->data[i];
        size_t  k    = sect.segment_index;
        secs[i].sh_offset = segs[k].p_offset + sect.segment_offset;
        if (k == 0) // do the header tables size compensation mentioned in a comment way above
            secs[i].sh_offset += sizeof(Elf64_Ehdr)
                + segments->length * sizeof(Elf64_Phdr)
                + sections->length * sizeof(Elf64_Shdr);

        if (secs[i].sh_flags & SHF_ALLOC)
            secs[i].sh_addr = secs[i].sh_offset + voffset;
        else
            secs[i].sh_addr = 0;
    }

    // ------------------------------------------------------------------------
    // Apply relocations

    // Get symbol table
    Elf64_Shdr syms_shdr = {0};
    Elf64_Sym* syms = NULL;
    for (size_t i = 0; i < sections->length; ++i) {
        if (secs[i].sh_type == SHT_SYMTAB) {
            Assert(syms == NULL, "Only one symbol table expected.\n");
            syms_shdr = secs[i];
            syms = (Elf64_Sym*)(out_data->data + secs[i].sh_offset);
        }
    }

    // Update symbol values before applying relocations.
    for (size_t i = 0; i < syms_shdr.sh_size/syms_shdr.sh_entsize; ++i) {
        if (syms[i].st_shndx < SHN_LOPROC)
            syms[i].st_value += secs[syms[i].st_shndx].sh_addr;
        if (strcmp(out_symstrtab->data + syms[i].st_name, "_start") == 0)
            ((Elf64_Ehdr*)out_data->data)->e_entry = syms[i].st_value;
    }

    // Apply relocations
    for (size_t i = 0; i < sections->length; ++i)
    {
        if (secs[i].sh_type != SHT_RELA)
            continue;
        const char* sect_name = sections->data[i].name;

        void* rel_sect_data = NULL;
        for (size_t j = 0; j < sections->length; ++j) {
            const char* name = sections->data[j].name;
            if (strcmp(sect_name + strlen(".rela"), name) == 0) {
                rel_sect_data = out_data->data + secs[j].sh_offset;
                break;
            }
        }

        Elf64_Shdr  rels_shdr = secs[i];
        Elf64_Rela* rels = (Elf64_Rela*)(out_data->data + secs[i].sh_offset);
        for (size_t j = 0; j < rels_shdr.sh_size/rels_shdr.sh_entsize; ++j)
        {
            uint32_t dword;
            uint64_t qword;
            Elf64_Rela rel = rels[j];
            Elf64_Xword type = ELF64_R_TYPE(rel.r_info);
            Elf64_Xword i_sym = ELF64_R_SYM(rel.r_info);
            Elf64_Sym sym = syms[i_sym];
            void* target = rel_sect_data + rel.r_offset;

            switch (type)
            {
            case R_X86_64_32: case R_X86_64_32S:
                dword = sym.st_value + rel.r_addend;
                memcpy(target, &dword, sizeof dword);
                break;

            case R_X86_64_64:
                qword = sym.st_value + rel.r_addend;
                memcpy(target, &qword, sizeof qword);
                break;

            // Note: we don't have a PLT, we just use symbol value instead.
            // Also note that we prematurely added symbol address to it's value,
            // so we have to compensate.
            case R_X86_64_PLT32: case R_X86_64_PC32:
                dword = sym.st_value + rel.r_addend - rel.r_offset
                    - secs[sym.st_shndx].sh_addr;
                memcpy(target, &dword, sizeof dword);
                break;

            case R_X86_64_PC64:
                qword = sym.st_value + rel.r_addend - rel.r_offset;
                memcpy(target, &qword, sizeof qword);
                break;
            }
        }

        // Prevent loader from doing relocation fixups at load time.
        secs[i].sh_size = 0;
    }

    // ------------------------------------------------------------------------
    // Finally, write the actual output file. // TODO -o flag

    const char* out_path = "a.out";
    FILE* out_fp = fopen(out_path, "wb");
    Assert(out_fp != NULL, "fopen(): %s\n", strerror(errno));
    Assert(fwrite(out_data->data, 1, out_data->length, out_fp) == out_data->length,
        "%s\n", strerror(errno));
    fclose(out_fp);
    Assert(chmod(out_path, 0755) != -1, "%s\n", strerror(errno));

    // ------------------------------------------------------------------------
    // Pedantic cleanup to shut up analyzers

    free(rel_sym_links);
    for (size_t i = 0; i < segments->length; ++i)
        free(segments->data[i].contents);
    free(segments);
    for (size_t i = 0; i < sections->length; ++i)
        free(sections->data[i].contents);
    free(sections);
    for (size_t i = 0; i < elfs_length; ++i) {
        free(elfs[i]);
    }
    free(elfs);
    free(ehdrs);
    free(out_data);
}
