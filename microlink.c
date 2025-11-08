// MIT License
// Copyright (c) 2025 Lauri Lorenzo Fiestas
// https://github.com/PrinssiFiestas/MicroELFLinker/blob/main/LICENSE

#include <elf.h>
#include "utils.h" // Assert(), xmalloc(), xrealloc(), round_to_aligned()
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdbool.h>

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

int main(int argc, char* argv[])
{
    if (argc == 1) {
        fprintf(stderr, "Usage: %s [file(s)]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    size_t      out_size  = 0;
    Elf64_Ehdr* out       = NULL;
    void*       out_elf   = NULL; // same as out, used for pointer arithmetic
    Elf64_Shdr* out_shdrs = NULL;
    Elf64_Phdr* out_phdrs = NULL;
    size_t      out_shstrtab_capacity = 16;
    size_t      out_shstrtab_length   = 0;
    char*       out_shstrtab          = NULL;

    size_t elfs_length = argc - 1;
    void** elfs = xmalloc(elfs_length * sizeof elfs[0]);
    Elf64_Ehdr** ehdrs = xmalloc(elfs_length * sizeof(void*)); // same as elfs, but casted for convenience
    out_shstrtab = xmalloc(out_shstrtab_capacity);

    for (size_t i = 0; i < elfs_length; ++i)
    {
        ehdrs[i] = elfs[i] = read_elf_file(argv[i + 1]);

        out_size += ehdrs[i]->e_shentsize * ehdrs[i]->e_shnum;

        for (size_t j = 0; j < ehdrs[i]->e_shnum; ++j)
        {
            Elf64_Shdr shdr = *(Elf64_Shdr*)(elfs[i] + ehdrs[i]->e_shoff);
            const char* sname = elfs[i] + ehdrs[i]->e_shstrndx + shdr.sh_name;

            const char* shstr;
            for (shstr = out_shstrtab;
                shstr < out_shstrtab + out_shstrtab_length;
                shstr += strlen(shstr) + sizeof"")
            {
                if (strcmp(shstr, sname) == 0)
                    break;
            }
            if (shstr > out_shstrtab)
            {
            }
        }
    }

    out_size += sizeof *out;
    out = out_elf = xmalloc(out_size);

}
