# Micro ELF Linker

Static x86_64 Linux ELF linker (`microlink`) and ELF examination utility (`peekelf`). This is a personal project that was meant to teach the inner workings of Linux executables and systems design. It is meant to be as simple to read and debug as possible, but also complete enough to be educationally useful i.e. it must be able to generate working executables. 

Simplicity and completeness are inherently conflicting requirements. Generating a working executable was the first priority, so simplicity here just means that the code has been written in the most straight forward way possible (minimal abstraction/indirection, simple control flow and project structure, only simple optimizations, etc.) given the complexity of an actually working ELF linker. 

## `microlink`

Creates simple static non-PIE executables from `.o` object files. Handles basic relocations of global symbols including procedures/functions. Links GNU assembler assembled object files and even some GCC and Clang compiled C code, although linking to standard libraries is not supported and `-fno-PIE` flag must be used. `-std=c99` recommended, but any C version will work as long as thread local storage or other features that require linker support are not used. 

## `peekelf`

Examines ELF files and prints basic information. Unlike `readelf`, no flags are implemented, just dumps all information to standard output instead. Prints sections, segments, symbols, and dynamically linked symbols.

## Build and Run

Clone the repository, navigate to it's root and run

```bash
make
```

This will build the executables and some test object files. 

Running the linker:

```bash
./microlink [-o out_name] [object_files...]
```

Running the ELF examination utility:

```bash
./peekelf [object_file]
```

`foo.c`, `foobar.s`, and `bar.s` contain assembly and C code that can be linked to an executable. Automated tests that link these files in different orders and runs them can be run with

```bash
make tests
```

## References

- [ELF Format Cheatsheet](https://gist.github.com/x0nu11byt3/bcb35c3de461e5fb66173071a2379779)
- [Oracle Linker Guide](https://docs.oracle.com/cd/E19683-01/816-1386/6m7qcoblh/index.html)
- [Ian Lance Taylor (author of GOLD) blogs](https://www.airs.com/blog/archives/38)
- [elf(5) man pages](https://www.man7.org/linux/man-pages/man5/elf.5.html)
- [elf.h](https://codebrowser.dev/glibc/glibc/elf/elf.h.html)
