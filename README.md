# Micro ELF Linker

Static x86_64 Linux ELF linker (`microlink`) and ELF examination utility (`peekelf`). This is a personal project that was meant to teach the inner workings of Linux executables and systems design. It is meant to be as simple to read and debug as possible, but also complete enough to be educationally useful i.e. it must be able to generate working executables from assembler generated inputs. 

Simplicity and completeness are inherently conflicting requirements. Generating a working executable was the first priority, so simplicity here just means that the code has been written in the most straight forward way possible (minimal abstraction/indirection, simple control flow and project structure, only simple optimizations, etc.) given the complexity of an actually working ELF linker. 

## `microlink`

Creates simple static non-PIE executables from simple `*.o` object files. Handles basic relocations of global symbols including procedures. 

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

