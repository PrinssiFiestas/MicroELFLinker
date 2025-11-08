# Micro ELF Linker

Tiny little linker and ELF examination utility.

## Build and Run

Clone the repository, navigate to it's root and run

```bash
make
```

This will build the executables and some test object files. Running the ELF
examination utility:

```bash
export LD_LIBRARY_PATH+=.
./peekelf [object_file]
```

