# MIT License
# Copyright (c) 2025 Lauri Lorenzo Fiestas
# https://github.com/PrinssiFiestas/MicroELFLinker/blob/main/LICENSE

# Targets
.PHONY: all   # default, builds with debug symbols.
.PHONY: debug # same as all except with sanitizers.
.PHONY: clean # remove build junk

ELFNAME = peekelf
CC = cc

all:
	as -o hello.o -g hello.asm
	ld -o hello hello.o
	as -o foobar.o -g foobar.asm
	as -o bar.o -g bar.asm
	ld -o foobar foobar.o bar.o
	$(CC) -c -Wall -Wextra -ggdb3 -gdwarf $(ELFNAME).c $(SANITIZERS)
	$(CC) -c -Wall -Wextra shared_foo.c -Os
	$(CC) -o shared_foo.so shared_foo.o -shared
	$(CC) -o $(ELFNAME) $(ELFNAME).o shared_foo.so $(SANITIZERS)

debug: SANITIZERS = -fsanitize=address -fsanitize=leak -fsanitize=undefined
debug: all

clean:
	rm *.o *.so $(ELFNAME)
