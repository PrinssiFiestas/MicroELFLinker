# MIT License
# Copyright (c) 2025 Lauri Lorenzo Fiestas
# https://github.com/PrinssiFiestas/MicroELFLinker/blob/main/LICENSE

# Targets
.PHONY: all   # default, builds with debug symbols.
.PHONY: debug # same as all except with sanitizers.
.PHONY: clean # remove build junk

LNKNAME = microlink
ELFNAME = peekelf
CC = cc

all:
	as -o hello.o -g hello.s
	ld -o hello hello.o
	as -o foobar.o -g foobar.s
	as -o bar.o -g bar.s
	ld -o foobar foobar.o bar.o
	$(CC) -o $(LNKNAME) -Wall -Wextra -ggdb3 -gdwarf $(LNKNAME).c $(SANITIZERS)
	$(CC) -c -Wall -Wextra -ggdb3 -gdwarf $(ELFNAME).c $(SANITIZERS)
	$(CC) -o $(ELFNAME) $(ELFNAME).o $(SANITIZERS)

debug: SANITIZERS = -fsanitize=address -fsanitize=leak -fsanitize=undefined
debug: all

clean:
	rm -f a.out foobar hello *.o *.so $(ELFNAME) $(LNKNAME)
