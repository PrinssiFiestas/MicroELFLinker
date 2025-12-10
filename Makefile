# MIT License
# Copyright (c) 2025 Lauri Lorenzo Fiestas
# https://github.com/PrinssiFiestas/MicroELFLinker/blob/main/LICENSE

# Targets
.PHONY: all   # default, builds with debug symbols.
.PHONY: debug # same as all except with sanitizers.
.PHONY: clean # remove build junk
.PHONY: tests # build and run tests

LNKNAME = microlink
ELFNAME = peekelf
CC = cc

all:
	as -o hello.o hello.s
	$(CC) -o foo.o -c foo.c -Os -no-pie -ansi -nolibc
	as -o foobar.o foobar.s
	as -o bar.o bar.s
	$(CC) -o $(LNKNAME) -Wall -Wextra -ggdb3 -gdwarf $(LNKNAME).c $(SANITIZERS)
	$(CC) -c -Wall -Wextra -ggdb3 -gdwarf $(ELFNAME).c $(SANITIZERS)
	$(CC) -o $(ELFNAME) $(ELFNAME).o $(SANITIZERS)

debug: SANITIZERS = -fsanitize=address -fsanitize=leak -fsanitize=undefined
debug: all

tests: clean all
	./$(LNKNAME) foo.o foobar.o bar.o && ./a.out > test.txt
	diff test.txt tests_expected_output.txt
	./$(LNKNAME) foo.o bar.o foobar.o && ./a.out > test.txt
	diff test.txt tests_expected_output.txt
	./$(LNKNAME) foobar.o foo.o bar.o && ./a.out > test.txt
	diff test.txt tests_expected_output.txt
	./$(LNKNAME) foobar.o bar.o foo.o && ./a.out > test.txt
	diff test.txt tests_expected_output.txt
	./$(LNKNAME) bar.o foo.o foobar.o && ./a.out > test.txt
	diff test.txt tests_expected_output.txt
	./$(LNKNAME) bar.o foobar.o foo.o && ./a.out > test.txt
	diff test.txt tests_expected_output.txt
	@echo "Passed all tests!"

clean:
	rm -f a.out foobar hello test.txt *.o *.so $(ELFNAME) $(LNKNAME)
