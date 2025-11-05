all:
	clang -c -Wall -Wextra -ggdb3 -gdwarf main.c
	clang -c -Wall -Wextra shared_foo.c -Oz
	clang -o shared_foo.so shared_foo.o -shared
	clang main.o shared_foo.so

SANITIZERS = -fsanitize=address -fsanitize=leak -fsanitize=undefined

debug:
	clang -c -Wall -Wextra -ggdb3 -gdwarf main.c $(SANITIZERS)
	clang -c -Wall -Wextra shared_foo.c -Oz
	clang -o shared_foo.so shared_foo.o -shared
	clang main.o shared_foo.so $(SANITIZERS)
