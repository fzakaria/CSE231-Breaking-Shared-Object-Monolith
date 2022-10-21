all:
	clang -fPIC -shared -O3 -g -o recordsymbolslib.so recordsymbols.cpp -Wall -Wextra -Werror -pedantic -Wno-unused-parameter

clean:
	rm -f recordsymbolslib.so


.PHONY: all clean