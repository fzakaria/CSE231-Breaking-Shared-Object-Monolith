sqlite3.o: sqlite3.c sqlite3.h
	clang -c -g sqlite3.c

recordsymbolslib.so: recordsymbols.cpp sqlite3.o
	clang++ -fPIC -shared -O3 -g -o recordsymbolslib.so recordsymbols.cpp \
			-Wall -Wextra -Werror -pedantic -Wno-unused-parameter
clean:
	rm -f recordsymbolslib.so sqlite3.o

run:
	LD_AUDIT=./recordsymbolslib.so whoami

.PHONY: clean run
.DEFAULT_GOAL := recordsymbolslib.so