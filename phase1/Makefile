sqlite3.o: sqlite3.c sqlite3.h
	clang -fPIC -c -g sqlite3.c

recordsymbolslib.so: recordsymbols.cpp sqlite3.o
	clang++  -std=c++17 -fPIC -shared -O3 -g -o recordsymbolslib.so recordsymbols.cpp sqlite3.o \
			-Wall -Wextra -Werror -pedantic -Wno-unused-parameter
clean:
	rm -f recordsymbolslib.so sqlite3.o database.db

run: recordsymbolslib.so
	LD_BIND_NOW=true LD_AUDIT=./recordsymbolslib.so whoami

.PHONY: clean run
.DEFAULT_GOAL := recordsymbolslib.so