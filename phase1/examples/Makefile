simple: simple.cpp simpleshared.so
	clang++ -L. -lsimpleshared -o simple simple.cpp -Wl,-rpath,"\$$ORIGIN" 
simpleshared.so: simpleshared.h simpleshared.cpp
	clang++ -fPIC -shared simpleshared.cpp -o libsimpleshared.so