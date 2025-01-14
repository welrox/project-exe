all: build/project-exe build/libkernel32.dylib build/libstdc++-6.dylib build/libmsvcrt.dylib build/libuser32.dylib

build/project-exe: src/main.cpp src/exe_parser_64.h src/macho_output.h src/macho.h src/pe.h
	g++ -Wall src/main.cpp -o build/project-exe -std=c++17

build/libkernel32.dylib: src/dlls/kernel32/main.cpp
	g++ src/dlls/kernel32/main.cpp -arch x86_64 -o build/libkernel32.dylib -shared -std=c++20 -O2 -rpath @executable_path/

build/libstdc++-6.dylib: src/dlls/libstdc++-6/main.cpp
	g++ src/dlls/libstdc++-6/main.cpp -arch x86_64 -o build/libstdc++-6.dylib -shared -std=c++17 -rpath @executable_path/

build/libmsvcrt.dylib: src/dlls/msvcrt/main.cpp
	g++ src/dlls/msvcrt/main.cpp -arch x86_64 -o build/libmsvcrt.dylib -shared -std=c++17 -O2 -rpath @executable_path/

build/libuser32.dylib: src/dlls/user32/main.cpp
	g++ src/dlls/user32/main.cpp -arch x86_64 -o build/libuser32.dylib -shared -std=c++17 -O2 -framework Carbon -rpath @executable_path/