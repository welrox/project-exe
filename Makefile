all: project-exe dlls/kernel32/libkernel32.dylib dlls/libstdc++-6/libstdc++-6.dylib dlls/msvcrt/libmsvcrt.dylib dlls/user32/libuser32.dylib

project-exe: main.cpp exe_parser_64.h macho_output.h macho.h pe.h
	g++ -Wall main.cpp -o project-exe -std=c++17

dlls/kernel32/libkernel32.dylib: dlls/kernel32/main.cpp
	g++ dlls/kernel32/main.cpp -arch x86_64 -o dlls/kernel32/libkernel32.dylib -shared -std=c++17 -O2

dlls/libstdc++-6/libstdc++-6.dylib: dlls/libstdc++-6/main.cpp
	g++ dlls/libstdc++-6/main.cpp -arch x86_64 -o dlls/libstdc++-6/libstdc++-6.dylib -shared -std=c++17

dlls/msvcrt/libmsvcrt.dylib: dlls/msvcrt/main.cpp
	g++ dlls/msvcrt/main.cpp -arch x86_64 -o dlls/msvcrt/libmsvcrt.dylib -shared -std=c++17 -O2

dlls/user32/libuser32.dylib: dlls/user32/main.cpp
	g++ dlls/user32/main.cpp -arch x86_64 -o dlls/user32/libuser32.dylib -shared -std=c++17 -O2 -framework Carbon