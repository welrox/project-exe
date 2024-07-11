#include <iostream>
#include <cstring>
#include <fstream>
#include <cassert>
#include <map>

#include "pe.h"
#include "exe_parser_64.h"
#include "macho.h"
#include "macho_output.h"


#define MAP(map, sym) map[sym] = #sym

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " [path/to/exe]\n";
        return 1;
    }

    EXE_Parser64 parser;
    std::cout << "Parsing exe...\n";
    bool result = parser.parse(argv[1]);
    if (!result)
    {
        std::cerr << "Failed to parse file\n";
        return 1;
    }

    std::cout << "\ncreating mach-o binary\n\n";
    output_macho_file("./out", parser);
}