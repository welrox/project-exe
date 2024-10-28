#include <iostream>
#include <cstring>
#include <fstream>
#include <cassert>
#include <map>
#include <sys/stat.h>

#include "pe.h"
#include "exe_parser_64.h"
#include "macho.h"
#include "macho_output.h"

bool is_option_set(int argc, char* argv[], const std::string& option)
{
    for (size_t i = 0; i < argc; ++i)
    {
        char* arg = argv[i];
        if (strcmp(arg, option.c_str()) == 0)
        {
            return true;
        }
    }
    return false;
}

char* get_option_value(int argc, char* argv[], const std::string& option)
{
    for (size_t i = 0; i < argc; ++i)
    {
        char* arg = argv[i];
        if (strcmp(arg, option.c_str()) == 0)
        {
            if (i + 1 >= argc)
            {
                std::cerr << "Expected argument after " << option << '\n';
                std::exit(1);
            }

            return argv[i + 1];
        }
    }
    return nullptr;
}

void show_usage(char* argv[])
{
    std::cerr << "USAGE: " << argv[0] << " [path/to/exe]\n";
    std::cerr << "OPTIONS:\n";

    std::cerr << "  -o <file>\t\tWrite output to <file>\n";
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        show_usage(argv);   
        return 1;
    }

    if (is_option_set(argc, argv, "-h") || is_option_set(argc, argv, "--help"))
    {
        show_usage(argv);
        return 1;
    }

    std::string output_file_name = "./a.out";

    if (char* output_file_name_val = get_option_value(argc, argv, "-o"))
    {
        output_file_name = output_file_name_val;
    }

    EXE_Parser64 parser;

    bool result = parser.parse(argv[1]);
    if (!result)
    {
        std::cerr << "error: failed to parse file\n";
        return 1;
    }

    std::cout << "\ncreating mach-o binary\n\n";
    output_macho_file(output_file_name, parser);

    // Make file executable
    chmod(output_file_name.c_str(), S_IRUSR|S_IWUSR|S_IXUSR | S_IRGRP|S_IXGRP | S_IROTH|S_IXOTH);
}