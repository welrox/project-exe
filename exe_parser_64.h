#pragma once
#include <string>
#include <fstream>
#include <iostream>
#include <map>
#include <vector>

#include "pe.h"

class EXE_Parser64
{
    public:
    char* file_buffer = nullptr;
    IMAGE_DOS_HEADER* dos_header;
    __IMAGE_NT_HEADERS64* nt_header;
    __IMAGE_DATA_DIRECTORY import_directory;
    std::vector<__IMAGE_SECTION_HEADER*> sections;
    std::map<__IMAGE_SECTION_HEADER*, std::vector<char>> section_data;
    __IMAGE_SECTION_HEADER* import_section;
    __IMAGE_SECTION_HEADER* text_section;
    std::map<std::string, std::vector<std::string>> import_map;
    size_t text_start_index = 0, text_size = 0;
    size_t entry_point_text_offset = 0;

    public:
    EXE_Parser64() = default;

    bool parse(const std::string& file_path)
    {
        std::ifstream file_stream(file_path, std::ios::binary);
        if (!file_stream)
        {
            std::cerr << "Could not find file: " << file_path << '\n';
            return false;
        }

        size_t file_size;
        {
            std::ifstream temp(file_path, std::ios::ate | std::ios::binary);
            file_size = temp.tellg();
        }

        file_buffer = new char[file_size];
        if (!file_buffer)
        {
            std::cerr << "Failed to allocate file buffer (size = " << file_size << ")\n";
            return false;
        }

        uintptr_t file_buffer_ptr = reinterpret_cast<uintptr_t>(file_buffer);

        file_stream.read(file_buffer, file_size);
        if (file_stream.fail())
        {
            std::cerr << "Failed to read entire file\n";
            delete[] file_buffer;
            return false;
        }

        dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(file_buffer);
        std::cout << "**** DOS HEADER ****\n\n";

        std::cout << "e_magic: 0x" << std::hex << dos_header->e_magic << std::dec << '\n';
        std::cout << "e_lfanew: " << dos_header->e_lfanew << '\n';

        std::cout << "\n";

        nt_header = reinterpret_cast<__IMAGE_NT_HEADERS64*>(reinterpret_cast<uintptr_t>(file_buffer) + dos_header->e_lfanew);
        std::cout << "**** NT HEADER ****\n\n";

        std::cout << "Signature: 0x" << std::hex << nt_header->Signature << std::dec << "\n\n";
        std::cout << "FileHeader.Machine: " << nt_header->FileHeader.Machine << '\n';
        if (nt_header->FileHeader.Machine != 0x8664)
        {
            std::cerr << "Unsupported file format: executable is not 64 bits\n";
            delete[] file_buffer;
            return false;
        }
        std::cout << "FileHeader.NumberOfSections: " << nt_header->FileHeader.NumberOfSections << '\n';
        std::cout << "FileHeader.TimeDateStamp: " << nt_header->FileHeader.TimeDateStamp << '\n';
        std::cout << "FileHeader.PointerToSymbolTable: " << nt_header->FileHeader.PointerToSymbolTable << '\n';
        std::cout << "FileHeader.NumberOfSymbols: " << nt_header->FileHeader.NumberOfSymbols << '\n';
        std::cout << "FileHeader.SizeOfOptionalHeader: " << nt_header->FileHeader.SizeOfOptionalHeader << '\n';
        std::cout << "FileHeader.Characteristics: " << nt_header->FileHeader.Characteristics << '\n';

        std::cout << '\n';

        std::cout << "OptionalHeader.Magic: 0x" << std::hex << nt_header->OptionalHeader.Magic << std::dec << '\n';
        std::cout << "OptionalHeader.SizeOfCode: " << nt_header->OptionalHeader.SizeOfCode << '\n';
        std::cout << "OptionalHeader.SizeOfInitializedData: " << nt_header->OptionalHeader.SizeOfInitializedData << '\n';
        std::cout << "OptionalHeader.SizeOfUninitializedData: " << nt_header->OptionalHeader.SizeOfUninitializedData << '\n';
        std::cout << "OptionalHeader.AddressOfEntryPoint: 0x" << std::hex << nt_header->OptionalHeader.AddressOfEntryPoint << '\n';
        std::cout << "OptionalHeader.BaseOfCode: 0x" << nt_header->OptionalHeader.BaseOfCode << '\n';
        std::cout << "OptionalHeader.ImageBase: 0x" << nt_header->OptionalHeader.ImageBase << '\n';
        std::cout << "OptionalHeader.SectionAlignment: 0x" << nt_header->OptionalHeader.SectionAlignment << '\n';
        std::cout << "OptionalHeader.FileAlignment: 0x" << nt_header->OptionalHeader.FileAlignment << std::dec << '\n';
        std::cout << "OptionalHeader.MajorSubsystemVersion: " << nt_header->OptionalHeader.MajorSubsystemVersion << '\n';
        std::cout << "OptionalHeader.MinorSubsystemVersion: " << nt_header->OptionalHeader.MinorSubsystemVersion << '\n';
        std::cout << "OptionalHeader.SizeOfImage: " << nt_header->OptionalHeader.SizeOfImage << '\n';
        std::cout << "OptionalHeader.SizeOfHeaders: " << nt_header->OptionalHeader.SizeOfHeaders << '\n';
        std::cout << "OptionalHeader.CheckSum: " << nt_header->OptionalHeader.CheckSum << '\n';
        std::cout << "OptionalHeader.Subsystem: " << nt_header->OptionalHeader.Subsystem << '\n';
        std::cout << "OptionalHeader.DllCharacteristics: " << nt_header->OptionalHeader.DllCharacteristics << '\n';
        std::cout << "OptionalHeader.SizeOfStackReserve: " << nt_header->OptionalHeader.SizeOfStackReserve << '\n';
        std::cout << "OptionalHeader.SizeOfStackCommit: " << nt_header->OptionalHeader.SizeOfStackCommit << '\n';
        std::cout << "OptionalHeader.SizeOfHeapReserve: " << nt_header->OptionalHeader.SizeOfHeapReserve << '\n';
        std::cout << "OptionalHeader.SizeOfHeapCommit: " << nt_header->OptionalHeader.SizeOfHeapCommit << '\n';
        std::cout << "OptionalHeader.LoaderFlags: " << nt_header->OptionalHeader.LoaderFlags << '\n';
        std::cout << "OptionalHeader.NumberOfRvaAndSizes: " << nt_header->OptionalHeader.NumberOfRvaAndSizes << '\n';
        std::cout << '\n';

        uintptr_t entry_point_va = nt_header->OptionalHeader.AddressOfEntryPoint;

        std::cout << "**** DATA DIRECTORIES ****\n\n";
        import_directory = nt_header->OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_IMPORT];

        uintptr_t import_va = import_directory.VirtualAddress;
        std::cout << "Data Directory Import: address = 0x" << std::hex << import_va << ", size = 0x" << import_directory.Size << std::dec << '\n';
        std::cout << '\n';

        std::cout << "**** SECTION HEADERS ****\n\n";

        import_section = nullptr;

        for (int i = 0; i < nt_header->FileHeader.NumberOfSections; ++i)
        {
            __IMAGE_SECTION_HEADER* section_header = reinterpret_cast<__IMAGE_SECTION_HEADER*>(reinterpret_cast<uintptr_t>(nt_header) + sizeof(*nt_header) + i * sizeof(__IMAGE_SECTION_HEADER));

            std::cout << "\tSection " << i << '\n';

            std::cout << "\t\tName: " << section_header->Name << '\n';
            std::cout << "\t\tVirtual Size: 0x" << std::hex << section_header->Misc.VirtualSize << '\n';
            std::cout << "\t\tVirtualAddress: 0x" << section_header->VirtualAddress << '\n';
            std::cout << "\t\tSizeOfRawData: 0x" << section_header->SizeOfRawData << '\n';
            std::cout << "\t\tPointerToRawData: 0x" << section_header->PointerToRawData << '\n';
            std::cout << "\t\tCharacteristics: 0x" << section_header->Characteristics << std::dec << '\n';
            std::cout << '\n';

            if (strstr(reinterpret_cast<char*>(section_header->Name), ".text"))
            {
                text_start_index = section_header->PointerToRawData;
                text_size = section_header->Misc.VirtualSize;
                entry_point_text_offset = entry_point_va - section_header->VirtualAddress;
                text_section = section_header;
            }

            if (section_header->VirtualAddress <= import_va 
                        && import_va <= section_header->VirtualAddress + section_header->Misc.VirtualSize)
            {
                import_section = section_header;
            }

            {
                std::vector<char> data(file_buffer + section_header->PointerToRawData,
                                       file_buffer + section_header->PointerToRawData + std::min(section_header->Misc.VirtualSize, section_header->SizeOfRawData));
                section_data[section_header] = data;
                sections.push_back(section_header);
                printf("%s:\n", section_header->Name);
                for (int i = 0; i < 0x10 && i < data.size(); ++i)
                    printf("%x ", (int)data[i]);
                printf("\n");
            }
        }

        if (import_section)
        {
            std::cout << "Found import section: " << import_section->Name << "\n\n";
        }
        else
        {
            std::cerr << "Could not find import section\n";
            delete[] file_buffer;
            return false;
        }

        auto import_va_to_offset = [this](uintptr_t va){
            return import_section->PointerToRawData + (va - import_section->VirtualAddress);
        };

        std::cout << "**** IMPORTS ****\n\n";

        for (IMAGE_IMPORT_DESCRIPTOR* import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(file_buffer_ptr + import_va_to_offset(import_va));
        import_descriptor->OriginalFirstThunk != 0; import_descriptor++)
        {
            std::string dll_name = reinterpret_cast<char*>(file_buffer_ptr + import_va_to_offset(import_descriptor->Name));
            std::cout << "Import DLL: " << dll_name << '\n';
            import_map[dll_name] = std::vector<std::string>();

            for (uintptr_t* thunk = reinterpret_cast<uintptr_t*>(file_buffer_ptr + import_va_to_offset(import_descriptor->OriginalFirstThunk));
            *thunk != 0; thunk++)
            {
                uintptr_t thunk_val = *thunk;
                if (thunk_val & (1ull << 63))
                {
                    std::cerr << "Warning: Ordinal detected! ignoring...\n";
                }
                else
                {
                    IMAGE_IMPORT_BY_NAME* hint_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(file_buffer_ptr + import_va_to_offset(thunk_val));
                    std::string import_fn_name = reinterpret_cast<char*>(hint_name->Name);
                    std::cout << "\t" << import_fn_name << '\n';
                    import_map[dll_name].push_back(import_fn_name);
                }
            }
        }
        return true;
    }
};