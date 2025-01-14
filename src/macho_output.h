#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <cstdint>
#include <cstring>
#include <cassert>
#include <unordered_map>
#include <unordered_set>
#include "macho.h"
#include "exe_parser_64.h"

#define ROUND_UP(value, multiple) ((((value) + (multiple) - 1) / (multiple)) * (multiple))

inline void output_macho_file(const std::string& out_path, const EXE_Parser64& parser)
{
    std::vector<char> output_buffer;

    mach_header_64 hdr;
    hdr.magic = MH_MAGIC_64;
    hdr.cputype = CPU_TYPE_X86_64;
    hdr.cpusubtype = 3;
    hdr.flags = MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL /*| MH_PIE*/;
    hdr.filetype = MH_OBJECT;
    hdr.ncmds = 4;
    hdr.reserved = 0;
    hdr.sizeofcmds = sizeof(segment_command_64);
    output_buffer.insert(output_buffer.end(), (char*)&hdr, (char*)&hdr + sizeof(hdr));
    uint32_t total_cmd_size = 0;

    size_t text_offset = output_buffer.size();
    segment_command_64 text;
    text.cmd = LC_SEGMENT_64;
    text.cmdsize = sizeof(text);
    text.flags = 0;
    text.initprot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
    text.maxprot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
    text.nsects = parser.sections.size() + 2;
    text.cmdsize += text.nsects * sizeof(section_64);
    memset(text.segname, 0, sizeof(text.segname));
    strcpy(text.segname, "__TEXT");
    text.vmaddr = parser.nt_header->OptionalHeader.ImageBase;
    text.vmsize = 0;
    text.fileoff = 0;
    text.filesize = 0;
    output_buffer.insert(output_buffer.end(), (char*)&text, (char*)&text + sizeof(text));
    total_cmd_size += text.cmdsize;

    size_t max_vm_addr = 0;
    size_t cur_fileoff = output_buffer.size() + text.nsects * sizeof(section_64)
                       + sizeof(symtab_command) + sizeof(dysymtab_command) + sizeof(build_version_command);
    for (auto section : parser.sections)
    {
        auto data = parser.section_data.at(section);
        section_64 sect;
        sect.addr = parser.nt_header->OptionalHeader.ImageBase + section->VirtualAddress;
        sect.align = 12;
        sect.flags = 0x0;
        sect.nreloc = 0;
        sect.reloff = 0;
        sect.offset = cur_fileoff;
        sect.size = data.size();
        sect.reserved1 = 0;
        sect.reserved2 = 0;
        sect.reserved3 = 0;
        memset(sect.sectname, 0, sizeof(sect.sectname));
        std::string sectname = "__";
        for (size_t i = 0; i < sizeof(section->Name) && section->Name[i]; ++i) {
            char c = section->Name[i];
            if (isalnum(c)) sectname.push_back(c);
        }
        memcpy(sect.sectname, sectname.c_str(), std::min(sectname.size(), sizeof(sect.sectname)));
        memcpy(sect.segname, text.segname, sizeof(text.segname));
        output_buffer.insert(output_buffer.end(), (char*)&sect, (char*)&sect + sizeof(sect));
        cur_fileoff += data.size();
        if (sect.addr + sect.size > max_vm_addr) max_vm_addr = sect.addr + sect.size;
    }

    size_t dos_nt_gap = (parser.dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER));
    size_t dos_and_pe_headers_size = sizeof(IMAGE_DOS_HEADER) + dos_nt_gap + sizeof(__IMAGE_NT_HEADERS64)
                                   + parser.sections.size() * sizeof(__IMAGE_SECTION_HEADER);

    // This section marks the start of the DOS and PE headers
    section_64 header;
    header.addr = max_vm_addr;
    header.align = 0;
    header.flags = 0x0;
    header.nreloc = 0;
    header.reloff = 0;
    header.offset = cur_fileoff;
    header.size = dos_and_pe_headers_size;
    header.reserved1 = 0;
    header.reserved2 = 0;
    header.reserved3 = 0;
    memcpy(header.sectname, "___header\0\0\0\0\0\0", sizeof(header.sectname));
    memcpy(header.segname, text.segname, sizeof(header.segname));
    output_buffer.insert(output_buffer.end(), (char*)&header, (char*)&header + sizeof(header));
    cur_fileoff += header.size;
    max_vm_addr += header.size;

    printf("dos_and_pe_headers_size = %llu, dos_and_pe_headers_fileoff = %u\n", header.size, header.offset);

    // Dummy TEB for C startup routine
    uint64_t teb_fileoff = cur_fileoff;
    TEB teb;
    teb.Tib.StackBase = reinterpret_cast<PVOID>(parser.nt_header->OptionalHeader.ImageBase);
    cur_fileoff += sizeof(teb);

    size_t real_entry_address = parser.nt_header->OptionalHeader.ImageBase + parser.nt_header->OptionalHeader.AddressOfEntryPoint;

    // The entry point of the output executable will be set to the code below:
    unsigned char entry_code[] =
    {
        // The first thing to do is to copy the DOS and PE headers,
        // this is needed as runtime startup routines assume that
        // the DOS and PE headers are loaded into memory
        0x48, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // 00: movabs rdi, ImageBase (`dst` argument of memcpy)
        0x48, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // 0a: movabs rsi, dos_and_pe_headers_vmaddr (`src` argument of memcpy)
        0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // 14: movabs rdx, dos_and_pe_headers_size (`size` argument of memcpy)
        0xE8, 0x00, 0x00, 0x00, 0x00,                                   // 1e: call memcpy (this is patched in by kernel32)

        // Windows C startup routine assumes that the TEB address
        // is in the `gs` segment, so we put the address of our
        // dummy TEB there
        0x50,                                                           // 23: push rax
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // 24: movabs rax, teb_vm_addr
        0x65, 0x48, 0x89, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,           // 2e: mov qword ptr [gs:0x30], rax
        0x58,                                                           // 37: pop rax

        // Jump to the actual entry point of the executable
        0xE9, 0x00, 0x00, 0x00, 0x00                                    // 38: jmp real_entry_fileoff
    };

    // This section marks the start of our custom entry point
    section_64 entry;
    entry.addr = max_vm_addr;
    entry.align = 0;
    entry.flags = 0x0;
    entry.nreloc = 0;
    entry.reloff = 0;
    entry.offset = cur_fileoff;
    entry.size = sizeof(entry_code);
    entry.reserved1 = 0;
    entry.reserved2 = 0;
    entry.reserved3 = 0;
    memcpy(entry.sectname, "___entry\0\0\0\0\0\0\0", sizeof(entry.sectname));
    memcpy(entry.segname, text.segname, sizeof(entry.segname));
    output_buffer.insert(output_buffer.end(), (char*)&entry, (char*)&entry + sizeof(entry));
    cur_fileoff += entry.size;
    max_vm_addr += entry.size;

    if (sizeof(entry_code) != 61)
    {
        throw std::runtime_error("entry code has changed, please update code");
    }
    { 
        // Patch memcpy arguments into entry_code
        memcpy(entry_code + 2, &parser.nt_header->OptionalHeader.ImageBase, sizeof(parser.nt_header->OptionalHeader.ImageBase));
        memcpy(entry_code + 0xc, (const void*)(&header.addr), sizeof(void*));
        memcpy(entry_code + 0x16, &dos_and_pe_headers_size, sizeof(dos_and_pe_headers_size));

        // Patch dummy TEB address into entry_code
        uint64_t teb_vm_addr = parser.nt_header->OptionalHeader.ImageBase + teb_fileoff;
        memcpy(entry_code + 0x26, &teb_vm_addr, sizeof(teb_vm_addr));

        // Patch actual entry point into entry_code
        int32_t entry_offset = real_entry_address - (entry.addr + 0x38) - 5;
        memcpy(entry_code + 0x39, &entry_offset, sizeof(entry_offset));
    }


    size_t symtab_offset = output_buffer.size();
    symtab_command symtab;
    symtab.cmd = LC_SYMTAB;
    symtab.cmdsize = sizeof(symtab);
    symtab.nsyms = 1;
    symtab.symoff = 0;
    symtab.stroff = 0;
    symtab.strsize = strlen("_main") + 2;
    output_buffer.insert(output_buffer.end(), (char*)&symtab, (char*)&symtab + sizeof(symtab));
    total_cmd_size += symtab.cmdsize;

    dysymtab_command dysymtab;
    memset(&dysymtab, 0, sizeof(dysymtab));
    dysymtab.cmd = LC_DYSYMTAB;
    dysymtab.cmdsize = sizeof(dysymtab);
    dysymtab.nextdefsym = 1;
    dysymtab.iundefsym = dysymtab.iextdefsym + dysymtab.nextdefsym;
    output_buffer.insert(output_buffer.end(), (char*)&dysymtab, (char*)&dysymtab + sizeof(dysymtab));
    total_cmd_size += dysymtab.cmdsize;

    build_version_command build_version;
    build_version.cmd = LC_BUILD_VERSION;
    build_version.cmdsize = sizeof(build_version);
    build_version.minos = (15 << 16);
    build_version.platform = PLATFORM_MACOS;
    build_version.sdk = 0;
    build_version.ntools = 0;
    output_buffer.insert(output_buffer.end(), (char*)&build_version, (char*)&build_version + sizeof(build_version));
    total_cmd_size += build_version.cmdsize;

    for (auto section : parser.sections)
    {
        auto data = parser.section_data.at(section);
        printf("section: %s\n", section->Name);
        printf("\twriting %zu bytes to: %p\n", data.size(), output_buffer.data() + output_buffer.size());
        output_buffer.insert(output_buffer.end(), data.begin(), data.end());
    }

    output_buffer.insert(output_buffer.end(), (char*)parser.dos_header, (char*)parser.dos_header + sizeof(*parser.dos_header));
    for (size_t i = 0; i < dos_nt_gap; ++i) output_buffer.push_back('\0');
    output_buffer.insert(output_buffer.end(), (char*)parser.nt_header, (char*)parser.nt_header + sizeof(*parser.nt_header));
    for (auto section : parser.sections)
    {
        output_buffer.insert(output_buffer.end(), (char*)section, (char*)section + sizeof(*section));
    }

    output_buffer.insert(output_buffer.end(), (char*)&teb, (char*)&teb + sizeof(teb));
    output_buffer.insert(output_buffer.end(), entry_code, entry_code + sizeof(entry_code));

    ((segment_command_64*)(output_buffer.data() + text_offset))->filesize = output_buffer.size();
    ((symtab_command*)(output_buffer.data() + symtab_offset))->symoff = output_buffer.size();
    nlist_64 main_symbol;
    main_symbol.n_un.n_strx = 1;
    main_symbol.n_type = N_SECT | N_EXT;
    main_symbol.n_sect = parser.sections.size() + 2;
    main_symbol.n_desc = 0;
    main_symbol.n_value = entry.addr;
    printf("entry.addr = %llx\n", entry.addr);
    output_buffer.insert(output_buffer.end(), (char*)&main_symbol, (char*)&main_symbol + sizeof(main_symbol));
    ((symtab_command*)(output_buffer.data() + symtab_offset))->stroff = output_buffer.size();
    const char sym_name[] = "\0_main";
    output_buffer.insert(output_buffer.end(), sym_name, sym_name + sizeof(sym_name));

    ((mach_header_64*)output_buffer.data())->sizeofcmds = total_cmd_size;
    ((segment_command_64*)(output_buffer.data() + text_offset))->vmsize = max_vm_addr - text.vmaddr;

     std::unordered_set<std::string> loaded_dylibs;

    for (auto& [dll, _] : parser.import_map)
    {
        printf("DLL: %s\n", dll.c_str());
        if (strcasecmp(dll.c_str(), "kernel32.dll") == 0)
            continue;
        std::string name_without_extension = dll.substr(0, dll.size() - 4).c_str();
        if (name_without_extension.find("api-ms-win-crt") != std::string::npos)
        {
            name_without_extension = "msvcrt";
        }

        std::transform(name_without_extension.begin(), name_without_extension.end(), name_without_extension.begin(),
            [](unsigned char c){ return std::tolower(c); });

        std::string dylib_name = name_without_extension + ".dylib";

        if (dylib_name.find("lib") != 0)
        {
            dylib_name = "lib" + dylib_name;
        }

        if (loaded_dylibs.find(name_without_extension) != loaded_dylibs.end())
            continue;
        
        std::ifstream presence_test(dylib_name);
        if (presence_test)
        {
            presence_test.close();
            loaded_dylibs.insert(name_without_extension);
        }
        else
        {
            printf("warning: could not find '%s'; this will likely cause a crash.\n", dylib_name.c_str());
            printf(" Continue anyway? (y/[n]) ");
            char ans = getchar();
            if (tolower(ans) != 'y')
            {
                printf("Exiting.\n");
                std::exit(1);
            }
        }
    }

    std::ofstream out_stream(out_path + ".o", std::ios::binary);
    out_stream.write(output_buffer.data(), output_buffer.size());
    out_stream.close();

    std::stringstream link_command_stream;
    link_command_stream << "ld " << out_path << ".o -o " << out_path << " -no_pie "
                             << "-L$(xcrun --show-sdk-path)/usr/lib/ -lSystem "
                             << "-L./ -rpath @executable_path/ "
                             << "-lkernel32 "
                             << "-segaddr __TEXT " << std::hex << parser.nt_header->OptionalHeader.ImageBase << std::dec << " "
                             << "-segprot __TEXT rwx rwx ";
    for (const std::string& dylib : loaded_dylibs)
    {
        std::string dylib_link_name = dylib;
        if (dylib.find("lib") == 0)
        {
            dylib_link_name = dylib.substr(3);
        }
        link_command_stream <<  "-l" << dylib_link_name << " ";
    }

    std::cout << link_command_stream.str() << '\n';
    system(link_command_stream.str().c_str());

    std::string post_link_command = "install_name_tool -change build/libkernel32.dylib @executable_path/libkernel32.dylib " + out_path;
    std::cout << post_link_command << '\n';
    system(post_link_command.c_str());

    for (const std::string& dylib : loaded_dylibs)
    {
        std::string dylib_name = dylib + ".dylib";
        if (dylib.find("lib") != 0)
        {
            dylib_name = "lib" + dylib_name;
        }
        post_link_command = "install_name_tool -change build/" + dylib_name + " @executable_path/" + dylib_name + " " + out_path;
        std::cout << post_link_command << '\n';
        system(post_link_command.c_str());
    }

    std::cout << "wrote to " << out_path << '\n';
}
