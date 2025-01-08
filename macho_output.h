#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <cstdint>
#include <cstring>
#include <cassert>
#include <unordered_map>
#include <set>
#include "macho.h"
#include "exe_parser_64.h"

#define ROUND_UP(value, multiple) ((((value) + (multiple) - 1) / (multiple)) * (multiple))

inline void output_macho_file(const std::string& out_path, const EXE_Parser64& parser)
{
    size_t max_vm_addr = 0;
    for (auto section : parser.sections)
    {
        if (max_vm_addr < section->VirtualAddress)
            max_vm_addr = section->VirtualAddress;
    }

    max_vm_addr += 0x1000;

    printf("max_vm_addr = %zu\n", max_vm_addr);

    size_t buffer_size = ROUND_UP(max_vm_addr + 0x2000, 0x4000);

    printf("output file buffer size = %zu\n", buffer_size);
    char* output_buffer = new char[buffer_size];
    assert(output_buffer);

    memset(output_buffer, 0, buffer_size);

    size_t current_offset = 0;

    mach_header_64 hdr;
    hdr.magic = MH_MAGIC_64;
    hdr.cputype = CPU_TYPE_X86_64;
    hdr.cpusubtype = 3;
    hdr.flags = MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL /*| MH_PIE*/;
    hdr.filetype = MH_OBJECT;
    hdr.ncmds = 4;
    hdr.reserved = 0;
    hdr.sizeofcmds = sizeof(segment_command_64);
    memcpy(output_buffer + current_offset, &hdr, sizeof(hdr));
    current_offset += sizeof(hdr);

    uint32_t total_cmd_size = 0;
    size_t text_offset = current_offset;
    segment_command_64 text;
    text.cmd = LC_SEGMENT_64;
    text.cmdsize = sizeof(text);
    text.flags = 0;
    text.initprot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
    text.maxprot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
    text.nsects = 4;
    text.cmdsize += text.nsects * sizeof(section_64);
    char text_segname[] = "__TEXT\0\0\0\0\0\0\0\0\0";
    memcpy(text.segname, text_segname, 16);
    text.vmaddr = parser.nt_header->OptionalHeader.ImageBase;
    text.vmsize = buffer_size;
    text.fileoff = 0x0;
    text.filesize = buffer_size;
    memcpy(output_buffer + current_offset, &text, sizeof(text));
    current_offset += sizeof(text);
    total_cmd_size += text.cmdsize;

    // This section is here so that our dll implementations
    // can easily retrieve the base address of the __TEXT segment
    // TODO: `ld` messes with section virtual addresses
    section_64 base;
    base.addr = text.vmaddr;
    base.align = 1;
    base.flags = 0x0;
    base.nreloc = 0;
    base.reloff = 0;
    base.offset = text.fileoff;
    base.size = 1;
    base.reserved1 = 0;
    base.reserved2 = 0;
    base.reserved3 = 0;
    memcpy(base.sectname, "__base\0\0\0\0\0\0\0\0\0", sizeof(base.sectname));
    memcpy(base.segname, text_segname, sizeof(base.segname));
    memcpy(output_buffer + current_offset, &base, sizeof(base));
    current_offset += sizeof(base);

    uintptr_t real_entry_point_va = parser.nt_header->OptionalHeader.AddressOfEntryPoint;
    size_t real_entry_fileoff = real_entry_point_va;

    // Dummy TEB for C startup routine
    TEB teb;
    teb.Tib.StackBase = reinterpret_cast<PVOID>(parser.nt_header->OptionalHeader.ImageBase);

    uint64_t teb_fileoff = max_vm_addr;
    size_t custom_entry_fileoff = max_vm_addr + sizeof(teb);

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

    size_t dos_nt_spacing = (parser.dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER));
    size_t dos_and_pe_headers_size = sizeof(IMAGE_DOS_HEADER) + dos_nt_spacing + sizeof(__IMAGE_NT_HEADERS64) + parser.sections.size() * sizeof(__IMAGE_SECTION_HEADER);
    size_t dos_and_pe_headers_fileoff = custom_entry_fileoff + sizeof(entry_code);
    printf("dos_and_pe_headers_size = %zu, dos_and_pe_headers_fileoff = %zu\n", dos_and_pe_headers_size, dos_and_pe_headers_fileoff);

    if (sizeof(entry_code) != 61)
    {
        throw std::runtime_error("entry code has changed, please update code");
    }
    { 
        // Patch memcpy arguments into entry_code
        memcpy(entry_code + 2, &parser.nt_header->OptionalHeader.ImageBase, sizeof(parser.nt_header->OptionalHeader.ImageBase));
        uint64_t header_addr = text.vmaddr + dos_and_pe_headers_fileoff;
        memcpy(entry_code + 0xc, &header_addr, 8);
        memcpy(entry_code + 0x16, &dos_and_pe_headers_size, sizeof(dos_and_pe_headers_size));

        // Patch dummy TEB address into entry_code
        uint64_t teb_vm_addr = parser.nt_header->OptionalHeader.ImageBase + teb_fileoff;
        memcpy(entry_code + 0x26, &teb_vm_addr, sizeof(teb_vm_addr));

        // Patch actual entry point into entry_code
        int32_t entry_offset = real_entry_fileoff - (custom_entry_fileoff + 0x38) - 5;
        memcpy(entry_code + 0x39, &entry_offset, sizeof(entry_offset));
    }

    size_t import_section_fileoff = custom_entry_fileoff + sizeof(entry_code);

    // This section marks the start of the PE import table
    section_64 import;
    import.addr = text.vmaddr + parser.import_directory.VirtualAddress;
    import.align = 0;
    import.flags = 0x0;
    import.nreloc = 0;
    import.reloff = 0;
    import.offset = import_section_fileoff;
    import.size = 1;
    import.reserved1 = 0;
    import.reserved2 = 0;
    import.reserved3 = 0;
    memcpy(import.sectname, "__import\0\0\0\0\0\0\0", sizeof(import.sectname));
    memcpy(import.segname, text_segname, sizeof(import.segname));
    memcpy(output_buffer + current_offset, &import, sizeof(import));
    current_offset += sizeof(import);

    // This section marks the start of the DOS and PE headers
    section_64 header;
    header.addr = text.vmaddr + dos_and_pe_headers_fileoff;
    header.align = 0;
    header.flags = 0x0;
    header.nreloc = 0;
    header.reloff = 0;
    header.offset = dos_and_pe_headers_fileoff;
    header.size = dos_and_pe_headers_size;
    header.reserved1 = 0;
    header.reserved2 = 0;
    header.reserved3 = 0;
    memcpy(header.sectname, "__header\0\0\0\0\0\0\0", sizeof(header.sectname));
    memcpy(header.segname, text_segname, sizeof(header.segname));
    memcpy(output_buffer + current_offset, &header, sizeof(header));
    current_offset += sizeof(header);

    // This section marks the start of our custom entry point
    section_64 entry;
    entry.addr = text.vmaddr + custom_entry_fileoff;
    entry.align = 0;
    entry.flags = 0x0;
    entry.nreloc = 0;
    entry.reloff = 0;
    entry.offset = custom_entry_fileoff;
    entry.size = sizeof(entry_code);
    entry.reserved1 = 0;
    entry.reserved2 = 0;
    entry.reserved3 = 0;
    memcpy(entry.sectname, "__entry\0\0\0\0\0\0\0\0", sizeof(entry.sectname));
    memcpy(entry.segname, text_segname, sizeof(entry.segname));
    memcpy(output_buffer + current_offset, &entry, sizeof(entry));
    current_offset += sizeof(entry);

    size_t symtab_offset = current_offset;
    symtab_command symtab;
    symtab.cmd = LC_SYMTAB;
    symtab.cmdsize = sizeof(symtab);
    symtab.nsyms = 1;
    symtab.symoff = 0;
    symtab.stroff = 0;
    symtab.strsize = strlen("_main") + 2;
    memcpy(output_buffer + current_offset, &symtab, sizeof(symtab));
    current_offset += sizeof(symtab);
    total_cmd_size += symtab.cmdsize;

    dysymtab_command dysymtab;
    memset(&dysymtab, 0, sizeof(dysymtab));
    dysymtab.cmd = LC_DYSYMTAB;
    dysymtab.cmdsize = sizeof(dysymtab);
    dysymtab.nextdefsym = 1;
    dysymtab.iundefsym = dysymtab.iextdefsym + dysymtab.nextdefsym;
    memcpy(output_buffer + current_offset, &dysymtab, sizeof(dysymtab));
    current_offset += sizeof(dysymtab);
    total_cmd_size += dysymtab.cmdsize;

    build_version_command build_version;
    build_version.cmd = LC_BUILD_VERSION;
    build_version.cmdsize = sizeof(build_version);
    build_version.minos = (15 << 16);
    build_version.platform = PLATFORM_MACOS;
    build_version.sdk = 0;
    build_version.ntools = 0;
    memcpy(output_buffer + current_offset, &build_version, sizeof(build_version));
    current_offset += sizeof(build_version);
    total_cmd_size += build_version.cmdsize;

    memcpy(output_buffer + teb_fileoff, &teb, sizeof(teb));
    memcpy(output_buffer + custom_entry_fileoff, entry_code, sizeof(entry_code));
    memcpy(output_buffer + dos_and_pe_headers_fileoff, parser.dos_header, sizeof(*parser.dos_header));
    current_offset = dos_and_pe_headers_fileoff + sizeof(*parser.dos_header) + dos_nt_spacing;
    memcpy(output_buffer + current_offset, parser.nt_header, sizeof(*parser.nt_header));
    current_offset += sizeof(*parser.nt_header);
    for (auto* pe_section : parser.sections)
    {
        memcpy(output_buffer + current_offset, pe_section, sizeof(*pe_section));
        current_offset += sizeof(*pe_section);
    }

    for (auto* section : parser.sections)
    {
        auto data = parser.section_data.at(section);
        printf("section: %s\n", section->Name);
        printf("\twriting %zu bytes to: %p\n", data.size(), output_buffer + section->VirtualAddress);
        memcpy(output_buffer + section->VirtualAddress, data.data(), data.size());
        current_offset = std::max(current_offset, section->VirtualAddress + data.size());
    }
    current_offset = ROUND_UP(current_offset, 0x10);
    ((segment_command_64*)(output_buffer + text_offset))->filesize = current_offset;
    ((symtab_command*)(output_buffer + symtab_offset))->symoff = current_offset;
    nlist_64 main_symbol;
    main_symbol.n_un.n_strx = 1;
    main_symbol.n_type = N_SECT | N_EXT;
    main_symbol.n_sect = 4;
    main_symbol.n_desc = 0;
    main_symbol.n_value = entry.addr;
    memcpy(output_buffer + current_offset, &main_symbol, sizeof(main_symbol));
    current_offset += sizeof(main_symbol);
    ((symtab_command*)(output_buffer + symtab_offset))->stroff = current_offset;
    memcpy(output_buffer + current_offset, "\0_main", sizeof("\0_main"));

    std::cout << "total_cmd_size: " << total_cmd_size << '\n';
    memcpy(output_buffer + ((uintptr_t)(&(hdr.sizeofcmds)) - (uintptr_t)(&hdr)), &total_cmd_size, sizeof(total_cmd_size));

    std::cout << "real entry fileoff: " << std::hex << real_entry_fileoff << std::dec << '\n';
    
    std::ofstream out_stream(out_path, std::ios::binary);
    out_stream.write(output_buffer, buffer_size);

    std::stringstream link_command_stream;
    link_command_stream << "ld " << out_path << " -o " << out_path << " -no_pie "
                             << "-L$(xcrun --show-sdk-path)/usr/lib/ -lSystem "
                             << "-Ldlls/kernel32/ -lkernel32 "
                             << "-segaddr __TEXT " << std::hex << parser.nt_header->OptionalHeader.ImageBase << std::dec << " "
                             << "-segprot __TEXT rwx rwx";

     std::set<std::string> loaded_dylibs;

    for (auto& [dll, _] : parser.import_map)
    {
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
            dylib_name = std::string("lib") + dylib_name;

        if (loaded_dylibs.find(name_without_extension) != loaded_dylibs.end())
            continue;
        
        std::ifstream presence_test(std::string("dlls/") + name_without_extension + std::string("/") + dylib_name);
        if (presence_test)
        {
            presence_test.close();
            // TODO: pass shared libraries to `ld`

            // dylib_command dyl;
            // dyl.cmd = LC_LOAD_DYLIB;
            // dyl.dylib.compatibility_version = 65536;
            // dyl.dylib.current_version = 87556096;
            // dyl.dylib.timestamp = 2;

            // std::string dyl_name_str = std::string("@executable_path/dlls/") + name_without_extension + std::string("/") + dylib_name;
            // char dyl_name[dyl_name_str.size() + 1];
            // memcpy(dyl_name, dyl_name_str.data(), dyl_name_str.size());
            // dyl_name[dyl_name_str.size()] = '\0';

            // dyl.dylib.name.offset = sizeof(dyl);
            // dyl.cmdsize = ROUND_UP(sizeof(dyl) + sizeof(dyl_name), 0x10);
            // std::cout << "dyl.cmdsize: " << dyl.cmdsize << ", " << ROUND_UP(dyl.cmdsize, 0x10) << '\n';

            // memcpy(output_buffer + current_offset, &dyl, sizeof(dyl));
            // current_offset += sizeof(dyl);
            // memcpy(output_buffer + current_offset, dyl_name, sizeof(dyl_name));
            // current_offset += (dyl.cmdsize - sizeof(dyl));
            // total_cmd_size += dyl.cmdsize;

            // reinterpret_cast<mach_header_64*>(output_buffer)->ncmds++;
            // loaded_dylibs.insert(dylib_name);
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


    system(link_command_stream.str().c_str());

    std::cout << "wrote to " << out_path << '\n';
    delete[] output_buffer;
}
