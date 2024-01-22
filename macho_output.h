#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <cstdint>
#include <cstring>
#include <cassert>
#include <unordered_map>
#include <set>
#include "macho.h"
#include "exe_parser_64.h"

#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

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

    printf("buffer size = %zu\n", buffer_size);
    char* buffer = new char[buffer_size];
    assert(buffer);

    memset(buffer, 0, buffer_size);

    size_t current_offset = 0;

    mach_header_64 hdr;
    hdr.magic = MH_MAGIC_64;
    hdr.cputype = CPU_TYPE_X86_64;
    hdr.cpusubtype = 3;
    hdr.flags = MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL /*| MH_PIE*/;
    printf("hdr flags match: %d\n", (int)(hdr.flags == 0x00200085));
    hdr.filetype = MH_EXECUTE;
    hdr.ncmds = 9;
    hdr.reserved = 0;
    hdr.sizeofcmds = sizeof(segment_command_64);
    memcpy(buffer + current_offset, &hdr, sizeof(hdr));
    current_offset += sizeof(hdr);

    uint32_t total_cmd_size = 0;

    segment_command_64 pagezero;
    pagezero.cmd = LC_SEGMENT_64;
    pagezero.cmdsize = sizeof(pagezero);
    pagezero.flags = 0;
    pagezero.initprot = 0;
    pagezero.maxprot = 0;
    pagezero.nsects = 0;
    char pagezero_segname[] = "__PAGEZERO\0\0\0\0\0";
    memcpy(pagezero.segname, pagezero_segname, 16);
    pagezero.vmaddr = 0;
    pagezero.vmsize = 0x1'0000'0000ull;
    pagezero.fileoff = 0;
    pagezero.filesize = 0;
    memcpy(buffer + current_offset, &pagezero, sizeof(pagezero));
    current_offset += sizeof(pagezero);
    total_cmd_size += sizeof(pagezero);

    segment_command_64 linkedit;
    linkedit.cmd = LC_SEGMENT_64;
    linkedit.cmdsize = sizeof(linkedit);
    linkedit.flags = 0;
    char linkedit_segname[] = "__LINKEDIT\0\0\0\0\0";
    memcpy(linkedit.segname, linkedit_segname, 16);
    linkedit.initprot = VM_PROT_READ;
    linkedit.maxprot = VM_PROT_READ;
    linkedit.nsects = 0;
    linkedit.vmaddr = 0x1'0000'4000ull;
    linkedit.vmsize = 0x4000;
    linkedit.fileoff = buffer_size;
    linkedit.filesize = 0;
    memcpy(buffer + current_offset, &linkedit, sizeof(linkedit));
    current_offset += sizeof(linkedit);
    total_cmd_size += linkedit.cmdsize;


    dylinker_command dylinker;
    dylinker.cmd = LC_LOAD_DYLINKER;
    const char dyld_str[] = "/usr/lib/dyld";
    dylinker.name.offset = sizeof(dylinker);
    dylinker.cmdsize = ROUND_UP(sizeof(dylinker) + sizeof(dyld_str), 0x10);
    memcpy(buffer + current_offset, &dylinker, sizeof(dylinker));
    current_offset += sizeof(dylinker);
    memcpy(buffer + current_offset, dyld_str, sizeof(dyld_str));
    current_offset += (dylinker.cmdsize - sizeof(dylinker));

    total_cmd_size += dylinker.cmdsize;

    dylib_command dylib;
    dylib.cmd = LC_LOAD_DYLIB;
    dylib.dylib.compatibility_version = 65536;
    dylib.dylib.current_version = 87556096;
    dylib.dylib.timestamp = 2;
    const char dylib_name[] = "/usr/lib/libSystem.B.dylib";
    dylib.dylib.name.offset = sizeof(dylib);
    dylib.cmdsize = ROUND_UP(sizeof(dylib) + sizeof(dylib_name), 0x10);
    std::cout << "dylib.cmdsize: " << dylib.cmdsize << ", " << ROUND_UP(dylib.cmdsize, 0x10) << '\n';
    memcpy(buffer + current_offset, &dylib, sizeof(dylib));
    current_offset += sizeof(dylib);
    memcpy(buffer + current_offset, dylib_name, sizeof(dylib_name));
    current_offset += (dylib.cmdsize - sizeof(dylib));
    total_cmd_size += dylib.cmdsize;

    std::set<std::string> loaded_dylibs;

    for (auto& [dll, _] : parser.import_map)
    {
        if (strcasecmp(dll.c_str(), "kernel32.dll") == 0)
            continue;
        std::string no_ext = dll.substr(0, dll.size() - 4).c_str();
        if (no_ext.find("api-ms-win-crt") != std::string::npos)
        {
            no_ext = "msvcrt";
        }

        std::transform(no_ext.begin(), no_ext.end(), no_ext.begin(),
            [](unsigned char c){ return std::tolower(c); });

        std::string dylib_name = no_ext + ".dylib";

        if (dylib_name.find("lib") != 0)
            dylib_name = std::string("lib") + dylib_name;

        if (loaded_dylibs.find(no_ext) != loaded_dylibs.end())
            continue;
        
        std::ifstream presence_test(std::string("dlls/") + no_ext + std::string("/") + dylib_name);
        if (presence_test)
        {
            presence_test.close();
            dylib_command dyl;
            dyl.cmd = LC_LOAD_DYLIB;
            dyl.dylib.compatibility_version = 65536;
            dyl.dylib.current_version = 87556096;
            dyl.dylib.timestamp = 2;
            std::string dyl_name_str = (std::string("@executable_path/dlls/") + no_ext + std::string("/") + dylib_name).c_str();
            char dyl_name[dyl_name_str.size() + 1];
            memcpy(dyl_name, dyl_name_str.data(), dyl_name_str.size());
            dyl_name[dyl_name_str.size()] = '\0';
            dyl.dylib.name.offset = sizeof(dyl);
            dyl.cmdsize = ROUND_UP(sizeof(dyl) + sizeof(dyl_name), 0x10);
            std::cout << "dyl.cmdsize: " << dyl.cmdsize << ", " << ROUND_UP(dyl.cmdsize, 0x10) << '\n';
            memcpy(buffer + current_offset, &dyl, sizeof(dyl));
            current_offset += sizeof(dyl);
            memcpy(buffer + current_offset, dyl_name, sizeof(dyl_name));
            current_offset += (dyl.cmdsize - sizeof(dyl));
            total_cmd_size += dyl.cmdsize;
            reinterpret_cast<mach_header_64*>(buffer)->ncmds++;
            loaded_dylibs.insert(dylib_name);
        }
        else
            printf("%s does NOT exist\n", dylib_name.c_str());
    }

    dylib_command kernel32;
    kernel32.cmd = LC_LOAD_DYLIB;
    kernel32.dylib.compatibility_version = 65536;
    kernel32.dylib.current_version = 87556096;
    kernel32.dylib.timestamp = 2;
    const char kernel32_name[] = "@executable_path/dlls/kernel32/libkernel32.dylib";
    kernel32.dylib.name.offset = sizeof(kernel32);
    kernel32.cmdsize = ROUND_UP(sizeof(kernel32) + sizeof(kernel32_name), 0x10);
    std::cout << "kernel32.cmdsize: " << kernel32.cmdsize << ", " << ROUND_UP(kernel32.cmdsize, 0x10) << '\n';
    memcpy(buffer + current_offset, &kernel32, sizeof(kernel32));
    current_offset += sizeof(kernel32);
    memcpy(buffer + current_offset, kernel32_name, sizeof(kernel32_name));
    current_offset += (kernel32.cmdsize - sizeof(kernel32));
    total_cmd_size += kernel32.cmdsize;

    symtab_command symtab;
    symtab.cmd = LC_SYMTAB;
    symtab.cmdsize = sizeof(symtab);
    symtab.nsyms = 0;
    symtab.symoff = 0;
    symtab.stroff = 0;
    symtab.strsize = 0;
    memcpy(buffer + current_offset, &symtab, sizeof(symtab));
    current_offset += sizeof(symtab);
    total_cmd_size += symtab.cmdsize;

    dysymtab_command dysymtab;
    memset(&dysymtab, 0, sizeof(dysymtab));
    dysymtab.cmd = LC_DYSYMTAB;
    dysymtab.cmdsize = sizeof(dysymtab);
    memcpy(buffer + current_offset, &dysymtab, sizeof(dysymtab));
    current_offset += sizeof(dysymtab);
    total_cmd_size += dysymtab.cmdsize;

    size_t main_offset = current_offset;

    entry_point_command main;
    main.cmd = LC_MAIN;
    main.cmdsize = sizeof(main);
    main.entryoff = 69420;
    main.stacksize = 0;
    memcpy(buffer + current_offset, &main, sizeof(main));
    current_offset += sizeof(main);

    total_cmd_size += main.cmdsize;

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
    memcpy(buffer + current_offset, &text, sizeof(text));
    current_offset += sizeof(text);
    total_cmd_size += text.cmdsize;
    section_64 base;
    base.addr = text.vmaddr;
    base.align = 1;
    base.flags = 0x0;
    base.nreloc = 0;
    base.reloff = 0;
    base.offset = text.fileoff;
    base.size = text.filesize;
    base.reserved1 = 0;
    base.reserved2 = 0;
    base.reserved3 = 0;
    memcpy(base.sectname, "__base\0\0\0\0\0\0\0\0\0", sizeof(base.sectname));
    memcpy(base.segname, text_segname, sizeof(base.segname));
    memcpy(buffer + current_offset, &base, sizeof(base));
    current_offset += sizeof(base);

    uintptr_t real_entry_point_va = parser.nt_header->OptionalHeader.AddressOfEntryPoint;
    size_t real_entry_fileoff = real_entry_point_va;

    TEB teb;
    teb.Tib.StackBase = reinterpret_cast<PVOID>(parser.nt_header->OptionalHeader.ImageBase);

    uint64_t teb_fileoff = max_vm_addr;
    size_t custom_entry_fileoff = max_vm_addr + sizeof(teb);

    unsigned char entry_code[] =
    {
        0x48, 0xBF, 0xEF, 0xBE, 0xED, 0xFE, 0xCE, 0xFA, 0xAD, 0xDE,     // 00: movabs rdi, 0xdeadfacefeedbeef
        0x48, 0xBE, 0x78, 0x56, 0xEF, 0xBE, 0x34, 0x12, 0xED, 0xFE,     // 0a: movabs rsi, 0xfeed1234beef5678
        0x48, 0xBA, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,     // 14: movabs rdx,0xffffffff
        0xE8, 0x00, 0x00, 0x00, 0x00,                                   // 1e: call memcpy

        0x50,                                                           // 23: push rax
        0x48, 0xB8, 0x20, 0x94, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,     // 24: movabs rax, 0x69420
        0x65, 0x48, 0x89, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,           // 2e: mov qword ptr [gs:0x30], rax
        0x58,                                                           // 37: pop rax
        0xE9, 0x00, 0x00, 0x00, 0x00                                    // 38: jmp real_entry_fileoff
    };

    // todo: make custom entry also write PE sections
    size_t dos_nt_spacing = (parser.dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER));
    size_t dos_and_pe_headers_size = sizeof(IMAGE_DOS_HEADER) + dos_nt_spacing + sizeof(__IMAGE_NT_HEADERS64) + parser.sections.size() * sizeof(__IMAGE_SECTION_HEADER);
    size_t dos_and_pe_headers_fileoff = custom_entry_fileoff + sizeof(entry_code);

    printf("dos_and_pe_headers_size = %zu, dos_and_pe_headers_fileoff = %zu\n", dos_and_pe_headers_size, dos_and_pe_headers_fileoff);

    size_t import_section_fileoff = custom_entry_fileoff + sizeof(entry_code);
    section_64 import;
    import.addr = text.vmaddr + parser.import_directory.VirtualAddress;
    import.align = 0;
    import.flags = 0x0;
    import.nreloc = 0;
    import.reloff = 0;
    import.offset = import_section_fileoff;
    import.size = 0;
    import.reserved1 = 0;
    import.reserved2 = 0;
    import.reserved3 = 0;
    memcpy(import.sectname, "__import\0\0\0\0\0\0\0", sizeof(import.sectname));
    memcpy(import.segname, text_segname, sizeof(import.segname));
    memcpy(buffer + current_offset, &import, sizeof(import));
    current_offset += sizeof(import);

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
    memcpy(buffer + current_offset, &header, sizeof(header));
    current_offset += sizeof(header);

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
    memcpy(buffer + current_offset, &entry, sizeof(entry));
    current_offset += sizeof(entry);

    if (sizeof(entry_code) != 61)
    {
        throw std::runtime_error("entry code has changed, please update code");
    }
    { 
        memcpy(entry_code + 2, &parser.nt_header->OptionalHeader.ImageBase, sizeof(parser.nt_header->OptionalHeader.ImageBase));
        memcpy(entry_code + 0xc, &header.addr, 8);
        memcpy(entry_code + 0x16, &dos_and_pe_headers_size, sizeof(dos_and_pe_headers_size));

        int32_t entry_offset = real_entry_fileoff - (custom_entry_fileoff + 0x38) - 5;
        memcpy(entry_code + 0x39, &entry_offset, sizeof(entry_offset));

        uint64_t teb_vm_addr = parser.nt_header->OptionalHeader.ImageBase + teb_fileoff;
        memcpy(entry_code + 0x26, &teb_vm_addr, sizeof(teb_vm_addr));
    }

    memcpy(buffer + teb_fileoff, &teb, sizeof(teb));
    memcpy(buffer + custom_entry_fileoff, entry_code, sizeof(entry_code));
    memcpy(buffer + dos_and_pe_headers_fileoff, parser.dos_header, sizeof(*parser.dos_header));
    current_offset = dos_and_pe_headers_fileoff + sizeof(*parser.dos_header) + dos_nt_spacing;
    memcpy(buffer + current_offset, parser.nt_header, sizeof(*parser.nt_header));
    current_offset += sizeof(*parser.nt_header);
    for (auto* pe_section : parser.sections)
    {
        memcpy(buffer + current_offset, pe_section, sizeof(*pe_section));
        current_offset += sizeof(*pe_section);
    }

    for (auto* section : parser.sections)
    {
        auto data = parser.section_data.at(section);
        printf("section: %s\n", section->Name);
        printf("\twriting %zu bytes to: %p\n", data.size(), buffer + section->VirtualAddress);
        memcpy(buffer + section->VirtualAddress, data.data(), data.size());
    }

    std::cout << "total_cmd_size: " << total_cmd_size << '\n';
    memcpy(buffer + ((uintptr_t)(&(hdr.sizeofcmds)) - (uintptr_t)(&hdr)), &total_cmd_size, sizeof(total_cmd_size));

    std::cout << "real entry fileoff: " << std::hex << real_entry_fileoff << std::dec << '\n';

    main.entryoff = custom_entry_fileoff;
    memcpy(buffer + main_offset + ((uintptr_t)&(main.entryoff) - (uintptr_t)&main), &main.entryoff, sizeof(main.entryoff));
    
    std::ofstream out_stream("out", std::ios::binary);
    out_stream.write(buffer, buffer_size);

    std::cout << "wrote to output\n";
    delete[] buffer;
}
