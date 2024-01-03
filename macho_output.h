#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <cstdint>
#include <cstring>
#include <cassert>
#include <unordered_map>
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

    printf("max_vm_addr = %zu\n", max_vm_addr);

    size_t buffer_size = ROUND_UP(max_vm_addr + 0x1000, 0x4000);

    printf("buffer size = %zu\n", buffer_size);
    char* buffer = new char[buffer_size];
    assert(buffer);

    memset(buffer, 0, buffer_size);

    size_t current_offset = 0;

    mach_header_64 hdr;
    hdr.magic = MH_MAGIC_64;
    hdr.cputype = CPU_TYPE_X86_64;
    hdr.cpusubtype = 3;
    hdr.flags = 0x00200085;
    hdr.filetype = MH_EXECUTE;
    hdr.ncmds = 8;
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
    text.nsects = 0;
    text.cmdsize += text.nsects * sizeof(section_64);
    char text_segname[] = "__TEXT\0\0\0\0\0\0\0\0\0";
    memcpy(text.segname, text_segname, 16);
    text.vmaddr = parser.nt_header->OptionalHeader.ImageBase;
    text.vmsize = max_vm_addr;
    text.fileoff = 0x0;
    text.filesize = max_vm_addr;
    memcpy(buffer + current_offset, &text, sizeof(text));
    current_offset += sizeof(text);
    total_cmd_size += text.cmdsize;

    uintptr_t entry_point_va = parser.nt_header->OptionalHeader.AddressOfEntryPoint;
    size_t entry_fileoff = entry_point_va;

    for (auto* section : parser.sections)
    {
        auto data = parser.section_data.at(section);
        printf("section: %s\n", section->Name);
        printf("\twriting %zu bytes to: %p\n", data.size(), buffer + section->VirtualAddress);
        memcpy(buffer + section->VirtualAddress, data.data(), data.size());
    }

    std::cout << "total_cmd_size: " << total_cmd_size << '\n';
    memcpy(buffer + ((uintptr_t)(&(hdr.sizeofcmds)) - (uintptr_t)(&hdr)), &total_cmd_size, sizeof(total_cmd_size));

    std::cout << "entry fileoff: " << std::hex << entry_fileoff << std::dec << '\n';

    main.entryoff = entry_fileoff;
    memcpy(buffer + main_offset + ((uintptr_t)&(main.entryoff) - (uintptr_t)&main), &main.entryoff, sizeof(main.entryoff));
    
    std::ofstream out_stream("out", std::ios::binary);
    out_stream.write(buffer, buffer_size);

    std::cout << "wrote to output\n";
    delete[] buffer;
}