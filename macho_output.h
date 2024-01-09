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

    max_vm_addr += 0x1000;

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

    dylib_command kernel32;
    kernel32.cmd = LC_LOAD_DYLIB;
    kernel32.dylib.compatibility_version = 65536;
    kernel32.dylib.current_version = 87556096;
    kernel32.dylib.timestamp = 2;
    const char kernel32_name[] = "@executable_path/kernel32/libkernel32.dylib";
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
    text.nsects = 2;
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
        0x50,                                                           // 0: push rax
        0x48, 0xB8, 0x20, 0x94, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,     // 1: movabs rax, 0x69420
        0x65, 0x48, 0x89, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,           // 11: mov qword ptr [gs:0x30], rax
        0x58,                                                           // 20: pop rax
        0xE9, 0x00, 0x00, 0x00, 0x00                                    // 21: jmp real_entry_fileoff
    };

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

    {
        int32_t entry_offset = real_entry_fileoff - (custom_entry_fileoff + 21) - 5;
        memcpy(entry_code + 22, &entry_offset, sizeof(entry_offset));

        uint64_t teb_vm_addr = parser.nt_header->OptionalHeader.ImageBase + teb_fileoff;
        memcpy(entry_code + 3, &teb_vm_addr, sizeof(teb_vm_addr));
    }

    memcpy(buffer + teb_fileoff, &teb, sizeof(teb));
    memcpy(buffer + custom_entry_fileoff, entry_code, sizeof(entry_code));

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