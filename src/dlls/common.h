#pragma once
#include <iostream>
#include <map>
#include <mach-o/getsect.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include "../pe.h"

// This function will be called once a dll is loaded,
// it parses the PE headers looking for imports from
// a particular dll, and substitutes them with its own
// functions according to `import_name_to_fn`
inline void patch_dll_imports(const char* dll_name, const std::map<std::string, uintptr_t> import_name_to_fn, section_64* header_cmd_pointer = nullptr, section_64* entry_cmd_pointer = nullptr) {
    const struct section_64* header_cmd = getsectbyname("__TEXT", "___header");
    if (!header_cmd)
    {
        printf("%s error: could not find section ___header, exiting\n", dll_name);
        std::exit(1);
    }
    if (header_cmd_pointer)
    {
        memcpy(header_cmd_pointer, header_cmd, sizeof(*header_cmd));
    }

    const struct section_64* entry_cmd = getsectbyname("__TEXT", "___entry");
    if (!entry_cmd)
    {
        printf("%s error: could not find section ___entry, exiting\n", dll_name);
        std::exit(1);
    }
    if (entry_cmd_pointer)
    {
        memcpy(entry_cmd_pointer, entry_cmd, sizeof(*entry_cmd));
    }

    if (entry_cmd->size != 61)
    {
        throw std::runtime_error("custom entry code size has changed -- update dlls/common.h to work with the new code");
    }

    constexpr int exe_image_index = 0;
    uintptr_t exe_base = reinterpret_cast<uintptr_t>(_dyld_get_image_header(exe_image_index));
    uintptr_t exe_slide = _dyld_get_image_vmaddr_slide(exe_image_index);
    printf ("image %d: %p\t%s\t(slide = 0x%lx)\n", exe_image_index,
    reinterpret_cast<void*>(exe_base),
    _dyld_get_image_name(exe_image_index),
    exe_slide);

    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)header_cmd->addr;
    __IMAGE_NT_HEADERS64* nt_header = (__IMAGE_NT_HEADERS64*)(header_cmd->addr + dos_header->e_lfanew);
    uintptr_t import_addr = exe_base + nt_header->OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    printf("%s: parsing imports\n", dll_name);
    printf(" import_addr %lx\n", import_addr);

    for (IMAGE_IMPORT_DESCRIPTOR* import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(import_addr + exe_slide);
    import_descriptor->OriginalFirstThunk != 0; import_descriptor++)
    {
        std::string import_dll_name = reinterpret_cast<char*>(exe_base + import_descriptor->Name);
        if (strcasecmp(import_dll_name.c_str(), dll_name) != 0)
            continue;

        for (uintptr_t* thunk = reinterpret_cast<uintptr_t*>(exe_base + import_descriptor->FirstThunk);
        *thunk != 0; thunk++)
        {
            uintptr_t thunk_val = *thunk;
            if (thunk_val & (1ull << 63))
            {
                std::cerr << "Warning: Ordinal detected! ignoring...\n";
            }
            else
            {
                IMAGE_IMPORT_BY_NAME* hint_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(exe_base + thunk_val);
                std::string import_fn_name = reinterpret_cast<char*>(hint_name->Name);
                if (import_name_to_fn.find(import_fn_name) != import_name_to_fn.end())
                {
                    uintptr_t fn = import_name_to_fn.at(import_fn_name);
                    *thunk = fn;
                    printf("Fixed %s import (%lx)\n", import_fn_name.c_str(), *thunk);
                }
                else
                {
                    printf("%s: warning: unimplemented function %s\n", dll_name, import_fn_name.c_str());

                    // Replace the unimplemented import with a function that prints its name for convenience
                    const BYTE unimplemented_fn_code[] =
                    "\x48\x8B\x34\x24"                         // 00: mov    rsi, return_address (2nd argument for printf)
                    "\x48\xBF\x00\x00\x00\x00\x00\x00\x00\x00" // 04: movabs rdi, format_string (format string for printf)
                    "\xB0\x00"                                 // 0e: mov al, 0x0 (number of float args for System V calling conv)
                    "\x53"                                     // 10: push rbx
                    "\x48\xBB\x00\x00\x00\x00\x00\x00\x00\x00" // 11: movabs rbx, printf
                    "\xFF\xD3"                                 // 1b: call rbx
                    "\x5B"                                     // 1d: pop rbx
                    "\xC3"                                     // 1e: ret
                    ;

                    uintptr_t printf_address = (uintptr_t)printf;

                    // Construct the format string
                    std::string unimplemented_fn_msg_first_part = "*** unimplemented " + std::string(dll_name) + " function: ";
                    char* unimplemented_fn_msg = (char*)mmap(nullptr, 256, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
                    if ((intptr_t)unimplemented_fn_msg == -1)
                    {
                        perror("mmap failed");
                        std::exit(1);
                    }
                    memset(unimplemented_fn_msg, 0, 256);
                    strcpy(unimplemented_fn_msg, unimplemented_fn_msg_first_part.c_str());
                    strcpy(unimplemented_fn_msg + unimplemented_fn_msg_first_part.size(), (import_fn_name + " : return address %p\n").c_str());

                    // Allocate the buffer for the unimplemented function
                    char* unimplemented_fn_buffer = (char*)mmap(nullptr, 256, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
                    if ((intptr_t)unimplemented_fn_buffer == -1)
                    {
                        perror("mmap failed");
                        std::exit(1);
                    }

                    if (mprotect((void*)((uintptr_t)unimplemented_fn_buffer & ~(0x1000ul - 1ul)), 0x1000, PROT_READ | PROT_WRITE) == -1)
                    {
                        perror("mprotect failed");
                        std::exit(1);
                    }

                    memcpy(unimplemented_fn_buffer, unimplemented_fn_code, sizeof(unimplemented_fn_code) - 1);
                    memcpy(unimplemented_fn_buffer + 6, &unimplemented_fn_msg, sizeof(const char*));
                    memcpy(unimplemented_fn_buffer + 0x13, &printf_address, sizeof(printf_address));

                    if (mprotect((void*)((uintptr_t)unimplemented_fn_buffer & ~(0x1000ul - 1ul)), 0x1000, PROT_READ | PROT_EXEC) == -1)
                    {
                        perror("mprotect failed");
                        std::exit(1);
                    }

                    *thunk = reinterpret_cast<uintptr_t>(unimplemented_fn_buffer);
                }
            }
        }
    }
}