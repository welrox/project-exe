#include <iostream>
#include <map>
#include <mach-o/getsect.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <thread>
#include <chrono>
#include <unistd.h>
#include <sys/mman.h>
#include "../pe.h"
#define EXPORT extern "C" __attribute__((visibility("default")))

void Sleep_impl(int32_t milliseconds)
{
    printf("Sleep(%d)\n", milliseconds);
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

EXPORT __attribute__((naked)) void Sleep()
{
    asm("pushq %rax\n");

    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n"
        "popq %0\n"
        "ret\n"
        ""
        :
        : "a"(Sleep_impl)
        : "rcx", "rdi");
}

EXPORT void ExitProcess(unsigned int exit_code)
{
    printf("ExitProcess(%u)\n", exit_code);
    std::exit(exit_code);
}

void unimplemented_fn()
{
    printf("*** unimplemted kernel32 fn called ***\n");
}

__attribute__((constructor)) void start()
{
    printf("kernel32 starting!\n");
    #define IMPORT_NAME_TO_FN_ENTRY(name, fn) {name, reinterpret_cast<uintptr_t>(fn)}
    const std::map<std::string, uintptr_t> import_name_to_fn = {
        IMPORT_NAME_TO_FN_ENTRY("Sleep", Sleep), IMPORT_NAME_TO_FN_ENTRY("ExitProcess", ExitProcess)
    };

    const struct section_64* base_cmd = getsectbyname("__TEXT", "__base");
    if (!base_cmd)
    {
        printf("kernel32 error: could not find section __base, exiting\n");
        std::exit(1);
    }
    const struct section_64* import_cmd = getsectbyname("__TEXT", "__import");
    if (!import_cmd)
    {
        printf("kernel32 error: could not find section __import, exiting\n");
        std::exit(1);
    }

    
    constexpr int exe_image_index = 0;
    uintptr_t exe_base = reinterpret_cast<uintptr_t>(_dyld_get_image_header(exe_image_index));
    uintptr_t exe_slide = _dyld_get_image_vmaddr_slide(exe_image_index);
    printf ("image %d: %p\t%s\t(slide = 0x%lx)\n", exe_image_index,
    reinterpret_cast<void*>(exe_base),
    _dyld_get_image_name(exe_image_index),
    exe_slide);

    if (exe_base - exe_slide != base_cmd->addr)
    {
        printf("kernel32 error: image %d does not match the current image (%lx vs %llx)\n", exe_image_index, exe_base - exe_slide, base_cmd->addr);
        std::exit(1);
    }

    printf("kernel32: __base vmaddr: 0x%llx, size = 0x%llx\n", base_cmd->addr, base_cmd->size);
    printf("kernel32: __import vmaddr: 0x%llx\n", import_cmd->addr);
    printf("kernel32: parsing imports\n");
    for (IMAGE_IMPORT_DESCRIPTOR* import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(import_cmd->addr + exe_slide);
    import_descriptor->OriginalFirstThunk != 0; import_descriptor++)
    {
        std::string dll_name = reinterpret_cast<char*>(exe_base + import_descriptor->Name);
        if (strcasecmp(dll_name.c_str(), "kernel32.dll") != 0)
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
                    printf("kernel32: warning: unimplemented function %s\n", import_fn_name.c_str());
                    *thunk = reinterpret_cast<uintptr_t>(unimplemented_fn);
                }
            }
        }
    }

    printf("kernel32: DONE!\n");
}