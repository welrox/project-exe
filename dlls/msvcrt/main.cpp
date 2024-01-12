#include <iostream>
#include <map>
#include <mach-o/getsect.h>
#include <mach-o/dyld.h>
#include <unistd.h>
#include <sys/mman.h>
#include "../../pe.h"
#include "../asm.h"
#define EXPORT extern "C" __attribute__((visibility("default")))

typedef void (*PVFV)();

void _initterm_impl(PVFV* start, PVFV* end)
{
    printf("_initterm(start=%p, end=%p)\n", start, end);
    for (; start < end; ++start)
    {
        PVFV fn = *start;
        if (fn)
            fn();
    }
}

EXPORT __attribute__((naked)) void _initterm()
{
    PUSH_ALL_REGS;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "callq *%0\n"
        :
        : "r"(_initterm_impl)
        : "rdi", "rsi", "rcx", "rdx"
    );
    POP_ALL_REGS;
    asm("ret\n");
}

EXPORT void __set_app_type(int at)
{
    printf("__set_app_type\n");
    // obsolete msvcrt function, let's not do anything here
}

int __argc = 0;
char** __argv = nullptr;
char** __env = nullptr;

int __getmainargs_impl(int* argc, char*** argv, char*** env)
{
    printf("__getmainargs(argc=%p, argv=%p, env=%p)\n", argc, argv, env);
    *argc = __argc;
    *argv = __argv;
    *env = __env;
    return 0;
}

EXPORT __attribute__((naked)) void __getmainargs()
{
        asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "movq %%r8, %%rdx\n"
        "callq *%0\n"
        "ret\n"
        :
        : "r"(_initterm_impl)
        : "rdi", "rsi", "rcx", "rdx", "r8"
    );
}

int* __p___argc_impl()
{
    printf("__p___argc()\n");
    return &__argc;
}

EXPORT __attribute__((naked)) void __p___argc()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("callq *%0\n": : "r"(__p___argc_impl):);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

char*** __p___argv_impl()
{
    printf("__p___argv()\n");
    return &__argv;
}

EXPORT __attribute__((naked)) void __p___argv()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("callq *%0\n": : "r"(__p___argv_impl):);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

char*** __p__environ_impl()
{
    printf("__p__environ()\n");
    return &__env;
}

EXPORT __attribute__((naked)) void __p__environ()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("callq *%0\n": : "r"(__p__environ_impl):);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

EXPORT uint64_t __initenv = 0;

void* malloc_impl(size_t size)
{
    printf("malloc(size=%zu)\n", size);
    return malloc(size);
}

EXPORT __attribute__((naked)) void _malloc()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n"
        :
        : "r"(malloc_impl)
        :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("ret\n");
}

void* _onexit_impl(void(*function)())
{
    printf("_onexit(function=%p)\n", function);
    int result = atexit(function);
    if (result == 0)
        return reinterpret_cast<void*>(function);
    return nullptr;
}

EXPORT __attribute__((naked)) void _onexit()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n"
        :
        : "r"(_onexit_impl)
        :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("ret\n");
}

int _crt_atexit_impl(void(*function)())
{
    // https://www.winehq.org/pipermail/wine-patches/2015-August/141941.html
    printf("_crt_atexit(function=%p)\n", function);
    return _onexit_impl(function) == function ? 0 : -1;
}

EXPORT __attribute__((naked)) void _crt_atexit()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n": : "r"(_crt_atexit_impl):);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

EXPORT int _fmode = 0;
EXPORT int* __p__fmode()
{
    return &_fmode;   
}

EXPORT int _commode = 0;
EXPORT int* __p__commode()
{
    return &_commode;
}

int _initialize_narrow_environment_impl()
{
    printf("_initialize_narrow_environment()\n");
    return 1;
}

EXPORT __attribute__((naked)) void _initialize_narrow_environment()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("callq *%0\n" : : "r"(_initialize_narrow_environment_impl):);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

void _configure_narrow_argv_impl()
{
    printf("_configure_narrow_argv()\n");
}

EXPORT __attribute__((naked)) void _configure_narrow_argv()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("callq *%0\n" : : "r"(_configure_narrow_argv_impl):);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

EXPORT void unimplemented()
{
    void* address;
    asm("movq 8(%%rbp), %0":"=r"(address):);
    printf("*** unimplemented msvcrt function (return=%p)***\n", address);
}

int _set_new_mode_impl(int newhandlermode)
{
    // not entirely sure what this does...
    printf("_set_new_mode(newhandlermode=%d)\n", newhandlermode);
    if (newhandlermode != 0 && newhandlermode != 1)
        return -1;
    
    return 1;
}

EXPORT __attribute__((naked)) void _set_new_mode()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n": : "r"(_set_new_mode_impl):);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

void* _set_invalid_parameter_handler_impl(void* pNew)
{
    printf("_set_invalid_parameter_handler(pNew=%p)\n", pNew);
    return pNew;
}

EXPORT __attribute__((naked)) void _set_invalid_parameter_handler()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n": : "r"(_set_invalid_parameter_handler_impl):);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

size_t strlen_impl(const char* str)
{
    printf("strlen(str=%s)\n", str);
    return strlen(str);
}

EXPORT __attribute__((naked)) void _strlen()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n": : "r"(strlen_impl):);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

void* memcpy_impl(void* dest, const void* src, size_t count)
{
    printf("memcpy(dest=%p, src=%p, count=%zu)\n", dest, src, count);
    return memcpy(dest, src, count);
}

EXPORT __attribute__((naked)) void _memcpy()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "movq %%r8, %%rdx\n"
        "callq *%0\n": : "r"(memcpy_impl): "rcx", "rdx", "r8", "rdi", "rsi", "rdx");
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

__attribute__((constructor)) void start(int argc, char** argv, char** env)
{
    printf("msvcrt starting!\n");
    __argc = argc;
    __argv = argv;
    __env = env;
    #define IMPORT_ENTRY(name) {#name, reinterpret_cast<uintptr_t>(&name)}
    const std::map<std::string, uintptr_t> import_name_to_fn = {
        IMPORT_ENTRY(_initterm), IMPORT_ENTRY(__set_app_type), IMPORT_ENTRY(__getmainargs), IMPORT_ENTRY(__initenv),
        IMPORT_ENTRY(_fmode), IMPORT_ENTRY(_commode), {"malloc", reinterpret_cast<uintptr_t>(&_malloc)}, IMPORT_ENTRY(_onexit),
        {"_set_app_type", reinterpret_cast<uintptr_t>(__set_app_type)}, IMPORT_ENTRY(__p__fmode), IMPORT_ENTRY(__p__commode),
        IMPORT_ENTRY(_initialize_narrow_environment), IMPORT_ENTRY(_configure_narrow_argv), IMPORT_ENTRY(__p___argc), 
        IMPORT_ENTRY(__p___argv), IMPORT_ENTRY(__p__environ), IMPORT_ENTRY(_set_new_mode), IMPORT_ENTRY(_set_invalid_parameter_handler),
        {"strlen", reinterpret_cast<uintptr_t>(_strlen)}, {"memcpy", reinterpret_cast<uintptr_t>(_memcpy)}, IMPORT_ENTRY(_crt_atexit),
    };
    #undef IMPORT_ENTRY

    const struct section_64* base_cmd = getsectbyname("__TEXT", "__base");
    if (!base_cmd)
    {
        printf("msvcrt error: could not find section __base, exiting\n");
        std::exit(1);
    }
    const struct section_64* import_cmd = getsectbyname("__TEXT", "__import");
    if (!import_cmd)
    {
        printf("msvcrt error: could not find section __import, exiting\n");
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
        printf("msvcrt error: image %d does not match the current image (%lx vs %llx)\n", exe_image_index, exe_base - exe_slide, base_cmd->addr);
        std::exit(1);
    }

    printf("msvcrt: parsing imports\n");
    for (IMAGE_IMPORT_DESCRIPTOR* import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(import_cmd->addr + exe_slide);
    import_descriptor->OriginalFirstThunk != 0; import_descriptor++)
    {
        std::string dll_name = reinterpret_cast<char*>(exe_base + import_descriptor->Name);
        if (strcasecmp(dll_name.c_str(), "msvcrt.dll") != 0 && dll_name.find("api-ms-win-crt") == std::string::npos)
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
                    printf("msvcrt: warning: unimplemented function %s\n", import_fn_name.c_str());
                    *thunk = reinterpret_cast<uintptr_t>(unimplemented);
                }
            }
        }
    }

    printf("msvcrt DONE!\n");
}