#include <iostream>
#include <map>
#include <mach-o/getsect.h>
#include <mach-o/dyld.h>
#include <unistd.h>
#include <termios.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/ioctl.h>
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

std::vector<void(*)()> _onexit_functions = {};
void* _onexit_impl(void(*function)())
{
    printf("_onexit(function=%p)\n", function);
    // calling atexit crashes since it expects a valid mach-o header to be loaded in memory,
    // but that had already been overwritten with a DOS and PE header by kernel32,
    // so we implement our own _onexit

    _onexit_functions.push_back(function);
    return reinterpret_cast<void*>(function);
}

EXPORT void ____call_all_exit_functions()
{
    for (auto function : _onexit_functions)
    {
        function();
    }
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
    //printf("strlen(str=%s)\n", str);
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
    //printf("memcpy(dest=%p, src=%p, count=%zu)\n", dest, src, count);
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

FILE* __acrt_iob_func_impl(unsigned int index)
{
    printf("__acrt_iob_func(index=%u)\n", index);
    switch (index)
    {
        case 0:
        return stdin;
        break;
        case 1:
        return stdout;
        break;
        case 2:
        return stderr;
        break;
        default:
        throw std::runtime_error("i don't think this index value is valid but can't know for sure...");
        break;
    }
}

EXPORT __attribute__((naked)) void __acrt_iob_func()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n": : "r"(__acrt_iob_func_impl):);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

void _lock_file_impl(FILE* file)
{
    printf("_lock_file(file=%p)\n", file);
    int fd = fileno(file);
    printf("\tfd=%d\n", fd);
    int ret = flock(fd, LOCK_EX);
    printf("\tret=%d\n", ret);
}

EXPORT __attribute__((naked)) void _lock_file()
{
    PUSH_ALL_REGS;
    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n": : "r"(_lock_file_impl):);
    POP_ALL_REGS;
    asm("retq\n");
}

void _unlock_file_impl(FILE* file)
{
    printf("_unlock_file(file=%p)\n", file);
    int fd = fileno(file);
    printf("\tfd=%d\n", fd);
    int ret = flock(fd, LOCK_UN);
    printf("\tret=%d\n", ret);
}

EXPORT __attribute__((naked)) void _unlock_file()
{
    PUSH_ALL_REGS;
    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n": : "r"(_unlock_file_impl):);
    POP_ALL_REGS;
    asm("retq\n");
}

int* _errno_impl()
{
    printf("_errno()\n");
    return &errno;
}

EXPORT __attribute__((naked)) void _errno()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("callq *%0\n": : "r"(_errno_impl):);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

int fputc_impl(int c, FILE* stream)
{
    //printf("fputc(c=%d, stream=%p)\n", c, stream);
    return fputc(c, stream);
}

EXPORT __attribute__((naked)) void _fputc()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "callq *%0\n"
        : : "r"(fputc_impl):);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

void _exit_impl(int exit_code)
{
    printf("_exit(exit_code=%d)\n", exit_code);
    _exit(exit_code);
}

EXPORT __attribute__((naked)) void ___exit()
{
    PUSH_ALL_REGS;
    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n"
        : : "r"(_exit_impl):);
    POP_ALL_REGS;
    asm("retq\n");
}

void exit_impl(int exit_code)
{
    printf("exit(exit_code=%d)\n", exit_code);
    exit(exit_code);
}

EXPORT __attribute__((naked)) void __exit()
{
    PUSH_ALL_REGS;
    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n"
        : : "r"(exit_impl):);
    POP_ALL_REGS;
    asm("retq\n");
}

// this is all wrong
int __stdio_common_vfprintf_impl(int unknown, FILE* stream, const char* format, va_list arg)
{
    printf("__stdio_common_vfprintf(stream=%p (fd=%d), format='%s', arg=%p)\n", stream, fileno(stream), format, arg);
    return vfprintf(stream, format, arg);
}

EXPORT __attribute__((naked)) void __stdio_common_vfprintf()
{
    asm("movq %rbp, 0x28(%rsp)");
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "movq %%r8, %%rdx\n"
        "movq %%rbp, %%rcx\n"
        "callq *%0\n"
        : : "r"(__stdio_common_vfprintf_impl):);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

size_t fwrite_impl(const void* buffer, size_t size, size_t count, FILE* stream)
{
    printf("fwrite(buffer=%p, size=%zu, count=%zu, stream=%p (fd=%d))\n", buffer, size, count, stream, fileno(stream));
    return fwrite(buffer, size, count, stream);
}

EXPORT __attribute__((naked)) void _fwrite()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "movq %%r8, %%rdx\n"
        "movq %%r9, %%rcx\n"
        "callq *%0\n"
        : : "r"(fwrite_impl):);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

EXPORT void _abort()
{
    abort();
}

time_t _time64_impl(time_t* arg)
{
    printf("_time64(arg=%p)\n", arg);
    return time(arg);
}

EXPORT __attribute__((naked)) void _time64()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n"
        : : "r"(_time64_impl):);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

void srand_impl(unsigned int seed)
{
    printf("srand(seed=%u)\n", seed);
    srand(seed);
}

EXPORT __attribute__((naked)) void _srand()
{
    PUSH_ALL_REGS;
    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n"
        : : "r"(srand_impl):);
    POP_ALL_REGS;
    asm("retq\n");
}

EXPORT int _rand()
{
    //printf("rand()\n");
    return rand();
}

int system_impl(const char* command)
{
    printf("system(command=%s)\n", command);
    if (strcmp(command, "cls") == 0)
    {
        return system("clear");
    }
    return system(command);
}

EXPORT __attribute__((naked)) void _system()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n"
        : : "r"(system_impl):);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

EXPORT int _kbhit()
{
    // https://www.flipcode.com/archives/_kbhit_for_Linux.shtml
    static const int STDIN = 0;
    static int initialized = 0;

    if (! initialized) {
        // Use termios to turn off line buffering
        struct termios term;
        tcgetattr(STDIN, &term);
        term.c_lflag &= ~ICANON;
        tcsetattr(STDIN, TCSANOW, &term);
        setbuf(stdin, NULL);
        initialized = 1;
    }

    int bytesWaiting;
    ioctl(STDIN, FIONREAD, &bytesWaiting);
    return bytesWaiting;
}

EXPORT int _getch()
{
    return fgetc(stdin);
}

void* memset_impl(void* dest, int c, size_t count)
{
    return memset(dest, c, count);
}

EXPORT __attribute__((naked)) void _memset()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "movq %%r8, %%rdx\n"
        "callq *%0\n"
        : : "r"(memset_impl):);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

void* memmove_impl(void* dst, const void* src, size_t count)
{
    return memmove(dst, src, count);
}

EXPORT __attribute__((naked)) void _memmove()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "movq %%r8, %%rdx\n"
        "callq *%0\n"
        : : "r"(memmove_impl):);
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
    #define PTR(sym) reinterpret_cast<uintptr_t>(sym)
    const std::map<std::string, uintptr_t> import_name_to_fn = {
        IMPORT_ENTRY(_initterm), IMPORT_ENTRY(__set_app_type), IMPORT_ENTRY(__getmainargs), IMPORT_ENTRY(__initenv),
        IMPORT_ENTRY(_fmode), IMPORT_ENTRY(_commode), {"malloc", PTR(&_malloc)}, IMPORT_ENTRY(_onexit),
        {"_set_app_type", PTR(__set_app_type)}, IMPORT_ENTRY(__p__fmode), IMPORT_ENTRY(__p__commode),
        IMPORT_ENTRY(_initialize_narrow_environment), IMPORT_ENTRY(_configure_narrow_argv), IMPORT_ENTRY(__p___argc), 
        IMPORT_ENTRY(__p___argv), IMPORT_ENTRY(__p__environ), IMPORT_ENTRY(_set_new_mode), IMPORT_ENTRY(_set_invalid_parameter_handler),
        {"strlen", PTR(_strlen)}, {"memcpy", PTR(_memcpy)}, IMPORT_ENTRY(_crt_atexit),
        IMPORT_ENTRY(__acrt_iob_func), IMPORT_ENTRY(_lock_file), IMPORT_ENTRY(_errno), {"fputc", PTR(_fputc)},
        IMPORT_ENTRY(_unlock_file), {"_exit", PTR(___exit)}, {"exit", PTR(__exit)},
        IMPORT_ENTRY(__stdio_common_vfprintf), {"abort", PTR(_abort)}, {"fwrite", PTR(_fwrite)},
        IMPORT_ENTRY(_time64), {"srand", PTR(_srand)}, {"rand", PTR(_rand)}, {"system", PTR(_system)}, IMPORT_ENTRY(_kbhit),
        IMPORT_ENTRY(_getch), {"memset", PTR(_memset)}, {"memmove", PTR(_memmove)}, 
    };
    #undef IMPORT_ENTRY
    #undef PTR

    const struct section_64* header_cmd = getsectbyname("__TEXT", "___header");
    if (!header_cmd)
    {
        printf("kernel32 error: could not find section ___header, exiting\n");
        std::exit(1);
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

    printf("msvcrt: parsing imports\n");
    for (IMAGE_IMPORT_DESCRIPTOR* import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(import_addr + exe_slide);
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