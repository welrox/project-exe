#include <iostream>
#include <ostream>
#include <map>
#include <mach-o/getsect.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/vm_region.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <dlfcn.h>
#include <thread>
#include <chrono>
#include <unistd.h>
#include <sys/mman.h>
#include "../../pe.h"
#include "../asm.h"
#define EXPORT extern "C" __attribute__((visibility("default")))

EXPORT std::ostream& _ZSt4cout = std::cout;
EXPORT std::istream& _ZSt3cin = std::cin;

std::ostream&(*_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc_fn)(std::ostream&, const char*) = &std::operator<<;
std::ostream&(*_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_c_fn)(std::ostream&, char) = &std::operator<<;
std::istream&(*_ZStrsIcSt11char_traitsIcEERSt13basic_istreamIT_T0_ES6_RS3__fn)(std::istream&, char&) = &std::operator>>;
std::ostream&(std::ostream::*_ZNSolsEi_fn)(int) = &std::ostream::operator<<;
std::ostream&(std::ostream::*_ZNSolsEPFRSoS_E_fn)(std::ostream&(*)(std::ostream&)) = &std::ostream::operator<<;
std::istream&(std::istream::*_ZNSirsERi_fn)(int&) = &std::istream::operator>>;
std::basic_ostream<char, std::char_traits<char> >&(*_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6__fn)(std::basic_ostream<char, std::char_traits<char> >&) = std::endl;

// indirection to avoid clang++ crash
void* _ZNSirsERi_fn2 = *reinterpret_cast<void**>(&_ZNSirsERi_fn);
void* _ZNSolsEPFRSoS_E_fn2 = *reinterpret_cast<void**>(&_ZNSolsEPFRSoS_E_fn);
void* _ZNSolsEi_fn2 = *reinterpret_cast<void**>(&_ZNSolsEi_fn);
void* _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_c_fn2 = *reinterpret_cast<void**>(&_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_c_fn);
void* _ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6__fn2 = *reinterpret_cast<void**>(&_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6__fn);

EXPORT __attribute__((naked)) void _ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "call *%0\n": :"r"(_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6__fn2) :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

EXPORT __attribute__((naked)) void _ZNSolsEPFRSoS_E()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "call *%0\n": :"r"(_ZNSolsEPFRSoS_E_fn2) :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

EXPORT __attribute__((naked)) void _ZStrsIcSt11char_traitsIcEERSt13basic_istreamIT_T0_ES6_RS3_()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "call *%0\n": :"r"(_ZStrsIcSt11char_traitsIcEERSt13basic_istreamIT_T0_ES6_RS3__fn) :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");    
}

EXPORT __attribute__((naked)) void _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_c()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "call *%0\n": :"r"(_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_c_fn2) :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

EXPORT __attribute__((naked)) void _ZNSolsEi()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "call *%0\n": :"r"(_ZNSolsEi_fn2) :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

EXPORT __attribute__((naked)) void _ZNSirsERi()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "call *%0\n": :"r"(_ZNSirsERi_fn2) :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

EXPORT __attribute__((naked)) void _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "call *%0\n": :"r"(_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc_fn) :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

EXPORT void unimplemented()
{
    void* address;
    asm("movq 8(%%rbp), %0":"=r"(address):);
    printf("*** unimplemented libstdc++-6 function (return=%p)***\n", address);
}

void __attribute__((constructor)) start()
{
    printf("libstdc++-6 starting!\n");

    #define IMPORT_ENTRY(name) {#name, reinterpret_cast<uintptr_t>(&name)}
    const std::map<std::string, uintptr_t> import_name_to_fn = {
        IMPORT_ENTRY(_ZSt4cout), IMPORT_ENTRY(_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc), IMPORT_ENTRY(_ZSt3cin), 
        IMPORT_ENTRY(_ZNSirsERi), IMPORT_ENTRY(_ZNSolsEi), IMPORT_ENTRY(_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_c), 
        IMPORT_ENTRY(_ZStrsIcSt11char_traitsIcEERSt13basic_istreamIT_T0_ES6_RS3_), IMPORT_ENTRY(_ZNSolsEPFRSoS_E), 
        IMPORT_ENTRY(_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_), 
    };
    #undef IMPORT_ENTRY

    const struct section_64* base_cmd = getsectbyname("__TEXT", "__base");
    if (!base_cmd)
    {
        printf("libstdc++-6 error: could not find section __base, exiting\n");
        std::exit(1);
    }
    const struct section_64* import_cmd = getsectbyname("__TEXT", "__import");
    if (!import_cmd)
    {
        printf("libstdc++-6 error: could not find section __import, exiting\n");
        std::exit(1);
    }

    constexpr int exe_image_index = 0;
    uintptr_t exe_base = reinterpret_cast<uintptr_t>(_dyld_get_image_header(exe_image_index));
    uintptr_t exe_slide = _dyld_get_image_vmaddr_slide(exe_image_index);
    printf ("image %d: %p\t%s\t(slide = 0x%lx)\n", exe_image_index,
    reinterpret_cast<void*>(exe_base),
    _dyld_get_image_name(exe_image_index),
    exe_slide);

    printf("libstdc++-6: parsing imports\n");
    for (IMAGE_IMPORT_DESCRIPTOR* import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(import_cmd->addr + exe_slide);
    import_descriptor->OriginalFirstThunk != 0; import_descriptor++)
    {
        std::string dll_name = reinterpret_cast<char*>(exe_base + import_descriptor->Name);
        if (strcasecmp(dll_name.c_str(), "libstdc++-6.dll") != 0)
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
                    printf("libstdc++-6: warning: unimplemented function %s\n", import_fn_name.c_str());
                    *thunk = reinterpret_cast<uintptr_t>(unimplemented);
                }
            }
        }
    }
}