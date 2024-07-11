#include <iostream>
#include <string>
#include <utility>
#include <ostream>
#include <map>
#include <set>
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

struct string
{
    char* data;
    size_t size;
    size_t capacity;
    size_t unk_0x18;
};

void _ZSt20__throw_length_errorPKc_impl(const char* msg)
{
    throw std::runtime_error(msg);
}

EXPORT __attribute__((naked)) void _ZSt20__throw_length_errorPKc()
{
    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n"
        "retq" : :"r"(_ZSt20__throw_length_errorPKc_impl) :);
}

void* _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_createERyy_impl(string* self, unsigned long long& capacity, unsigned long long old_capacity)
{
    if (static_cast<signed long long>(capacity) < 0)
        _ZSt20__throw_length_errorPKc_impl("basic_string::_M_create");

    if (capacity > old_capacity && capacity < 2 * old_capacity)
    {
        capacity = 2 * old_capacity;
        if (static_cast<signed long long>(capacity) < 0)
            capacity = 0x7fff'ffff'ffff'ffffull;
    }

    return operator new(capacity + 1);
}

EXPORT __attribute__((naked)) void _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_createERyy()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "movq %%r8,  %%rdx\n"
        "call *%0\n": :"r"(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_createERyy_impl) :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

void _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE13_S_copy_charsEPcPKcS7__impl(char* dest, char* const src_begin, char* const src_end)
{
    size_t len = reinterpret_cast<uintptr_t>(src_end) - reinterpret_cast<uintptr_t>(src_begin);
    for (size_t i = 0; i < len; ++i)
    {
        dest[i] = src_begin[i];
    }
}

EXPORT __attribute__((naked)) void _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE13_S_copy_charsEPcPKcS7_()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "movq %%r8,  %%rdx\n"
        "call *%0\n": :"r"(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE13_S_copy_charsEPcPKcS7__impl) :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

void _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSEPKc_impl(string* self, char* const str)
{
    //printf("std::string operator=(self=%p, str=%s)\n", self, str);
    if (reinterpret_cast<uintptr_t>(self->data) != reinterpret_cast<uintptr_t>(&self->capacity))
        operator delete(self->data);

    size_t len = strlen(str);
    unsigned long long capacity = len;
    self->data = reinterpret_cast<char*>(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_createERyy_impl(self, capacity, self->capacity));
    self->size = len;
    self->capacity = capacity;
    memcpy(self->data, str, len);
}

EXPORT __attribute__((naked)) void _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSEPKc()
{
    PUSH_ALL_REGS;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "call *%0\n": :"r"(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSEPKc_impl) :);
    POP_ALL_REGS;
    asm("retq\n");
}

void _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev_impl(string* self)
{
    if (reinterpret_cast<uintptr_t>(self->data) == reinterpret_cast<uintptr_t>(&self->capacity))
        return;
    operator delete(self->data);
}

EXPORT __attribute__((naked)) void _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev()
{
    PUSH_ALL_REGS;
    asm("movq %%rcx, %%rdi\n"
        "call *%0\n": :"r"(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev_impl) :);
    POP_ALL_REGS;
    asm("retq\n");
}

void _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructEyc_impl(string* self, unsigned long long size, char c)
{
    char* data;
    if (size <= 15)
    {
        data = self->data;
    }
    else
    {
        data = reinterpret_cast<char*>(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_createERyy_impl(self, size, 0));
        self->data = data;
        self->capacity = size;
    }

    self->size = size;
    data[size] = '\0';
    if (!size)
        return;
    
    if (size == 1)
    {
        data[0] = c;
    }
    else
    {
        memset(data, c, size);
    }
}

EXPORT __attribute__((naked)) void _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructEyc()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "movq %%r8,  %%rdx\n"
        "call *%0\n": :"r"(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructEyc_impl) :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

string* _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6insertEyPKc_impl(string* self, unsigned long long pos, char* const str)
{
    std::string s = std::string(self->data);
    s.insert(pos, str);
    size_t cap = std::max(s.size() + 1, s.capacity());
    char* buffer = new char[cap];
    memcpy(buffer, s.data(), s.size() + 1);
    if (reinterpret_cast<uintptr_t>(self->data) != reinterpret_cast<uintptr_t>(&self->capacity))
        operator delete(self->data);
    
    self->data = buffer;
    self->size = s.size();
    self->capacity = cap;
    return self;
}

EXPORT __attribute__((naked)) void _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6insertEyPKc()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "movq %%r8,  %%rdx\n"
        "call *%0\n": :"r"(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6insertEyPKc_impl) :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

// std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::basic_string(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&&)
void _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EOS4__impl(string* self, string* rvalue_ref)
{
    self->data = reinterpret_cast<char*>(&self->capacity);
    self->capacity = rvalue_ref->capacity;

    if (reinterpret_cast<uintptr_t>(rvalue_ref->data) != reinterpret_cast<uintptr_t>(&rvalue_ref->capacity))
    {
        self->data = rvalue_ref->data;
    }
    else
    {
        self->unk_0x18 = rvalue_ref->unk_0x18;
    }

    self->size = rvalue_ref->size;
    rvalue_ref->data = reinterpret_cast<char*>(&rvalue_ref->capacity);
    rvalue_ref->size = 0;
    *reinterpret_cast<char*>(&rvalue_ref->capacity) = '\0';
}

EXPORT __attribute__((naked)) void _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EOS4_()
{
    PUSH_ALL_REGS;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "call *%0\n": :"r"(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EOS4__impl) :);
    POP_ALL_REGS;
    asm("retq\n");
}

string* _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6appendEPKc_impl(string* self, const char* str)
{
    std::string s = std::string(self->data);
    s.append(str);
    size_t cap = std::max(s.size() + 1, s.capacity());
    char* buffer = new char[cap];
    memcpy(buffer, s.data(), s.size() + 1);
    if (reinterpret_cast<uintptr_t>(self->data) != reinterpret_cast<uintptr_t>(&self->capacity))
        operator delete(self->data);
    
    self->data = buffer;
    self->size = s.size();
    self->capacity = cap;
    return self;
}

EXPORT __attribute__((naked)) void _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6appendEPKc()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "call *%0\n": :"r"(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6appendEPKc_impl) :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

size_t _ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE8capacityEv_impl(string* self)
{
    return (reinterpret_cast<uintptr_t>(self->data) == reinterpret_cast<uintptr_t>(&self->capacity) ? 15 : self->capacity);
}

EXPORT __attribute__((naked)) void _ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE8capacityEv()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "call *%0\n": :"r"(_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE8capacityEv_impl) :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

EXPORT __attribute__((naked)) void _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6appendERKS4_()
{
    asm("movq %%rcx, %%rdi\n"
        "movq (%%rdx), %%rsi\n"
        "jmp *%0\n": :"r"(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6appendEPKc_impl) :);
}

EXPORT __attribute__((naked)) void _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE13_M_set_lengthEy()
{
    asm("movq (%rcx), %rax\n"
    "movq %rdx, 0x8(%rcx)\n"
    "movb $0x0, (%rax,%rdx)\n"
    "retq\n");
}

EXPORT __attribute__((naked)) void _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE13_M_local_dataEv()
{
    asm("leaq 0x10(%rcx), %rax\n"
        "retq\n");
}

EXPORT __attribute__((naked)) void _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_Alloc_hiderC1EPcRKS3_()
{
    asm("movq %rdx, (%rcx)\n"
        "retq\n");
}

EXPORT __attribute__((naked)) void _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7_M_dataEPc()
{
    asm("movq %rdx, (%rcx)\n"
        "retq\n");
}

EXPORT __attribute__((naked)) void _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE11_M_capacityEy()
{
    asm("movq %rdx, 0x10(%rcx)\n"
        "retq\n");
}

EXPORT __attribute__((naked)) void _ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7_M_dataEv()
{
    asm("movq (%rcx), %rax\n"
    "retq\n");
}

EXPORT __attribute__((naked)) void _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEixEy()
{
    asm("movq %rdx, %rax\n"
        "addq (%rcx), %rax\n"
        "retq\n");
}

EXPORT __attribute__((naked)) void _ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4sizeEv()
{
    asm("movq 0x8(%rcx), %rax\n"
        "retq\n");
}

std::ostream&(*_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc_fn)(std::ostream&, const char*) = &std::operator<<;
std::ostream&(*_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_c_fn)(std::ostream&, char) = &std::operator<<;
std::istream&(*_ZStrsIcSt11char_traitsIcEERSt13basic_istreamIT_T0_ES6_RS3__fn)(std::istream&, char&) = &std::operator>>;
std::ostream&(std::ostream::*_ZNSolsEi_fn)(int) = &std::ostream::operator<<;
std::ostream&(std::ostream::*_ZNSolsEPFRSoS_E_fn)(std::ostream&(*)(std::ostream&)) = &std::ostream::operator<<;
std::istream&(std::istream::*_ZNSirsERi_fn)(int&) = &std::istream::operator>>;
std::basic_ostream<char, std::char_traits<char> >&(*_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6__fn)(std::basic_ostream<char, std::char_traits<char> >&) = std::endl;
void*(*_Znwy_fn)(std::size_t) = operator new;
void(*_ZdlPvy_fn)(void*, std::size_t) = operator delete;


// indirection to avoid clang++ crash
void* _ZNSirsERi_fn2 = *reinterpret_cast<void**>(&_ZNSirsERi_fn);
void* _ZNSolsEPFRSoS_E_fn2 = *reinterpret_cast<void**>(&_ZNSolsEPFRSoS_E_fn);
void* _ZNSolsEi_fn2 = *reinterpret_cast<void**>(&_ZNSolsEi_fn);
void* _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_c_fn2 = *reinterpret_cast<void**>(&_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_c_fn);
void* _ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6__fn2 = *reinterpret_cast<void**>(&_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6__fn);

EXPORT __attribute__((naked)) void _ZdlPvy()
{
    PUSH_ALL_REGS;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "call *%0\n": :"r"(_ZdlPvy_fn) :);
    POP_ALL_REGS;
    asm("retq\n");
}

EXPORT __attribute__((naked)) void _Znwy()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "call *%0\n": :"r"(_Znwy_fn) :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

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

int __cxa_guard_acquire_impl(uint64_t guard)
{
    //printf("__cxa_guard_acquire(guard=0x%llx)\n", guard);
    static std::set<uint64_t> initialized;
    if (initialized.find(guard) == initialized.end())
    {
        initialized.insert(guard);
        //printf("\tret=1\n");
        return 1;
    }
    //printf("\tret=0\n");
    return 0;
}

EXPORT __attribute__((naked)) void ___cxa_guard_acquire()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "call *%0\n": :"r"(__cxa_guard_acquire_impl) :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

void __cxa_guard_release_impl(uint64_t guard)
{
    printf("__cxa_guard_release(guard=0x%llx)\n", guard);
}

EXPORT __attribute__((naked)) void ___cxa_guard_release()
{
    PUSH_ALL_REGS;
    asm("movq %%rcx, %%rdi\n"
        "call *%0\n": :"r"(__cxa_guard_release_impl) :);
    POP_ALL_REGS;
    asm("retq\n");
}

void __attribute__((constructor)) start()
{
    printf("libstdc++-6 starting!\n");

    #define IMPORT_ENTRY(name) {#name, reinterpret_cast<uintptr_t>(&name)}
    const std::map<std::string, uintptr_t> import_name_to_fn = {
        IMPORT_ENTRY(_ZSt4cout), IMPORT_ENTRY(_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc), IMPORT_ENTRY(_ZSt3cin), 
        IMPORT_ENTRY(_ZNSirsERi), IMPORT_ENTRY(_ZNSolsEi), IMPORT_ENTRY(_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_c), 
        IMPORT_ENTRY(_ZStrsIcSt11char_traitsIcEERSt13basic_istreamIT_T0_ES6_RS3_), IMPORT_ENTRY(_ZNSolsEPFRSoS_E), 
        IMPORT_ENTRY(_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_), {"__cxa_guard_acquire", reinterpret_cast<uintptr_t>(___cxa_guard_acquire)}, 
        IMPORT_ENTRY(_Znwy), {"__cxa_guard_release", reinterpret_cast<uintptr_t>(___cxa_guard_release)}, 
        IMPORT_ENTRY(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE13_M_local_dataEv), IMPORT_ENTRY(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_Alloc_hiderC1EPcRKS3_),
        IMPORT_ENTRY(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_createERyy), IMPORT_ENTRY(_ZSt20__throw_length_errorPKc), 
        IMPORT_ENTRY(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7_M_dataEPc), IMPORT_ENTRY(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE11_M_capacityEy), 
        IMPORT_ENTRY(_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7_M_dataEv), IMPORT_ENTRY(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE13_S_copy_charsEPcPKcS7_), 
        IMPORT_ENTRY(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE13_M_set_lengthEy), IMPORT_ENTRY(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEixEy),
        IMPORT_ENTRY(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSEPKc), IMPORT_ENTRY(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev), 
        IMPORT_ENTRY(_ZdlPvy), IMPORT_ENTRY(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructEyc), 
        IMPORT_ENTRY(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6insertEyPKc), IMPORT_ENTRY(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EOS4_), 
        IMPORT_ENTRY(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6appendEPKc), IMPORT_ENTRY(_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4sizeEv), 
        IMPORT_ENTRY(_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE8capacityEv), IMPORT_ENTRY(_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6appendERKS4_),
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
    const struct section_64* header_cmd = getsectbyname("__TEXT", "__header");
    if (!header_cmd)
    {
        printf("user32 error: could not find section __header, exiting\n");
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
                    const BYTE unimplemented_fn_code[] = "\x48\x8B\x34\x24\x48\xBF\x00\x00\x00\x00\x00\x00\x00\x00\xB0\x00\x53\x48\xBB\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xD3\x5B\xC3";
                    uintptr_t printf_address = (uintptr_t)printf;
                    const char msg1[] = "*** unimplemented libstdc++-6 function: ";
                    char* unimplemented_fn_msg = (char*)mmap(nullptr, 256, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
                    if ((intptr_t)unimplemented_fn_msg == -1)
                    {
                        perror("mmap failed");
                        std::exit(1);
                    }
                    memset(unimplemented_fn_msg, 0, 256);
                    strcpy(unimplemented_fn_msg, msg1);
                    strcpy(unimplemented_fn_msg + strlen(msg1), (import_fn_name + " : return address %p\n").c_str());
                    char* data = (char*)mmap(nullptr, 256, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
                    if ((intptr_t)data == -1)
                    {
                        perror("mmap failed");
                        std::exit(1);
                    }
                    if (mprotect((void*)((uintptr_t)data & ~(0x1000ul - 1ul)), 0x1000, PROT_READ | PROT_WRITE) == -1)
                    {
                        perror("mprotect failed");
                        std::exit(1);
                    }
                    memcpy(data, unimplemented_fn_code, sizeof(unimplemented_fn_code) - 1);
                    memcpy(data + 6, &unimplemented_fn_msg, sizeof(const char*));
                    memcpy(data + 0x13, &printf_address, sizeof(printf_address));
                    if (mprotect((void*)((uintptr_t)data & ~(0x1000ul - 1ul)), 0x1000, PROT_READ | PROT_EXEC) == -1)
                    {
                        perror("mprotect failed");
                        std::exit(1);
                    }
                    *thunk = reinterpret_cast<uintptr_t>(data);
                }
            }
        }
    }
}