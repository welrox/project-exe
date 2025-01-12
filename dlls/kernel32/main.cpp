#include <iostream>
#include <map>
#include <locale>
#include <codecvt>
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
#include "../cp437.h"
#define EXPORT extern "C" __attribute__((visibility("default")))

void Sleep_impl(int32_t milliseconds)
{
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

void ExitProcess_impl(unsigned int exit_code)
{
    printf("ExitProcess(%u)\n", exit_code);
    void* msvcrt_handle = dlopen("libmsvcrt.dylib", RTLD_NOLOAD);
    if (!msvcrt_handle)
    {
        printf("msvcrt_handle is null\n");
    }
    else
    {
        void(*call_all)() = (void(*)())dlsym(msvcrt_handle, "____call_all_exit_functions");
        if (!call_all)
        {
            printf("call_all is null\n");
        }
        else
        {
            call_all();
        }
    }
    std::exit(exit_code);
}

EXPORT __attribute__((naked)) void ExitProcess()
{
    asm("movq %%rcx, %%rdi\n"
        "call *%0\n"
        :
        : "r"(ExitProcess_impl)
        :);
}

void EnterCriticalSection_impl(void* lpCriticalSection)
{
    printf("(not implemented) EnterCriticalSection(lpCriticalSection=%p)\n", lpCriticalSection);
}

EXPORT __attribute__((naked)) void EnterCriticalSection()
{
    asm("pushq %rax\n");

    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n"
        "popq %0\n"
        "ret\n"
        ""
        :
        : "a"(EnterCriticalSection_impl)
        : "rcx", "rdi");
}

void DeleteCriticalSection_impl(void* lpCriticalSection)
{
    printf("(not implemented) DeleteCriticalSection(lpCriticalSection=%p)\n", lpCriticalSection);
}

EXPORT __attribute__((naked)) void DeleteCriticalSection()
{
    asm("pushq %rax\n");

    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n"
        "popq %0\n"
        "ret\n"
        ""
        :
        : "a"(DeleteCriticalSection_impl)
        : "rcx", "rdi");
}

void LeaveCriticalSection_impl(void* lpCriticalSection)
{
    printf("(not implemented) LeaveCriticalSection(lpCriticalSection=%p)\n", lpCriticalSection);
}

EXPORT __attribute__((naked)) void LeaveCriticalSection()
{
    asm("pushq %rax\n");

    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n"
        "popq %0\n"
        "ret\n"
        ""
        :
        : "a"(LeaveCriticalSection_impl)
        : "rcx", "rdi");
}

void InitializeCriticalSection_impl(void* lpCriticalSection)
{
    printf("(not implemented) InitializeCriticalSection(lpCriticalSection=%p)\n", lpCriticalSection);
}

EXPORT __attribute__((naked)) void InitializeCriticalSection()
{
    asm("pushq %rax\n");

    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n"
        "popq %0\n"
        "ret\n"
        ""
        :
        : "a"(InitializeCriticalSection_impl)
        : "rcx", "rdi");
}

void* SetUnhandledExceptionFilter_impl(void* lpTopLevelExceptionFilter)
{
    printf("(not implemented) SetUnhandledExceptionFilter(lpTopLevelExceptionFilter=%p)\n", lpTopLevelExceptionFilter);
    return nullptr;
}

EXPORT __attribute__((naked)) void SetUnhandledExceptionFilter()
{
    asm("pushq %rdi\n");
    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n"
        "popq %%rdi\n"
        "ret\n"
        ""
        :
        : "a"(SetUnhandledExceptionFilter_impl)
        : "rcx", "rdi");
}

SIZE_T VirtualQuery_impl(const void* lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
{
    printf("VirtualQuery(lpAddress=%p, lpBuffer=%p, dwLength=%zu)\n", lpAddress, lpBuffer, dwLength);
    vm_size_t size = 0;
    vm_region_flavor_t flavor = VM_REGION_BASIC_INFO_64;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = 0;
    kern_return_t kret = vm_region_64(current_task(), reinterpret_cast<vm_address_t*>(&lpAddress), &size, flavor, (vm_region_info_64_t)&info, &count, &object);
    printf("\tkret: %d (%s)\n", kret, mach_error_string(kret));
    if (kret == KERN_SUCCESS)
    {
        printf("\toffset = 0x%llx\n", info.offset);
        printf("\tsize = 0x%lx\n", size);
        lpBuffer->AllocationBase = reinterpret_cast<PVOID>(reinterpret_cast<uintptr_t>(lpAddress) - info.offset);
        lpBuffer->AllocationProtect = info.protection;
        lpBuffer->BaseAddress = lpBuffer->AllocationBase;
        lpBuffer->Protect = info.protection;
        lpBuffer->RegionSize = size;
        lpBuffer->State = 0x1000; // MEM_COMMIT
        lpBuffer->Type = 0x40000 | 0x20000; // MEM_MAPPED | MEM_PRIVATE
    }
    else
    {
        return 0;
    }
    return sizeof(MEMORY_BASIC_INFORMATION);
}

EXPORT __attribute__((naked)) void VirtualQuery()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "movq %%r8, %%rdx\n"
        "callq *%0\n"
        :
        : "r"(VirtualQuery_impl)
        : "rcx", "rdi");
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

bool VirtualProtect_impl(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect)
{
    printf("(not implemented) VirtualProtect(lpAddress=%p, dwSize=%zu, flNewProtect=0x%x, lpflOldProtect=%p)\n", lpAddress, dwSize, flNewProtect, lpflOldProtect);
    return true;
}

EXPORT __attribute__((naked)) void VirtualProtect()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "movq %%r8, %%rdx\n"
        "movq %%r9, %%rcx\n"
        "callq *%0\n"
        :
        : "r"(VirtualProtect_impl)
        : "rcx", "rdi");
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

DWORD last_error = 0;
EXPORT DWORD GetLastError()
{
    return last_error;
}

void __memcpy_kernel32_startup_impl(void* dst, const void* src, size_t size)
{
    printf("__memcpy_kernel32_startup_impl\n");
    char* buf = new char[size];
    for (size_t i = 0; i < size; ++i)
    {
        buf[i] = reinterpret_cast<char*>(dst)[i];
    }
    for (size_t i = 0; i < size; ++i)
    {
        reinterpret_cast<char*>(dst)[i] = reinterpret_cast<const char*>(src)[i];
    }
    for (size_t i = 0; i < size; ++i)
    {
        const_cast<char*>(reinterpret_cast<const char*>(src))[i] = buf[i];
    }
    delete[] buf;
}

void* GetStdHandle_impl(DWORD nStdHandle)
{
    printf("(not implemented) GetStdHandle(nStdHandle=%d)\n", static_cast<signed int>(nStdHandle));
    return reinterpret_cast<void*>(0xdeadfacefeedbeef);
}

 EXPORT __attribute__((naked)) void GetStdHandle()
 {
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n"
        :
        : "r"(GetStdHandle_impl)
        :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
 }

 BOOL ReadConsoleOutputA_impl(void* hConsoleOutput, PCHAR_INFO lpBuffer, COORD dwBufferSize, COORD dwBufferCoord, PSMALL_RECT lpReadRegion)
 {
    printf("(not implemented) ReadConsoleOutputA\n");
    return true;
 }

 EXPORT __attribute__((naked)) void ReadConsoleOutputA()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "movq %%r8, %%rdx\n"
        "movq %%r9, %%rcx\n"
        "callq *%0\n"
        :
        : "r"(ReadConsoleOutputA_impl)
        :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

BOOL GetConsoleCursorInfo_impl(void* hConsoleOutput, PCONSOLE_CURSOR_INFO lpConsoleCursorInfo)
{
    printf("GetConsoleCursorInfo(hConsoleOutput=%p, lpConsoleCursorInfo=%p)\n", hConsoleOutput, lpConsoleCursorInfo);
    CONSOLE_CURSOR_INFO cursorInfo;
    cursorInfo.dwSize = 100;
    cursorInfo.bVisible = true;
    *lpConsoleCursorInfo = cursorInfo;
    return true;
}

EXPORT __attribute__((naked)) void GetConsoleCursorInfo()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "callq *%0\n"
        :
        : "r"(GetConsoleCursorInfo_impl)
        :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

BOOL SetConsoleCursorInfo_impl(void* hConsoleOutput, const PCONSOLE_CURSOR_INFO lpConsoleCursorInfo)
{
    printf("SetConsoleCursorInfo(hConsoleOutput=%p, lpConsoleCursorInfo.dwSize=%d, lpConsoleCursorInfo.bVisible=%d)\n", hConsoleOutput, lpConsoleCursorInfo->dwSize, lpConsoleCursorInfo->bVisible);
    #define CSI "\e["
    if (lpConsoleCursorInfo->bVisible)
    {
        fputs(CSI "?25h", stdout);
    }
    else
    {
        fputs(CSI "?25l", stdout);
    }
    #undef CSI

    return true;
}

EXPORT __attribute__((naked)) void SetConsoleCursorInfo()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "callq *%0\n"
        :
        : "r"(SetConsoleCursorInfo_impl)
        :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

BOOL SetConsoleScreenBufferSize_impl(void* hConsoleOutput, COORD dwSize)
{
    printf("SetConsoleScreenBufferSize_impl(hConsoleOutput=%p, dwSize={%d, %d})\n", hConsoleOutput, dwSize.X, dwSize.Y);
    printf("\e[8;%d;%dt", dwSize.Y, dwSize.X);
    return true;
}

EXPORT __attribute__((naked)) void SetConsoleScreenBufferSize()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "callq *%0\n"
        :
        : "r"(SetConsoleScreenBufferSize_impl)
        :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

BOOL SetConsoleWindowInfo_impl(void* hConsoleOutput, BOOL bAbsolute, const SMALL_RECT* lpConsoleWindow)
{
    printf("SetConsoleWindowInfo(hConsoleOutput=%p, hAbsolute=%d, lpConsoleWindow=%p)\n", hConsoleOutput, (int)bAbsolute, lpConsoleWindow);
    printf("\tL=%d, R=%d, T=%d, B=%d\n", lpConsoleWindow->Left, lpConsoleWindow->Right, lpConsoleWindow->Top, lpConsoleWindow->Bottom);
    COORD dwSize = {.X = static_cast<SHORT>(lpConsoleWindow->Right - lpConsoleWindow->Left), .Y = static_cast<SHORT>(lpConsoleWindow->Bottom - lpConsoleWindow->Top)};
    printf("\e[8;%d;%dt", dwSize.Y, dwSize.X);
    return true;
}

EXPORT __attribute__((naked)) void SetConsoleWindowInfo()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "movq %%r8, %%rdx\n"
        "callq *%0\n"
        :
        : "r"(SetConsoleWindowInfo_impl)
        :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

BOOL WriteConsoleOutputA_impl(void* hConsoleOutput, const CHAR_INFO* lpBuffer, COORD dwBufferSize, COORD dwBufferCoord, PSMALL_RECT lpWriteRegion)
{
    printf("\x1B[%d;%dH", lpWriteRegion->Top, lpWriteRegion->Left);
    for (size_t i = 0; i < dwBufferSize.X * dwBufferSize.Y; ++i)
    {
        if (i % dwBufferSize.X == 0 && i > 0)
        {
            printf("\n");
        }
        CHAR ch = lpBuffer[i].Char.AsciiChar;
        if (cp437.find(ch) != cp437.end())
            printf("%s", cp437[ch]);
        else
            printf("%c", ch);
    }
    return true;
}

EXPORT __attribute__((naked)) void WriteConsoleOutputA()
{
    asm("movq 0x28(%rsp), %rax\n");
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "movq %%r8, %%rdx\n"
        "movq %%r9, %%rcx\n"
        "movq %%rax, %%r8\n"
        "callq *%0\n"
        :
        : "r"(WriteConsoleOutputA_impl)
        :"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9");
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

uint64_t header_addr = -1;
EXPORT uint64_t ___get_header()
{
    return header_addr;
}

void GetSystemTimeAsFileTime_impl(uint64_t* lpSystemTimeAsFileTime)
{
    printf("GetSystemTimeAsFileTime(%p)\n", lpSystemTimeAsFileTime);
    time_t t = time(nullptr);
    printf(" return = %ld\n", t);
}

EXPORT __attribute__((naked)) void GetSystemTimeAsFileTime()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n"
        :
        : "r"(GetSystemTimeAsFileTime_impl)
        :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

EXPORT DWORD GetCurrentThreadId()
{
    printf("(not implemented) GetCurrentThreadId()\n");
    return 1;
}

EXPORT DWORD GetCurrentProcessId()
{
    printf("(not implemented) GetCurrentProcessId()\n");
    return 1;
}

BOOL QueryPerformanceCounter_impl(int64_t *lpPerformanceCount)
{
    printf("QueryPerformanceCounter(%p)\n", lpPerformanceCount);
    timespec tp;
    BOOL result = 0;
    if (clock_gettime(CLOCK_MONOTONIC, &tp) == -1)
    {
        perror("QueryPerformanceCounter: clock_gettime failed: ");
    }
    else
    {
        result = 1;
        long calculation = tp.tv_sec * 1'000'000'000 + tp.tv_nsec;
        *lpPerformanceCount = calculation;
        printf(" %ld\n", calculation);
    }
    return result;
}

EXPORT __attribute__((naked)) void QueryPerformanceCounter()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n"
        :
        : "r"(QueryPerformanceCounter_impl)
        :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

void* LoadLibraryExW_impl(const char16_t* lpLibFileName, void* hFile, DWORD dwFlags)
{
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>,char16_t> cvt;
    std::string file_name = cvt.to_bytes(lpLibFileName);
    printf("LoadLibraryExW(%s, %p, %u)\n", file_name.c_str(), hFile, dwFlags);

    if (file_name.starts_with("api-ms-win") || file_name == "kernel32")
    {
        printf(" returning kernel32 handle\n");
        return (void*)1;
    }

    printf(" returning null\n");
    return nullptr;
}

EXPORT __attribute__((naked)) void LoadLibraryExW()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "movq %%r8, %%rdx\n"
        "callq *%0\n"
        :
        : "r"(LoadLibraryExW_impl)
        :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

void* GetProcAddress_impl(void* hModule, const char* lpProcName)
{
    printf("(not implemented) GetProcAddress(%p, %s)\n", hModule, lpProcName);
    return nullptr;
}

EXPORT __attribute__((naked)) void GetProcAddress()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "movq %%rdx, %%rsi\n"
        "callq *%0\n"
        :
        : "r"(GetProcAddress_impl)
        :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

__attribute__((constructor)) void start()
{
    printf("kernel32 starting!\n");
    #define IMPORT_ENTRY(name) {#name, reinterpret_cast<uintptr_t>(name)}
    const std::map<std::string, uintptr_t> import_name_to_fn = {
        IMPORT_ENTRY(Sleep), IMPORT_ENTRY(ExitProcess), IMPORT_ENTRY(EnterCriticalSection), IMPORT_ENTRY(DeleteCriticalSection),
        IMPORT_ENTRY(LeaveCriticalSection), IMPORT_ENTRY(GetLastError), IMPORT_ENTRY(InitializeCriticalSection), IMPORT_ENTRY(SetUnhandledExceptionFilter),
        IMPORT_ENTRY(VirtualQuery), IMPORT_ENTRY(VirtualProtect), IMPORT_ENTRY(GetStdHandle), IMPORT_ENTRY(ReadConsoleOutputA), IMPORT_ENTRY(GetConsoleCursorInfo),
        IMPORT_ENTRY(SetConsoleCursorInfo), IMPORT_ENTRY(SetConsoleScreenBufferSize), IMPORT_ENTRY(SetConsoleWindowInfo), IMPORT_ENTRY(WriteConsoleOutputA),
        IMPORT_ENTRY(GetSystemTimeAsFileTime), IMPORT_ENTRY(GetCurrentThreadId), IMPORT_ENTRY(GetCurrentProcessId), IMPORT_ENTRY(QueryPerformanceCounter),
        IMPORT_ENTRY(LoadLibraryExW), IMPORT_ENTRY(GetProcAddress),
    };
    #undef IMPORT_ENTRY

    const struct section_64* header_cmd = getsectbyname("__TEXT", "___header");
    if (!header_cmd)
    {
        printf("kernel32 error: could not find section ___header, exiting\n");
        std::exit(1);
    }
    const struct section_64* entry_cmd = getsectbyname("__TEXT", "___entry");
    if (!entry_cmd)
    {
        printf("kernel32 error: could not find section ___entry, exiting\n");
        std::exit(1);
    }

    if (entry_cmd->size != 61)
    {
        throw std::runtime_error("custom entry code size has changed -- update kernel32 to work with the new code");
    }

    header_addr = header_cmd->addr;
    uint32_t memcpy_offset = reinterpret_cast<uintptr_t>(__memcpy_kernel32_startup_impl) - (entry_cmd->addr + 0x1e) - 5;
    printf("kernel32: patching memcpy into entry\n");
    memcpy(reinterpret_cast<void*>(entry_cmd->addr + 0x1f), &memcpy_offset, sizeof(memcpy_offset));
    
    constexpr int exe_image_index = 0;
    uintptr_t exe_base = reinterpret_cast<uintptr_t>(_dyld_get_image_header(exe_image_index));
    uintptr_t exe_slide = _dyld_get_image_vmaddr_slide(exe_image_index);
    printf ("image %d: %p\t%s\t(slide = 0x%lx)\n", exe_image_index,
    reinterpret_cast<void*>(exe_base),
    _dyld_get_image_name(exe_image_index),
    exe_slide);

    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)header_addr;
    __IMAGE_NT_HEADERS64* nt_header = (__IMAGE_NT_HEADERS64*)(header_addr + dos_header->e_lfanew);
    uintptr_t import_addr = exe_base + nt_header->OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    printf("kernel32: parsing imports\n");
    printf(" import_addr %lx\n", import_addr);

    for (IMAGE_IMPORT_DESCRIPTOR* import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(import_addr + exe_slide);
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
                    const char msg1[] = "*** unimplemented kernel32 function: ";
                    char* unimplemented_fn_msg = (char*)mmap(nullptr, 256, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
                    if ((intptr_t)unimplemented_fn_msg == -1)
                    {
                        perror("mmap failed");
                        std::exit(1);
                    }
                    memset(unimplemented_fn_msg, 0, 256);
                    strcpy(unimplemented_fn_msg, msg1);
                    strcpy(unimplemented_fn_msg + strlen(msg1), (import_fn_name + " : return address %p\n").c_str());

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

                    // Do the necessary patching
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

    printf("kernel32: DONE!\n");
}