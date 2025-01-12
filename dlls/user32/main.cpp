#include <iostream>
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
#include <Carbon/Carbon.h>
#include "../../pe.h"
#include "../../vkeycodes.h"
#include "../asm.h"
#define EXPORT extern "C" __attribute__((visibility("default")))

std::map<int, int> vk = {
    {VK_KEY_A, kVK_ANSI_A},
    {VK_KEY_S, kVK_ANSI_S},
    {VK_KEY_D, kVK_ANSI_D},
    {VK_KEY_F, kVK_ANSI_F},
    {VK_KEY_H, kVK_ANSI_H},
    {VK_KEY_G, kVK_ANSI_G},
    {VK_KEY_Z, kVK_ANSI_Z},
    {VK_KEY_X, kVK_ANSI_X},
    {VK_KEY_C, kVK_ANSI_C},
    {VK_KEY_V, kVK_ANSI_V},
    {VK_KEY_B, kVK_ANSI_B},
    {VK_KEY_Q, kVK_ANSI_Q},
    {VK_KEY_W, kVK_ANSI_W},
    {VK_KEY_E, kVK_ANSI_E},
    {VK_KEY_R, kVK_ANSI_R},
    {VK_KEY_Y, kVK_ANSI_Y},
    {VK_KEY_T, kVK_ANSI_T},
    {VK_KEY_1, kVK_ANSI_1},
    {VK_KEY_2, kVK_ANSI_2},
    {VK_KEY_3, kVK_ANSI_3},
    {VK_KEY_4, kVK_ANSI_4},
    {VK_KEY_6, kVK_ANSI_6},
    {VK_KEY_5, kVK_ANSI_5},
    {VK_OEM_PLUS, kVK_ANSI_Equal},
    {VK_KEY_9, kVK_ANSI_9},
    {VK_KEY_7, kVK_ANSI_7},
    {VK_OEM_MINUS, kVK_ANSI_Minus},
    {VK_KEY_8, kVK_ANSI_8},
    {VK_KEY_0, kVK_ANSI_0},
    {VK_OEM_4, kVK_ANSI_RightBracket},
    {VK_KEY_O, kVK_ANSI_O},
    {VK_KEY_U, kVK_ANSI_U},
    {VK_OEM_6, kVK_ANSI_LeftBracket},
    {VK_KEY_I, kVK_ANSI_I},
    {VK_KEY_P, kVK_ANSI_P},
    {VK_KEY_L, kVK_ANSI_L},
    {VK_KEY_J, kVK_ANSI_J},
    {VK_OEM_7, kVK_ANSI_Quote},
    {VK_KEY_K, kVK_ANSI_K},
    {VK_OEM_1, kVK_ANSI_Semicolon},
    {VK_OEM_5, kVK_ANSI_Backslash},
    {VK_OEM_COMMA, kVK_ANSI_Comma},
    {VK_OEM_2, kVK_ANSI_Slash},
    {VK_KEY_N, kVK_ANSI_N},
    {VK_KEY_M, kVK_ANSI_M},
    {VK_OEM_PERIOD, kVK_ANSI_Period},
    {VK_OEM_3, kVK_ANSI_Grave},
    {VK_DECIMAL, kVK_ANSI_KeypadDecimal},
    {VK_MULTIPLY, kVK_ANSI_KeypadMultiply},
    {VK_ADD, kVK_ANSI_KeypadPlus},
    {VK_CLEAR, kVK_ANSI_KeypadClear},
    {VK_DIVIDE, kVK_ANSI_KeypadDivide},
    {VK_SUBTRACT, kVK_ANSI_KeypadMinus},
    {VK_NUMPAD0, kVK_ANSI_Keypad0},
    {VK_NUMPAD1, kVK_ANSI_Keypad1},
    {VK_NUMPAD2, kVK_ANSI_Keypad2},
    {VK_NUMPAD3, kVK_ANSI_Keypad3},
    {VK_NUMPAD4, kVK_ANSI_Keypad4},
    {VK_NUMPAD5, kVK_ANSI_Keypad5},
    {VK_NUMPAD6, kVK_ANSI_Keypad6},
    {VK_NUMPAD7, kVK_ANSI_Keypad7},
    {VK_NUMPAD8, kVK_ANSI_Keypad8},
    {VK_NUMPAD9, kVK_ANSI_Keypad9},
    {VK_TAB, kVK_Tab},
    {VK_SPACE, kVK_Space},
    {VK_RETURN, kVK_Return},
    {VK_BACK, kVK_Delete},
    {VK_ESCAPE, kVK_Escape},
    {VK_CONTROL, kVK_Command},
    {VK_SHIFT, kVK_Shift},
    {VK_CAPITAL, kVK_CapsLock},
    {VK_MENU, kVK_Option},
    {VK_CONTROL, kVK_Control},
    {VK_RCONTROL, kVK_RightCommand},
    {VK_RSHIFT, kVK_RightShift},
    {VK_RMENU, kVK_RightOption},
    {VK_F17, kVK_F17},
    {VK_VOLUME_UP, kVK_VolumeUp},
    {VK_VOLUME_DOWN, kVK_VolumeDown},
    {VK_VOLUME_MUTE, kVK_Mute},
    {VK_F18, kVK_F18},
    {VK_F19, kVK_F19},
    {VK_F20, kVK_F20},
    {VK_F5, kVK_F5},
    {VK_F6, kVK_F6},
    {VK_F7, kVK_F7},
    {VK_F3, kVK_F3},
    {VK_F8, kVK_F8},
    {VK_F9, kVK_F9},
    {VK_F11, kVK_F11},
    {VK_F13, kVK_F13},
    {VK_F16, kVK_F16},
    {VK_F14, kVK_F14},
    {VK_F10, kVK_F10},
    {VK_F12, kVK_F12},
    {VK_F15, kVK_F15},
    {VK_HELP, kVK_Help},
    {VK_HOME, kVK_Home},
    {VK_PRIOR, kVK_PageUp},
    {VK_DELETE, kVK_ForwardDelete},
    {VK_F4, kVK_F4},
    {VK_END, kVK_End},
    {VK_F2, kVK_F2},
    {VK_NEXT, kVK_PageDown},
    {VK_F1, kVK_F1},
    {VK_LEFT, kVK_LeftArrow},
    {VK_RIGHT, kVK_RightArrow},
    {VK_DOWN, kVK_DownArrow},
    {VK_UP, kVK_UpArrow},
};

void unimplemented_fn()
{
    void* address;
    asm("movq 8(%%rbp), %0":"=r"(address):);
    printf("*** unimplemented user32 function (return=%p)***\n", address);
}

bool GetKeyboardState_impl(BYTE* lpKeyState)
{
    printf("(not implemented) GetKeyboardState()\n");
    return true;
}

EXPORT __attribute__((naked)) void GetKeyboardState()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n": :"r"(GetKeyboardState_impl) :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

const struct section_64* header_cmd = nullptr;
uintptr_t exe_base = 0;

SHORT GetAsyncKeyState_impl(int vKey)
{
    if (vk.find(vKey) != vk.end())
    {
        // Hack: calling CGEventSourceKeyState crashes if the mach header isn't loaded,
        // so we ensure that it is loaded here
        if (*(uint32_t*)(exe_base) != MH_MAGIC_64)
        {
            memcpy((void*)exe_base, (const void*)header_cmd->addr, header_cmd->size);
        }

        SHORT result = 0x8000 * CGEventSourceKeyState(kCGEventSourceStateHIDSystemState, vk[vKey]);
        return result;
    }
    return 0;
}

EXPORT __attribute__((naked)) void GetAsyncKeyState()
{
    PUSH_ALL_REGS_EXCEPT_RAX;
    asm("movq %%rcx, %%rdi\n"
        "callq *%0\n": :"r"(GetAsyncKeyState_impl) :);
    POP_ALL_REGS_EXCEPT_RAX;
    asm("retq\n");
}

__attribute__((constructor)) void start()
{
    printf("user32 starting!\n");
    #define IMPORT_ENTRY(name) {#name, reinterpret_cast<uintptr_t>(name)}
    const std::map<std::string, uintptr_t> import_name_to_fn = {
        IMPORT_ENTRY(GetKeyboardState), IMPORT_ENTRY(GetAsyncKeyState), 
    };
    #undef IMPORT_ENTRY

    header_cmd = getsectbyname("__TEXT", "___header");
    if (!header_cmd)
    {
        printf("user32 error: could not find section ___header, exiting\n");
        std::exit(1);
    }
    
    constexpr int exe_image_index = 0;
    exe_base = reinterpret_cast<uintptr_t>(_dyld_get_image_header(exe_image_index));
    uintptr_t exe_slide = _dyld_get_image_vmaddr_slide(exe_image_index);
    printf ("image %d: %p\t%s\t(slide = 0x%lx)\n", exe_image_index,
    reinterpret_cast<void*>(exe_base),
    _dyld_get_image_name(exe_image_index),
    exe_slide);

    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)header_cmd->addr;
    __IMAGE_NT_HEADERS64* nt_header = (__IMAGE_NT_HEADERS64*)(header_cmd->addr + dos_header->e_lfanew);
    uintptr_t import_addr = exe_base + nt_header->OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    printf("user32: parsing imports\n");
    for (IMAGE_IMPORT_DESCRIPTOR* import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(import_addr + exe_slide);
    import_descriptor->OriginalFirstThunk != 0; import_descriptor++)
    {
        std::string dll_name = reinterpret_cast<char*>(exe_base + import_descriptor->Name);
        if (strcasecmp(dll_name.c_str(), "user32.dll") != 0)
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
                    printf("user32: warning: unimplemented function %s\n", import_fn_name.c_str());
                    *thunk = reinterpret_cast<uintptr_t>(unimplemented_fn);
                }
            }
        }
    }

    printf("user32: DONE!\n");
}