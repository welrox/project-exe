#include <cstdint>

extern "C" void Sleep(int32_t milliseconds);
extern "C" void ExitProcess(unsigned int exit_code);

int main()
{
    Sleep(69420);
    ExitProcess(42);
}