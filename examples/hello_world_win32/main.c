#include <Windows.h>

int main() {
    const char message[] = "Hello, world!";
    HANDLE output_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!WriteConsoleA(output_handle, message, strlen(message), NULL, NULL)) {
        ExitProcess(10);
    }
    ExitProcess(42);
}