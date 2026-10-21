#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

static volatile LONG64 calls = 0;
static ULONGLONG deadline;
__declspec(dllexport) volatile unsigned char fixture_marker[32] = "WX_LAB_OWN_FIXTURE_ONLY";

__declspec(dllexport) __attribute__((noinline)) LONG64 probe_tick(LONG64 value) {
    InterlockedIncrement64(&calls);
    return value + 7;
}

static DWORD WINAPI worker(void *unused) {
    (void)unused;
    LONG64 value = 0;
    while (GetTickCount64() < deadline) {
        value = probe_tick(value);
        Sleep(1);
    }
    return 0;
}

int main(int argc, char **argv) {
    DWORD seconds = argc > 1 ? (DWORD)strtoul(argv[1], NULL, 10) : 30;
    if (seconds < 5 || seconds > 90) return 2;
    HANDLE threads[4];
    deadline = GetTickCount64() + seconds * 1000ULL;
    for (int i = 0; i < 4; ++i) {
        threads[i] = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        if (!threads[i]) return 3;
    }
    printf("ready\n"); fflush(stdout);
    WaitForMultipleObjects(4, threads, TRUE, INFINITE);
    for (int i = 0; i < 4; ++i) CloseHandle(threads[i]);
    printf("{\"calls\":%ld,\"completed\":true}\n", (long)calls);
    return 0;
}
