#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

static CRITICAL_SECTION g_cs1;
static CRITICAL_SECTION g_cs2;

static DWORD WINAPI thread_a(LPVOID arg)
{
    (void)arg;
    printf("[thread-a] tid=%lu acquiring cs1\n", GetCurrentThreadId());
    EnterCriticalSection(&g_cs1);
    printf("[thread-a] acquired cs1, sleeping before cs2\n");
    Sleep(500);
    printf("[thread-a] attempting cs2\n");
    EnterCriticalSection(&g_cs2);

    LeaveCriticalSection(&g_cs2);
    LeaveCriticalSection(&g_cs1);
    return 0;
}

static DWORD WINAPI thread_b(LPVOID arg)
{
    (void)arg;
    printf("[thread-b] tid=%lu acquiring cs2\n", GetCurrentThreadId());
    EnterCriticalSection(&g_cs2);
    printf("[thread-b] acquired cs2, sleeping before cs1\n");
    Sleep(500);
    printf("[thread-b] attempting cs1\n");
    EnterCriticalSection(&g_cs1);

    LeaveCriticalSection(&g_cs1);
    LeaveCriticalSection(&g_cs2);
    return 0;
}

int main(void)
{
    HANDLE a;
    HANDLE b;
    DWORD tid_a = 0;
    DWORD tid_b = 0;

    InitializeCriticalSection(&g_cs1);
    InitializeCriticalSection(&g_cs2);

    printf("[main] pid=%lu\n", GetCurrentProcessId());
    a = CreateThread(NULL, 0, thread_a, NULL, 0, &tid_a);
    b = CreateThread(NULL, 0, thread_b, NULL, 0, &tid_b);

    if (a == NULL || b == NULL) {
        fprintf(stderr, "CreateThread failed: error=%lu\n", GetLastError());
        return 1;
    }

    printf("[main] thread-a tid=%lu\n", tid_a);
    printf("[main] thread-b tid=%lu\n", tid_b);
    printf("[main] waiting; process should deadlock shortly\n");

    WaitForSingleObject(a, INFINITE);
    WaitForSingleObject(b, INFINITE);

    CloseHandle(a);
    CloseHandle(b);
    DeleteCriticalSection(&g_cs1);
    DeleteCriticalSection(&g_cs2);
    return 0;
}

