#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

static HANDLE g_event;
static volatile LONG g_stop;

static void set_thread_description_if_available(const wchar_t *description)
{
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (kernel32 == NULL) {
        return;
    }

    typedef HRESULT (WINAPI *SetThreadDescriptionFn)(HANDLE, PCWSTR);
    FARPROC proc = GetProcAddress(kernel32, "SetThreadDescription");
    SetThreadDescriptionFn set_description = NULL;

    if (proc != NULL) {
        memcpy(&set_description, &proc, sizeof(set_description));
        (void)set_description(GetCurrentThread(), description);
    }
}

static DWORD WINAPI event_waiter(LPVOID arg)
{
    (void)arg;
    set_thread_description_if_available(L"event-waiter");
    printf("[event-waiter] tid=%lu waiting on manual-reset event\n", GetCurrentThreadId());
    fflush(stdout);

    WaitForSingleObject(g_event, INFINITE);
    printf("[event-waiter] released\n");
    return 0;
}

static DWORD WINAPI alertable_sleeper(LPVOID arg)
{
    (void)arg;
    set_thread_description_if_available(L"alertable-sleeper");
    printf("[alertable-sleeper] tid=%lu entering SleepEx(INFINITE, TRUE)\n", GetCurrentThreadId());
    fflush(stdout);

    while (InterlockedCompareExchange(&g_stop, 0, 0) == 0) {
        SleepEx(1000, TRUE);
    }

    printf("[alertable-sleeper] released\n");
    return 0;
}

static DWORD WINAPI delay_sleeper(LPVOID arg)
{
    (void)arg;
    set_thread_description_if_available(L"delay-sleeper");
    printf("[delay-sleeper] tid=%lu entering repeated Sleep(1000)\n", GetCurrentThreadId());
    fflush(stdout);

    while (InterlockedCompareExchange(&g_stop, 0, 0) == 0) {
        Sleep(1000);
    }

    printf("[delay-sleeper] released\n");
    return 0;
}

static HANDLE create_worker(LPTHREAD_START_ROUTINE start_routine, const char *role)
{
    DWORD tid = 0;
    HANDLE thread = CreateThread(NULL, 0, start_routine, NULL, 0, &tid);
    if (thread == NULL) {
        fprintf(stderr, "CreateThread failed for %s: error=%lu\n", role, GetLastError());
        return NULL;
    }

    printf("[main] created %-18s tid=%lu\n", role, tid);
    return thread;
}

int main(void)
{
    HANDLE threads[3];

    g_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_event == NULL) {
        fprintf(stderr, "CreateEventW failed: error=%lu\n", GetLastError());
        return 1;
    }

    set_thread_description_if_available(L"main-console-wait");

    printf("[main] process id: %lu\n", GetCurrentProcessId());
    printf("[main] press Enter after collecting Process Explorer / WinDbg evidence\n");

    threads[0] = create_worker(event_waiter, "event-waiter");
    threads[1] = create_worker(alertable_sleeper, "alertable-sleeper");
    threads[2] = create_worker(delay_sleeper, "delay-sleeper");

    if (threads[0] == NULL || threads[1] == NULL || threads[2] == NULL) {
        SetEvent(g_event);
        CloseHandle(g_event);
        return 1;
    }

    getchar();

    printf("[main] signaling event-waiter and requesting sleepers to stop\n");
    InterlockedExchange(&g_stop, 1);
    SetEvent(g_event);

    WaitForMultipleObjects(3, threads, TRUE, 3000);

    CloseHandle(threads[0]);
    CloseHandle(threads[1]);
    CloseHandle(threads[2]);
    CloseHandle(g_event);

    return 0;
}
