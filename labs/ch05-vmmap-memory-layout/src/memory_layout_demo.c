#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

static volatile LONG g_stop;

static DWORD WINAPI worker_thread(LPVOID arg)
{
    (void)arg;
    printf("[worker] tid=%lu stack active\n", GetCurrentThreadId());
    fflush(stdout);

    while (InterlockedCompareExchange(&g_stop, 0, 0) == 0) {
        Sleep(500);
    }

    return 0;
}

int main(void)
{
    char temp_path[MAX_PATH];
    char file_path[MAX_PATH];
    HANDLE file_handle = INVALID_HANDLE_VALUE;
    HANDLE mapping_handle = NULL;
    HANDLE thread_handle = NULL;
    void *heap_block = NULL;
    void *private_block = NULL;
    void *mapped_view = NULL;
    DWORD thread_id = 0;

    printf("[lab] pid=%lu\n", GetCurrentProcessId());

    heap_block = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024);
    if (heap_block == NULL) {
        fprintf(stderr, "HeapAlloc failed\n");
        return 1;
    }

    private_block = VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (private_block == NULL) {
        fprintf(stderr, "VirtualAlloc failed: error=%lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, heap_block);
        return 1;
    }

    GetTempPathA((DWORD)sizeof(temp_path), temp_path);
    snprintf(file_path, sizeof(file_path), "%sInternalsNoteBookMemoryLayout.bin", temp_path);

    file_handle = CreateFileA(
        file_path,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
        NULL);

    if (file_handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateFileA failed: error=%lu\n", GetLastError());
        VirtualFree(private_block, 0, MEM_RELEASE);
        HeapFree(GetProcessHeap(), 0, heap_block);
        return 1;
    }

    SetFilePointer(file_handle, 1024 * 1024 - 1, NULL, FILE_BEGIN);
    SetEndOfFile(file_handle);

    mapping_handle = CreateFileMappingA(file_handle, NULL, PAGE_READWRITE, 0, 1024 * 1024, NULL);
    if (mapping_handle == NULL) {
        fprintf(stderr, "CreateFileMappingA failed: error=%lu\n", GetLastError());
        CloseHandle(file_handle);
        VirtualFree(private_block, 0, MEM_RELEASE);
        HeapFree(GetProcessHeap(), 0, heap_block);
        return 1;
    }

    mapped_view = MapViewOfFile(mapping_handle, FILE_MAP_WRITE, 0, 0, 0);
    if (mapped_view == NULL) {
        fprintf(stderr, "MapViewOfFile failed: error=%lu\n", GetLastError());
        CloseHandle(mapping_handle);
        CloseHandle(file_handle);
        VirtualFree(private_block, 0, MEM_RELEASE);
        HeapFree(GetProcessHeap(), 0, heap_block);
        return 1;
    }

    thread_handle = CreateThread(NULL, 0, worker_thread, NULL, 0, &thread_id);
    if (thread_handle == NULL) {
        fprintf(stderr, "CreateThread failed: error=%lu\n", GetLastError());
        UnmapViewOfFile(mapped_view);
        CloseHandle(mapping_handle);
        CloseHandle(file_handle);
        VirtualFree(private_block, 0, MEM_RELEASE);
        HeapFree(GetProcessHeap(), 0, heap_block);
        return 1;
    }

    printf("[lab] heap_block=%p size=1MB\n", heap_block);
    printf("[lab] private_block=%p size=1MB protection=PAGE_READWRITE\n", private_block);
    printf("[lab] mapped_view=%p file=%s\n", mapped_view, file_path);
    printf("[lab] worker_tid=%lu\n", thread_id);
    printf("[lab] inspect with VMMap now, then press Enter to exit\n");

    getchar();
    InterlockedExchange(&g_stop, 1);
    WaitForSingleObject(thread_handle, 2000);

    CloseHandle(thread_handle);
    UnmapViewOfFile(mapped_view);
    CloseHandle(mapping_handle);
    CloseHandle(file_handle);
    VirtualFree(private_block, 0, MEM_RELEASE);
    HeapFree(GetProcessHeap(), 0, heap_block);

    printf("[lab] cleaned up\n");
    return 0;
}

