#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

static const wchar_t *EVENT_NAME = L"Local\\InternalsNoteBook_ObjectLab_Event";
static const wchar_t *MUTEX_NAME = L"Local\\InternalsNoteBook_ObjectLab_Mutex";

int main(void)
{
    HANDLE event_handle;
    HANDLE mutex_handle;
    DWORD mutex_error;

    event_handle = CreateEventW(NULL, TRUE, FALSE, EVENT_NAME);
    if (event_handle == NULL) {
        fprintf(stderr, "CreateEventW failed: error=%lu\n", GetLastError());
        return 1;
    }

    mutex_handle = CreateMutexW(NULL, FALSE, MUTEX_NAME);
    mutex_error = GetLastError();
    if (mutex_handle == NULL) {
        fprintf(stderr, "CreateMutexW failed: error=%lu\n", mutex_error);
        CloseHandle(event_handle);
        return 1;
    }

    printf("[lab] pid=%lu\n", GetCurrentProcessId());
    printf("[lab] event=Local\\InternalsNoteBook_ObjectLab_Event\n");
    printf("[lab] mutex=Local\\InternalsNoteBook_ObjectLab_Mutex\n");

    if (mutex_error == ERROR_ALREADY_EXISTS) {
        printf("[lab] mutex already existed before this process opened it\n");
    } else {
        printf("[lab] mutex created by this process\n");
    }

    printf("[lab] inspect with WinObj, Handle, or Process Explorer now\n");
    printf("[lab] press Enter to close handles and exit\n");
    getchar();

    CloseHandle(mutex_handle);
    CloseHandle(event_handle);

    printf("[lab] handles closed\n");
    return 0;
}

