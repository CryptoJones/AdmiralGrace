// Windows prototypes; the types they name are in libc.
//
// The `#[ordinal(N)]` numbers are kernel32's on 64-bit Windows 10 and 11
// (they match wine's kernel32.dll export table); an image that imports one
// of these by number rather than by name takes the prototype beside it.


#[ordinal(115)] HANDLE CreateFileA(LPCSTR name, DWORD access, DWORD share, LPVOID security, DWORD disposition, DWORD flags, HANDLE templ);
#[ordinal(946)] BOOL ReadFile(HANDLE file, LPVOID buf /* size: 3 */, DWORD count, DWORD *read, LPVOID overlapped);
#[ordinal(1310)] BOOL WriteFile(HANDLE file, const void *buf, DWORD count, DWORD *written, LPVOID overlapped);
#[ordinal(62)] BOOL CloseHandle(HANDLE handle);
#[ordinal(490)] DWORD GetLastError(void);
#[ordinal(1253)] LPVOID VirtualAlloc(LPVOID address, SIZE_T size, DWORD type, DWORD protect);
#[ordinal(1257)] BOOL VirtualFree(LPVOID address, SIZE_T size, DWORD type);
#[ordinal(570)] HANDLE GetProcessHeap(void);
#[ordinal(706)] LPVOID HeapAlloc(HANDLE heap, DWORD flags, SIZE_T size);
#[ordinal(712)] BOOL HeapFree(HANDLE heap, DWORD flags, LPVOID p);
#[ordinal(818)] HMODULE LoadLibraryA(LPCSTR name);
#[ordinal(508)] HMODULE GetModuleHandleA(LPCSTR name);
#[ordinal(564)] void *GetProcAddress(HMODULE module, LPCSTR name);
#[ordinal(1198)] void Sleep(DWORD milliseconds);
#[ordinal(262)] void ExitProcess(UINT code);
#[ordinal(649)] DWORD GetTickCount(void);
#[ordinal(1356)] int lstrlenA(LPCSTR s);
