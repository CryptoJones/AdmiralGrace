// windows/x86-64 and windows/x86: the Windows SDK type names images
// import and name in their data, LLP64 at 64 bits and ILP32 at 32 —
// HANDLE and friends are pointers where the SDK says so, DWORD is 4,
// SIZE_T is the pointer's width. Where the builtin type libraries (#376)
// already know a name, the platform keeps its own definition here, so
// the platform's types are whole without them; the project's definition
// still wins over both.

typedef void *HANDLE;
typedef void *HMODULE;
typedef void *HINSTANCE;
typedef void *HWND;
typedef void *LPVOID;
typedef void *PVOID;
typedef void *LPSTR;
typedef char *LPCSTR;
typedef unsigned char *LPBYTE;
typedef unsigned char *PBYTE;
typedef int BOOL;
typedef unsigned int UINT;
typedef unsigned int DWORD;
typedef unsigned long long SIZE_T;
typedef unsigned long long ULONGLONG;
typedef unsigned int ULONG;
typedef int LONG;
typedef short WORD;
typedef unsigned short DWORD16;
typedef unsigned short USHORT;
typedef short SHORT;
typedef unsigned char BYTE;
typedef unsigned char UCHAR;
typedef char CHAR;
typedef unsigned char *PSTR;
typedef unsigned char *PCSTR;
typedef wchar_t WCHAR;
typedef wchar_t *LPWSTR;
typedef wchar_t *LPCWSTR;
typedef long long LONGLONG;
typedef unsigned long long DWORDLONG;

struct SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

struct OVERLAPPED {
    DWORD Internal;
    DWORD InternalHigh;
    DWORD Offset;
    DWORD OffsetHigh;
    HANDLE hEvent;
};

struct WIN32_FIND_DATAA {
    DWORD dwFileAttributes;
    long long ftCreationTime;
    long long ftLastAccessTime;
    long long ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    CHAR cFileName[260];
    CHAR cAlternateFileName[14];
};

typedef struct WIN32_FIND_DATAA WIN32_FIND_DATAA;
typedef struct WIN32_FIND_DATAA *LPWIN32_FIND_DATAA;

struct STARTUPINFOA {
    DWORD cb;
    LPSTR lpReserved;
    LPSTR lpDesktop;
    LPSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

struct PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
};

enum {
    INVALID_HANDLE_VALUE = -1,
    ERROR_SUCCESS = 0,
    ERROR_FILE_NOT_FOUND = 2,
    ERROR_ACCESS_DENIED = 5,
};
