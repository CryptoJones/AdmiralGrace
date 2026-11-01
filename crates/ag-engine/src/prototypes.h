// The prototypes of the library functions type propagation knows
// (`ag_engine::propagate`, docs/types.md, Propagation).
//
// The file is C, read by the engine's own parser under the image's data
// model: the types first — what the prototypes name besides C's
// primitives — then one prototype a function. Every parameter is named,
// and the name is dropped. `const` is read and dropped, as everywhere.
//
// A buffer parameter whose length another argument gives carries the
// annotation `/* size: N */`, N the length's argument counted from 1, or
// `/* size: N*M */` for a count of elements of a size: a stack slot whose
// address is passed there with a constant length is made an array of that
// many bytes, `char local_48[64]` for `fgets(&local_48, 64, f)`.
//
// To teach the engine a function, add its prototype here; a name already
// here is taken once, the first. A function called under an import's or a
// stub's decoration — `strlen@plt`, `__imp_ReadFile`, `_strlen`,
// `j_strlen` — is found by its plain name. Type libraries (#376) are the
// general form of this table.

// ---- the types ------------------------------------------------------------

typedef struct _IO_FILE FILE;
typedef long off_t;
typedef long time_t;
typedef unsigned int mode_t;
typedef int pid_t;
typedef unsigned int socklen_t;
typedef int clockid_t;

struct timeval {
    long tv_sec;
    long tv_usec;
};

struct timespec {
    long tv_sec;
    long tv_nsec;
};

struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

struct sockaddr {
    unsigned short sa_family;
    char sa_data[14];
};

struct in_addr {
    unsigned int s_addr;
};

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    struct in_addr sin_addr;
    unsigned char sin_zero[8];
};

typedef void *HANDLE;
typedef void *HMODULE;
typedef void *LPVOID;
typedef int BOOL;
typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef char *LPSTR;
typedef char *LPCSTR;
typedef uintptr_t SIZE_T;

// ---- strings and memory ---------------------------------------------------

size_t strlen(const char *s);
size_t strnlen(const char *s, size_t maxlen);
char *strcpy(char *dst, const char *src);
char *strncpy(char *dst /* size: 3 */, const char *src, size_t n);
char *strcat(char *dst, const char *src);
char *strncat(char *dst, const char *src, size_t n);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);
int strcasecmp(const char *a, const char *b);
char *strchr(const char *s, int c);
char *strrchr(const char *s, int c);
char *strstr(const char *haystack, const char *needle);
char *strdup(const char *s);
char *strndup(const char *s, size_t n);
char *strtok(char *s, const char *delim);
long strtol(const char *s, char **end, int base);
unsigned long strtoul(const char *s, char **end, int base);
int atoi(const char *s);
long atol(const char *s);
void *memcpy(void *dst /* size: 3 */, const void *src /* size: 3 */, size_t n);
void *memmove(void *dst /* size: 3 */, const void *src /* size: 3 */, size_t n);
void *memset(void *s /* size: 3 */, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
void *memchr(const void *s, int c, size_t n);

// ---- standard input and output ------------------------------------------

int printf(const char *format, ...);
int fprintf(FILE *stream, const char *format, ...);
int sprintf(char *s, const char *format, ...);
int snprintf(char *s /* size: 2 */, size_t n, const char *format, ...);
int scanf(const char *format, ...);
int sscanf(const char *s, const char *format, ...);
int puts(const char *s);
int fputs(const char *s, FILE *stream);
char *fgets(char *s /* size: 2 */, int n, FILE *stream);
int putchar(int c);
int getchar(void);
int fgetc(FILE *stream);
int fputc(int c, FILE *stream);
FILE *fopen(const char *path, const char *mode);
FILE *fdopen(int fd, const char *mode);
int fclose(FILE *stream);
size_t fread(void *ptr /* size: 2*3 */, size_t size, size_t count, FILE *stream);
size_t fwrite(const void *ptr, size_t size, size_t count, FILE *stream);
int fflush(FILE *stream);
int fseek(FILE *stream, long offset, int whence);
long ftell(FILE *stream);
void perror(const char *s);

// ---- the C library besides --------------------------------------------------

void *malloc(size_t size);
void *calloc(size_t count, size_t size);
void *realloc(void *p, size_t size);
void free(void *p);
void exit(int status);
void abort(void);
char *getenv(const char *name);
int system(const char *command);
int atexit(void (*function)(void));
void qsort(void *base, size_t count, size_t size, int (*compare)(const void *, const void *));
int rand(void);
void srand(unsigned int seed);
time_t time(time_t *t);
struct tm *localtime(const time_t *t);
size_t strftime(char *s /* size: 2 */, size_t max, const char *format, const struct tm *tm);

// ---- POSIX ----------------------------------------------------------------

int open(const char *path, int flags, ...);
int close(int fd);
ssize_t read(int fd, void *buf /* size: 3 */, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
off_t lseek(int fd, off_t offset, int whence);
int unlink(const char *path);
int access(const char *path, int mode);
int mkdir(const char *path, mode_t mode);
char *getcwd(char *buf /* size: 2 */, size_t size);
ssize_t readlink(const char *path, char *buf /* size: 3 */, size_t size);
pid_t getpid(void);
pid_t fork(void);
int execve(const char *path, char **argv, char **envp);
int pipe(int *fds);
unsigned int sleep(unsigned int seconds);
int usleep(unsigned int usec);
int gettimeofday(struct timeval *tv, void *tz);
int clock_gettime(clockid_t clock, struct timespec *tp);
int nanosleep(const struct timespec *req, struct timespec *rem);
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int munmap(void *addr, size_t length);
int socket(int domain, int type, int protocol);
int bind(int fd, const struct sockaddr *addr, socklen_t len);
int connect(int fd, const struct sockaddr *addr, socklen_t len);
int listen(int fd, int backlog);
int accept(int fd, struct sockaddr *addr, socklen_t *len);
ssize_t send(int fd, const void *buf, size_t len, int flags);
ssize_t recv(int fd, void *buf /* size: 3 */, size_t len, int flags);

// ---- Windows ----------------------------------------------------------------

HANDLE CreateFileA(LPCSTR name, DWORD access, DWORD share, LPVOID security, DWORD disposition, DWORD flags, HANDLE templ);
BOOL ReadFile(HANDLE file, LPVOID buf /* size: 3 */, DWORD count, DWORD *read, LPVOID overlapped);
BOOL WriteFile(HANDLE file, const void *buf, DWORD count, DWORD *written, LPVOID overlapped);
BOOL CloseHandle(HANDLE handle);
DWORD GetLastError(void);
LPVOID VirtualAlloc(LPVOID address, SIZE_T size, DWORD type, DWORD protect);
BOOL VirtualFree(LPVOID address, SIZE_T size, DWORD type);
HANDLE GetProcessHeap(void);
LPVOID HeapAlloc(HANDLE heap, DWORD flags, SIZE_T size);
BOOL HeapFree(HANDLE heap, DWORD flags, LPVOID p);
HMODULE LoadLibraryA(LPCSTR name);
HMODULE GetModuleHandleA(LPCSTR name);
void *GetProcAddress(HMODULE module, LPCSTR name);
int MessageBoxA(HANDLE window, LPCSTR text, LPCSTR caption, UINT type);
void Sleep(DWORD milliseconds);
void ExitProcess(UINT code);
DWORD GetTickCount(void);
int lstrlenA(LPCSTR s);
