// macos/x86-64 and macos/arm64: the Darwin C library types, LP64.
// FILE is an opaque pointer as Darwin's stdio holds it, DISPATCH
// objects are the pointers libdispatch hands out, and sockaddr_in is
// the BSD shape. Where the builtin type libraries (#376) already know
// a name, the platform keeps its own definition here, so the platform's
// types are whole without them; the project's definition still wins
// over both.

typedef struct __sFILE FILE;
typedef long off_t;
typedef long time_t;
typedef unsigned int mode_t;
typedef int pid_t;
typedef unsigned int socklen_t;
typedef void *dispatch_queue_t;
typedef void *dispatch_group_t;
typedef void *dispatch_semaphore_t;
typedef void *dispatch_time_t;
typedef int dispatch_once_t;
typedef unsigned long pthread_t;

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
    unsigned char sa_len;
    unsigned char sa_family;
    char sa_data[14];
};

struct sockaddr_in {
    unsigned char sin_len;
    unsigned char sin_family;
    unsigned short sin_port;
    unsigned int sin_addr;
    unsigned char sin_zero[8];
};

struct sockaddr_in6 {
    unsigned char sin6_len;
    unsigned char sin6_family;
    unsigned short sin6_port;
    unsigned int sin6_flowinfo;
    unsigned char sin6_addr[16];
    unsigned int sin6_scope_id;
};

struct pollfd {
    int fd;
    short events;
    short revents;
};

typedef unsigned int sigset_t;
typedef unsigned int useconds_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef unsigned short dev_t;
typedef unsigned long ino_t;
typedef unsigned long nlink_t;
typedef unsigned long blksize_t;
typedef long blkcnt_t;
typedef long clock_t;
typedef int clockid_t;
