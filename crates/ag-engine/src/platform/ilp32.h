// The 32-bit platforms — linux/arm, linux/x86 under ILP32 and
// ILP32 (i386) — carry the same C library names as the 64-bit Linux
// types, read under the 32-bit data model, where long and pointers are
// 4 bytes. The definitions are the same C; the layout follows the
// model the platform is laid out under.

typedef struct _IO_FILE FILE;
typedef long off_t;
typedef long time_t;
typedef unsigned int mode_t;
typedef int pid_t;
typedef unsigned int socklen_t;
typedef unsigned long pthread_t;

struct timeval {
    long tv_sec;
    long tv_usec;
};

struct timespec {
    long tv_sec;
    long tv_nsec;
};

struct sockaddr {
    unsigned short sa_family;
    char sa_data[14];
};

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int sin_addr;
    unsigned char sin_zero[8];
};

struct pollfd {
    int fd;
    short events;
    short revents;
};

typedef unsigned long sigset_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef unsigned short dev_t;
typedef unsigned long ino_t;
typedef long clock_t;
typedef int clockid_t;
