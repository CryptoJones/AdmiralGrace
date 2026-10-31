// What the C runtime would give a guarded image: the guard pointers,
// pointing at a dispatcher that jumps to rax, and the load configuration
// that names them, which the linker puts in the image's data directory.
__asm__(".globl guard_dispatch\nguard_dispatch:\n jmp rax\n");
extern void guard_dispatch(void);
void *__guard_dispatch_icall_fptr = (void *)guard_dispatch;
void *__guard_check_icall_fptr = (void *)guard_dispatch;
struct load_config {
    unsigned int size;
    unsigned char before_check[0x70 - 4];
    void **check;
    void **dispatch;
    unsigned char after[0x138 - 0x80];
};
const struct load_config _load_config_used = {
    0x138, {0}, &__guard_check_icall_fptr, &__guard_dispatch_icall_fptr, {0}
};
