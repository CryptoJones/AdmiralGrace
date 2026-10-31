// Calls through function pointers under Windows control-flow guard:
// the compiler puts the target in rax and calls, or jumps, through
// __guard_dispatch_icall_fptr. See the README for the build.
int add(int a, int b) { return a + b; }
__attribute__((noinline)) int call_through(int (*p)(int, int), int x) { return p(x, 1); }
__attribute__((noinline)) void tail_through(void (*p)(void)) { p(); }
struct ops { int (*run)(int, int); int base; };
__attribute__((noinline)) int field_call(struct ops *o, int x) { return o->run(x, o->base); }
int main(void) { return call_through(add, 2) + field_call(0, 3); }
