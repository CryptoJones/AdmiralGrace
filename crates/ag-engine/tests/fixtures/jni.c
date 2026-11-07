// A Java native library: the exports JNI names `Java_<class>_<method>` —
// a class and a method — and the runtime functions `JNI_OnLoad` and
// `JNI_OnUnload`, whose parameters are the environment, the object the
// method runs on, and the signature's own when the name carries one.
//
// Built with:
//   gcc -O1 -fno-pic -no-pie -nostdlib -static -fno-builtin -fno-stack-protector -o jni.elf jni.c
__attribute__((noinline)) int Java_com_example_Native_add(long env, long obj, int a, int b) {
    return a + b + (int)env + (int)obj;
}

__attribute__((noinline)) long Java_com_example_Native_greet(long env, long obj) {
    return env + obj;
}

__attribute__((noinline)) int Java_com_example_Native_overloaded__II(long env, long obj, int a, int b) {
    return a + b + (int)env + (int)obj;
}

__attribute__((noinline)) int JNI_OnLoad(long vm, long reserved) {
    return 0x00010006 + (int)vm + (int)reserved;
}

__attribute__((noinline)) void JNI_OnUnload(long vm, long reserved) {
    (void)vm;
    (void)reserved;
}

void _start(void) {
    Java_com_example_Native_add(0, 0, 40, 1);
}
