// A Java native library: the exports JNI names `Java_<class>_<method>` —
// a class and a method — and the runtime functions `JNI_OnLoad` and
// `JNI_OnUnload`, whose parameters are the environment, the object the
// method runs on, and the signature's own when the name carries one.

int Java_com_example_Native_add(long env, long obj, int a, int b) {
    return a + b + (int)env + (int)obj;
}

long Java_com_example_Native_get__ILjava_lang_String_(long env, long obj, long s) {
    return s + env + obj;
}

int Java_com_example_Native_overloaded__II(long env, long obj, int a, int b) {
    return a + b + (int)env + (int)obj;
}

int JNI_OnLoad(long vm, long reserved) {
    return 0x00010006 + (int)vm + (int)reserved;
}

void JNI_OnUnload(long vm, long reserved) {
    (void)vm;
    (void)reserved;
}

int main(void) {
    return Java_com_example_Native_add(0, 0, 40, 1);
}
