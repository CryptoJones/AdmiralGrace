// A multiple-inheritance hierarchy: one primary base and one secondary,
// each with a virtual function, so the vtable carries two groups and the
// RTTI names both bases. Built with:
//   g++ -O1 -fno-pic -no-pie -o cxx_mi.elf cxx_mi.cpp
struct base {
    virtual int a(int x);
    int data;
};
struct side {
    virtual int b();
};
struct multi : public base, public side {
    int a(int x) override;
    int b() override;
};
int base::a(int x) { return x; }
int side::b() { return 1; }
int multi::a(int x) { return x + 1; }
int multi::b() { return data + 2; }
extern "C" int call(int k) {
    multi m;
    base* b = &m;
    side* s = &m;
    return b->a(k) + s->b();
}
int main() { return call(1); }
