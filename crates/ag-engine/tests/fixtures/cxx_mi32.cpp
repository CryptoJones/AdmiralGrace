// The same multiple-inheritance shape as cxx_mi.cpp, built for i386 so the
// VMI header and the secondary vtable headers use 4-byte words:
//   g++ -m32 -O1 -fno-pic -c -o cxx_mi32.o cxx_mi32.cpp
struct base { virtual int a(int x); int data; };
struct side { virtual int b(); };
struct multi : public base, public side { int a(int x) override; int b() override; };
int base::a(int x) { return x; }
int side::b() { return 1; }
int multi::a(int x) { return x + 1; }
int multi::b() { return data + 2; }
extern "C" int call(int k) { multi m; base* b = &m; side* s = &m; return b->a(k) + s->b(); }
int main() { return call(1); }
