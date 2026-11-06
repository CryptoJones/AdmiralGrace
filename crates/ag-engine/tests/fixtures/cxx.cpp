// A C++ class hierarchy with virtual functions, and a template, built
// with:
//   g++ -O1 -fno-pic -no-pie -o cxx.elf cxx.cpp
struct base {
    base();
    virtual int f(int x);
    virtual int g();
    int data;
};
struct derived : public base {
    derived();
    int f(int x) override;
    int h();
};
base::base() : data(0) {}
derived::derived() : base() {}
int base::f(int x) { return x + 1; }
int base::g() { return data; }
int derived::f(int x) { return x * 2; }
int derived::h() { return data + 1; }
template <typename T>
T twice(T value) { return value + value; }
template int twice<int>(int);
extern "C" int call(int k) {
    derived d;
    base* b = &d;
    return b->f(k) + b->g() + d.h() + twice(k);
}
int main() { return call(3); }
