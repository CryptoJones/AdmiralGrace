// A virtual (diamond) inheritance hierarchy: the shared base is virtual,
// so its VMI offset_flags carry the virtual bit. Built with:
//   g++ -O1 -fno-pic -no-pie -o cxx_vi.elf cxx_vi.cpp
struct vbase { virtual int v(); };
struct left : virtual public vbase { int v() override; };
struct right : virtual public vbase { int v() override; };
struct diamond : public left, public right { int v() override; };
int vbase::v() { return 0; }
int left::v() { return 1; }
int right::v() { return 1; }
int diamond::v() { return 2; }
extern "C" int call() { diamond d; return d.v(); }
int main() { return call(); }
