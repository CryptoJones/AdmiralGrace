/* A tiny C++ program with no runtime library: a namespace, a class with a
   constructor and two methods, an overloaded free function and a template
   instance, so the symbols the linker keeps are mangled names of every
   common shape — Itanium on ELF and Mach-O, Microsoft on PE. */
#ifdef _WIN32
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED
#endif

namespace geometry {

struct Point {
    int x;
    int y;
};

class Shape {
public:
    EXPORTED Shape(int sides);
    EXPORTED int sides() const;
    EXPORTED Point corner(int index) const;
    static EXPORTED int count;

private:
    int sides_;
};

Shape::Shape(int sides) : sides_(sides) { count++; }
int Shape::sides() const { return sides_; }
Point Shape::corner(int index) const { Point p = {index, sides_ - index}; return p; }
int Shape::count = 0;

EXPORTED int area(int side) { return side * side; }
EXPORTED int area(int width, int height) { return width * height; }

template <typename T>
EXPORTED T twice(T value) { return value + value; }

template int twice<int>(int);
template long twice<long>(long);

}  // namespace geometry

extern "C" EXPORTED int main(void) {
    geometry::Shape square(4);
    return geometry::area(square.sides()) + geometry::area(2, 3) +
           geometry::twice(square.corner(1).x) + (int)geometry::twice(5L);
}
