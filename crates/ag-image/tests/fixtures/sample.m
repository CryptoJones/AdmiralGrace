/* A tiny Objective-C program with no Foundation: a root class, a subclass,
   a category and a protocol, so the metadata the loader reads has every
   kind of thing in it — and, for the header the workbench writes, a
   property, an optional protocol method, a class method in a protocol,
   and methods whose types are a struct, a pointer, a class and a block. */
struct Point {
    int x;
    int y;
};

@protocol Greeting
- (int)greet:(int)times;
+ (id)greeter;
@optional
- (void)wave:(const char *)to;
@end

__attribute__((objc_root_class))
@interface Base {
    Class isa;
}
+ (int)answer;
- (int)twice:(int)value;
@end

@implementation Base
+ (int)answer { return 42; }
- (int)twice:(int)value { return value * 2; }
@end

@interface Derived : Base <Greeting> {
    struct Point _origin;
    Base *_parent;
}
@property (nonatomic) int count;
@property (nonatomic, readonly) struct Point origin;
@property (nonatomic, assign) Base *parent;
- (int)greet:(int)times;
- (unsigned long)hash:(const char *)text at:(unsigned long)index;
- (void)each:(void (^)(int))block;
@end

@implementation Derived
@synthesize count = _count;
@synthesize origin = _origin;
@synthesize parent = _parent;
- (int)greet:(int)times { return [self twice:times] + 1; }
- (unsigned long)hash:(const char *)text at:(unsigned long)index { return (unsigned long)text[index]; }
- (void)each:(void (^)(int))block { block(_count); }
@end

@interface Base (Extra)
@property (nonatomic, readonly) int thriceOfOne;
- (int)thrice:(int)value;
@end

@implementation Base (Extra)
- (int)thrice:(int)value { return value * 3; }
- (int)thriceOfOne { return 3; }
@end

int main(void) {
    Derived *d = (Derived *)0;
    return [d greet:[Base answer]] + [d thrice:2];
}
