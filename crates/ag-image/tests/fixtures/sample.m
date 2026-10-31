/* A tiny Objective-C program with no Foundation: a root class, a subclass,
   a category and a protocol, so the metadata the loader reads has every
   kind of thing in it. */
@protocol Greeting
- (int)greet:(int)times;
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

@interface Derived : Base <Greeting>
- (int)greet:(int)times;
@end

@implementation Derived
- (int)greet:(int)times { return [self twice:times] + 1; }
@end

@interface Base (Extra)
- (int)thrice:(int)value;
@end

@implementation Base (Extra)
- (int)thrice:(int)value { return value * 3; }
@end

int main(void) {
    Derived *d = (Derived *)0;
    return [d greet:[Base answer]] + [d thrice:2];
}
