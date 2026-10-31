import Darwin

// A tiny Swift program: a protocol, a struct, an enum, a class with
// properties and methods, a generic function and a closure, so the
// metadata the runtime reads and the mangled names the linker keeps have
// every common shape in them.
public protocol Greeting {
    func greet(times: Int) -> Int
}

public struct Point {
    public var x: Int
    public var y: Int
    public func manhattan() -> Int { return abs(x) + abs(y) }
}

public enum Shape {
    case circle(radius: Int)
    case square(side: Int)
    case empty
}

public class Base {
    public var count: Int = 0
    public init(count: Int) { self.count = count }
    public func twice(_ value: Int) -> Int { return value * 2 }
    public class func answer() -> Int { return 42 }
}

public final class Derived: Base, Greeting {
    public var origin = Point(x: 1, y: 2)
    public var shape: Shape = .empty
    public func greet(times: Int) -> Int { return twice(times) + 1 }
    public func area(of shape: Shape) -> Int {
        switch shape {
        case .circle(let r): return 3 * r * r
        case .square(let s): return s * s
        case .empty: return 0
        }
    }
}

public func twice<T: Numeric>(_ value: T) -> T { return value + value }

@inline(never) public func apply(_ f: (Int) -> Int, to value: Int) -> Int { return f(value) }

let d = Derived(count: 3)
let total = d.greet(times: Base.answer()) + d.area(of: .square(side: 2)) + twice(5) + apply({ $0 + 1 }, to: d.origin.manhattan())
exit(Int32(total & 0xff))
