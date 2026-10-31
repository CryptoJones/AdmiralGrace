import Darwin

public struct Point { public var x: Int; public var y: Int }
public protocol Shaped { associatedtype Unit: Numeric; func area() -> Unit }
public class Box<T: Hashable & Comparable> {
    public var items: [T] = []
    public var first: T? { return items.first }
    public init() {}
    public func add(_ item: T) { items.append(item) }
}
public enum Failure: Error { case empty, bad(code: Int) }
public func sum(_ a: [Int], _ p: Point, _ b: [Int], _ c: Int?) throws -> Int? {
    if a.isEmpty { throw Failure.empty }
    return a.reduce(0, +) + b.reduce(0, +) + p.x + (c ?? 0)
}
public func describe(x: Int?, names: [String: Int], flag: Bool) -> String {
    return "\(x ?? -1) \(names.count) \(flag)"
}
public func fetch(x: Int?) async -> String { return "\(x ?? 0)" }
public func pick<T: Comparable>(_ a: T, _ b: T) -> T { return a < b ? a : b }
public func measure<S: Shaped>(_ s: S) -> S.Unit { return s.area() }
public func twice<T>(_ v: T, _ f: (T) throws -> T) rethrows -> T { return try f(try f(v)) }
public func pair<A, B>(_ a: A, _ b: B) -> (A, B) { return (a, b) }
let box = Box<Int>()
box.add(3)
let s = try? sum([1, 2], Point(x: 1, y: 2), [3], box.first)
let d = describe(x: s, names: ["a": 1], flag: true)
exit(Int32(d.count & 0xff))
