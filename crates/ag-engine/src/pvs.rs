//! Possible-value sets: the constants, sets and ranges a variable can hold
//! at each statement, constrained by the branches that reach it.
//!
//! The analysis needs no word from the analyst. It runs forward over the
//! structured body, on the statement graph [`crate::slice`] builds, from
//! the function's entry, where every parameter and local can hold any
//! value of its type. What a variable can hold is one of:
//!
//! - [`PossibleValues::Constant`], one value, spelled `5`;
//! - [`PossibleValues::Set`], up to [`SET_LIMIT`] values, `{1, 3, 7}`; a
//!   set that would grow past the limit is the range that holds it;
//! - [`PossibleValues::Range`], the values from `min` to `max` `step`
//!   apart, `0..=9` or `0..=36 step 4`; a range holds three values or
//!   more, and fewer are a set;
//! - [`PossibleValues::Top`], any value of its type, `any`;
//! - [`PossibleValues::Undetermined`], no value: the statement is on no
//!   path the analysis follows — an arm a condition never takes, code after
//!   a `return` — `undetermined`.
//!
//! A value is a number as the variable's type reads it: signed for a signed
//! type, so an `int` holds `-1`, and unsigned for an unsigned one, so an
//! `unsigned int` holding the same bits holds `4294967295`. The arithmetic
//! is the machine's: it wraps in its type, so a range that wraps part way
//! is any value, and one that wraps whole is the range it wraps to.
//!
//! Forward, an assignment gives its variable what its right side can be:
//! `+`, `-`, `*`, `&`, `<<` and `>>` over ranges and their steps, `x * 4`
//! being `step 4`, the six comparisons, `&&`, `||`, `?:` and casts; `/`,
//! `%`, `|` and `^` of small sets value by value. A call, a load through a
//! pointer and the rest are any value. Where paths meet, what each brings
//! is joined; at a loop's head, after three rounds that grew, a bound that
//! still moves goes to its type's end — the widening — so the rounds end,
//! and two rounds more, without it, take back what the loop's condition
//! bounds.
//!
//! Backward, each arm of a condition narrows what it compares: on the arm
//! where `a < 10` holds, `a` is at most 9; where `a == 3` holds, `a` is 3,
//! and where it fails, 3 is out of `a`'s set; each case of a `switch (a)`
//! has `a` its value, and the default none of them. A side that is a
//! simple invertible expression of the variable passes the narrowing on:
//! `a + 1 < 10`, `a - 1`, `5 - a`, a cast, and `a & 7` where `a` is in
//! `0..=7` already — wrapping as the machine does, so `a + 1 < 10` says
//! `a` is at most 8 only where `a + 1` cannot wrap. A condition over a
//! variable with a few values keeps the values for which it can go the
//! arm's way. `&&` and `||` narrow by both sides on the arm both decide,
//! and an arm no value can take is on no path.
//!
//! The analyst's values, [`crate::values::PinnedValue`], seed the analysis:
//! a value at the entry is the variable's there, and a value from an
//! address on is a definition of its own where the value is said to hold.
//!
//! Only variables of integer and pointer types are followed; a variable
//! whose address is taken is memory, which a store or a call may change,
//! and a global is too: none is followed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::ast::{AstNode, BinaryOp};
use crate::emulate::type_of;
use crate::lift::{LiftedFunction, Statement, StatementKind};
use crate::merge::nodes_of;
use crate::slice::{strip_casts, Arm, Graph, Part, ENTRY};
use crate::values::{insert_pin, pin_index, PinnedValue, PINNED};

/// A range of values, as numbers rather than bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Range {
    pub(crate) lo: i128,
    pub(crate) hi: i128,
}

impl Range {
    pub(crate) fn hull(self, other: Self) -> Self {
        Self {
            lo: self.lo.min(other.lo),
            hi: self.hi.max(other.hi),
        }
    }

    pub(crate) fn contains(self, value: i128) -> bool {
        self.lo <= value && value <= self.hi
    }

    /// Whether a value in the range is true: always, never, or either.
    pub(crate) fn truth(self) -> Option<bool> {
        if !self.contains(0) {
            Some(true)
        } else if self.lo == 0 && self.hi == 0 {
            Some(false)
        } else {
            None
        }
    }

    /// The values in both, when there are any.
    fn intersect(self, other: Self) -> Option<Self> {
        let lo = self.lo.max(other.lo);
        let hi = self.hi.min(other.hi);
        (lo <= hi).then_some(Self { lo, hi })
    }

    /// Whether every value of `other` is in it.
    fn covers(self, other: Self) -> bool {
        self.lo <= other.lo && other.hi <= self.hi
    }
}

/// A width in bits and a signedness, as [`type_of`] reads a C type.
pub(crate) type Ty = (u32, bool);

/// The values a type holds.
pub(crate) fn full(ty: Ty) -> Range {
    let bits = ty.0.clamp(1, 64);
    if ty.1 {
        Range {
            lo: -(1i128 << (bits - 1)),
            hi: (1i128 << (bits - 1)) - 1,
        }
    } else {
        Range {
            lo: 0,
            hi: (1i128 << bits) - 1,
        }
    }
}

/// How many values a type holds: what its arithmetic wraps by.
fn modulus(ty: Ty) -> i128 {
    1i128 << ty.0.clamp(1, 64)
}

/// The value converted to `ty` as C converts a value: modulo the type's
/// size.
fn wrap(value: i128, ty: Ty) -> i128 {
    let bounds = full(ty);
    (value - bounds.lo).rem_euclid(modulus(ty)) + bounds.lo
}

/// The range converted to `ty` as C converts a value: modulo the type's
/// size, so a range that does not wrap in it stays whole, and one that
/// does is unknown.
pub(crate) fn convert(range: Range, ty: Ty) -> Option<Range> {
    let bounds = full(ty);
    if bounds.contains(range.lo) && bounds.contains(range.hi) {
        return Some(range);
    }
    if range.hi - range.lo >= modulus(ty) {
        return None;
    }
    let (lo, hi) = (wrap(range.lo, ty), wrap(range.hi, ty));
    (hi - lo == range.hi - range.lo).then_some(Range { lo, hi })
}

/// A comparison's or a logical operator's result: `int`, 0 or 1.
pub(crate) const TRUTH: Ty = (32, true);

/// The most values a [`PossibleValues::Set`] holds.
pub const SET_LIMIT: usize = 16;

/// The values a variable can hold at a point of the function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PossibleValues {
    /// No value: the point is on no path the analysis follows.
    Undetermined,
    /// One value.
    Constant(i128),
    /// Two to [`SET_LIMIT`] values.
    Set(BTreeSet<i128>),
    /// The values from `min` to `max`, `step` apart: three or more, `max`
    /// one of them.
    Range { min: i128, max: i128, step: i128 },
    /// Any value of its type.
    Top,
}

/// The greatest common divisor, of magnitudes; `gcd(x, 0)` is `x`.
fn gcd(a: i128, b: i128) -> i128 {
    let (mut a, mut b) = (a.abs(), b.abs());
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

impl PossibleValues {
    /// The values given, as few or as many as they are.
    pub fn of_values(values: impl IntoIterator<Item = i128>) -> Self {
        let values: BTreeSet<i128> = values.into_iter().collect();
        match values.len() {
            0 => Self::Undetermined,
            1 => Self::Constant(*values.first().expect("one value")),
            n if n <= SET_LIMIT => Self::Set(values),
            _ => {
                let min = *values.first().expect("values");
                let max = *values.last().expect("values");
                let step = values.iter().fold(0, |step, value| gcd(step, value - min));
                Self::range(min, max, step)
            }
        }
    }

    /// The values from `min` to at most `max`, `step` apart.
    pub fn range(min: i128, max: i128, step: i128) -> Self {
        if min > max {
            return Self::Undetermined;
        }
        let step = step.max(1);
        let count = (max - min) / step + 1;
        let max = min + (count - 1) * step;
        if count <= 2 {
            Self::of_values([min, max])
        } else {
            Self::Range { min, max, step }
        }
    }

    /// Itself, a range that is the whole of `ty` being any value.
    fn within(self, ty: Ty) -> Self {
        match self {
            Self::Range { min, max, step: 1 } if (Range { lo: min, hi: max }) == full(ty) => {
                Self::Top
            }
            other => other,
        }
    }

    /// The least and the greatest value, when they are known: not for any
    /// value, nor for none.
    pub fn bounds(&self) -> Option<(i128, i128)> {
        match self {
            Self::Undetermined | Self::Top => None,
            Self::Constant(value) => Some((*value, *value)),
            Self::Set(values) => Some((*values.first()?, *values.last()?)),
            Self::Range { min, max, .. } => Some((*min, *max)),
        }
    }

    /// The least and the greatest value as a type holds them: any value is
    /// the whole type.
    fn hull_in(&self, ty: Ty) -> Option<Range> {
        match self {
            Self::Top => Some(full(ty)),
            other => other.bounds().map(|(lo, hi)| Range { lo, hi }),
        }
    }

    /// The values, when they are few enough to list.
    fn finite(&self) -> Option<Vec<i128>> {
        match self {
            Self::Constant(value) => Some(vec![*value]),
            Self::Set(values) => Some(values.iter().copied().collect()),
            _ => None,
        }
    }

    /// The distance every value is from the least by a multiple of: 0 for
    /// one value, 1 for any.
    fn step(&self) -> i128 {
        match self {
            Self::Undetermined | Self::Constant(_) => 0,
            Self::Set(values) => {
                let min = values.first().copied().unwrap_or_default();
                values.iter().fold(0, |step, value| gcd(step, value - min))
            }
            Self::Range { step, .. } => *step,
            Self::Top => 1,
        }
    }

    /// Whether the value is one it can be.
    pub fn contains(&self, value: i128) -> bool {
        match self {
            Self::Undetermined => false,
            Self::Constant(held) => *held == value,
            Self::Set(values) => values.contains(&value),
            Self::Range { min, max, step } => {
                *min <= value && value <= *max && (value - min) % step == 0
            }
            Self::Top => true,
        }
    }

    /// What either can be.
    pub fn join(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Undetermined, other) | (other, Self::Undetermined) => other.clone(),
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (a, b) => {
                if let (Some(a), Some(b)) = (a.finite(), b.finite()) {
                    return Self::of_values(a.into_iter().chain(b));
                }
                let ((alo, ahi), (blo, bhi)) = (
                    a.bounds().expect("some value"),
                    b.bounds().expect("some value"),
                );
                let step = gcd(gcd(a.step(), b.step()), alo - blo);
                Self::range(alo.min(blo), ahi.max(bhi), step)
            }
        }
    }

    /// Whether every value it can be, `other` can be too.
    fn within_of(&self, other: &Self) -> bool {
        other.join(self) == *other
    }

    /// The values it can be between `lo` and `hi`, of type `ty`.
    fn meet_range(&self, range: Range, ty: Ty) -> Self {
        match self {
            Self::Undetermined => Self::Undetermined,
            Self::Top => match full(ty).intersect(range) {
                Some(range) => Self::range(range.lo, range.hi, 1).within(ty),
                None => Self::Undetermined,
            },
            Self::Constant(_) | Self::Set(_) => Self::of_values(
                self.finite()
                    .expect("a few values")
                    .into_iter()
                    .filter(|value| range.contains(*value)),
            ),
            Self::Range { min, max, step } => {
                let lo = range.lo.max(*min);
                let hi = range.hi.min(*max);
                if lo > hi {
                    return Self::Undetermined;
                }
                let first = min + (lo - min + step - 1).div_euclid(*step) * step;
                let last = min + (hi - min).div_euclid(*step) * step;
                Self::range(first, last, *step)
            }
        }
    }

    /// The values it can be that are among `values`.
    fn meet_values(&self, values: &BTreeSet<i128>) -> Self {
        Self::of_values(values.iter().copied().filter(|value| self.contains(*value)))
    }

    /// The values it can be that are none of `values`.
    fn except(&self, values: &BTreeSet<i128>) -> Self {
        match self {
            Self::Constant(_) | Self::Set(_) => Self::of_values(
                self.finite()
                    .expect("a few values")
                    .into_iter()
                    .filter(|value| !values.contains(value)),
            ),
            Self::Range { min, max, step } => {
                let (mut lo, mut hi) = (*min, *max);
                while lo <= hi && values.contains(&lo) {
                    lo += step;
                }
                while lo <= hi && values.contains(&hi) {
                    hi -= step;
                }
                Self::range(lo, hi, *step)
            }
            other => other.clone(),
        }
    }

    /// What it can be after a loop's head has seen it grow again: a bound
    /// that moved goes to the end of `ty`.
    fn widen(&self, newer: &Self, ty: Ty) -> Self {
        if newer.within_of(self) {
            return self.clone();
        }
        let joined = self.join(newer);
        if matches!(joined, Self::Top) {
            return Self::Top;
        }
        let (Some(old), Some(all)) = (self.hull_in(ty), joined.hull_in(ty)) else {
            return joined;
        };
        let bounds = full(ty);
        let step = joined.step().max(1);
        let base = all.lo;
        let lo = if all.lo < old.lo {
            base - (base - bounds.lo).div_euclid(step) * step
        } else {
            all.lo
        };
        let hi = if all.hi > old.hi {
            base + (bounds.hi - base).div_euclid(step) * step
        } else {
            all.hi
        };
        Self::range(lo, hi, step).within(ty)
    }

    /// The values converted to `ty`, as C converts them.
    fn convert(&self, ty: Ty) -> Self {
        match self {
            Self::Undetermined => Self::Undetermined,
            Self::Top => Self::Top,
            Self::Constant(_) | Self::Set(_) => Self::of_values(
                self.finite()
                    .expect("a few values")
                    .into_iter()
                    .map(|value| wrap(value, ty)),
            ),
            Self::Range { min, max, step } => wrapped(*min, *max, *step, ty),
        }
    }

    /// Whether it is true: always, never, or either.
    fn truth(&self) -> Option<bool> {
        match self {
            Self::Top | Self::Undetermined => None,
            Self::Range { min, max, .. } => Range { lo: *min, hi: *max }.truth(),
            values => {
                let values = values.finite().expect("a few values");
                if values.iter().all(|value| *value != 0) {
                    Some(true)
                } else if values.iter().all(|value| *value == 0) {
                    Some(false)
                } else {
                    None
                }
            }
        }
    }

    /// Whether it says anything: not any value.
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Top)
    }
}

impl fmt::Display for PossibleValues {
    /// `5`, `{1, 3, 7}`, `0..=9`, `0..=36 step 4`, `undetermined`, `any`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Undetermined => write!(f, "undetermined"),
            Self::Constant(value) => write!(f, "{value}"),
            Self::Set(values) => {
                let values: Vec<String> = values.iter().map(|value| value.to_string()).collect();
                write!(f, "{{{}}}", values.join(", "))
            }
            Self::Range { min, max, step: 1 } => write!(f, "{min}..={max}"),
            Self::Range { min, max, step } => write!(f, "{min}..={max} step {step}"),
            Self::Top => write!(f, "any"),
        }
    }
}

/// The values from `lo` to `hi`, `step` apart, converted to `ty`: whole,
/// or wrapped whole; where they wrap part way, every value of the type
/// `step` apart from them where the step divides the type's size, and any
/// value where it does not.
fn wrapped(lo: i128, hi: i128, step: i128, ty: Ty) -> PossibleValues {
    match convert(Range { lo, hi }, ty) {
        Some(range) => PossibleValues::range(range.lo, range.hi, step).within(ty),
        None if step > 1 && modulus(ty) % step == 0 => {
            let bounds = full(ty);
            let first = bounds.lo + (wrap(lo, ty) - bounds.lo).rem_euclid(step);
            PossibleValues::range(first, bounds.hi, step).within(ty)
        }
        None => PossibleValues::Top,
    }
}

/// The truth of a condition as a value: 1, 0, or either.
fn truth_value(holds: Option<bool>) -> PossibleValues {
    match holds {
        Some(true) => PossibleValues::Constant(1),
        Some(false) => PossibleValues::Constant(0),
        None => PossibleValues::of_values([0, 1]),
    }
}

/// A value and its type.
pub(crate) type Typed = (PossibleValues, Ty);

/// The type the usual conversions give two operands: the wider one's, and
/// when the widths are the same, unsigned if either is.
fn usual(ta: Ty, tb: Ty) -> Ty {
    match ta.0.cmp(&tb.0) {
        std::cmp::Ordering::Greater => ta,
        std::cmp::Ordering::Less => tb,
        std::cmp::Ordering::Equal => (ta.0, ta.1 && tb.1),
    }
}

/// Whether `op` holds of every pair of values from the two ranges, of none,
/// or of some.
fn compare(op: BinaryOp, a: Range, b: Range) -> Option<bool> {
    let less = |a: Range, b: Range| {
        if a.hi < b.lo {
            Some(true)
        } else if a.lo >= b.hi {
            Some(false)
        } else {
            None
        }
    };
    let equal = if a.lo == a.hi && b.lo == b.hi && a.lo == b.lo {
        Some(true)
    } else if a.hi < b.lo || b.hi < a.lo {
        Some(false)
    } else {
        None
    };
    match op {
        BinaryOp::Less => less(a, b),
        BinaryOp::GreaterEqual => less(a, b).map(|holds| !holds),
        BinaryOp::Greater => less(b, a),
        BinaryOp::LessEqual => less(b, a).map(|holds| !holds),
        BinaryOp::Equal => equal,
        BinaryOp::NotEqual => equal.map(|holds| !holds),
        _ => None,
    }
}

/// Whether `op` holds of every pair of the values, of none, or of some.
fn compare_values(op: BinaryOp, a: &PossibleValues, b: &PossibleValues) -> Option<bool> {
    let (alo, ahi) = a.bounds()?;
    let (blo, bhi) = b.bounds()?;
    if let Some(holds) = compare(op, Range { lo: alo, hi: ahi }, Range { lo: blo, hi: bhi }) {
        return Some(holds);
    }
    // One value the other cannot be is never equal to it.
    let apart = match (a, b) {
        (PossibleValues::Constant(value), other) | (other, PossibleValues::Constant(value)) => {
            !other.contains(*value)
        }
        _ => match (a.finite(), b.finite()) {
            (Some(a), Some(b)) => a.iter().all(|value| !b.contains(value)),
            _ => false,
        },
    };
    match (op, apart) {
        (BinaryOp::Equal, true) => Some(false),
        (BinaryOp::NotEqual, true) => Some(true),
        _ => None,
    }
}

/// `op` of two values of type `ty`, as the machine computes it, when it is
/// defined.
fn exact(op: BinaryOp, a: i128, b: i128, ty: Ty) -> Option<i128> {
    let bits = |value: i128| wrap(value, (ty.0, false));
    let value = match op {
        BinaryOp::Add => a + b,
        BinaryOp::Sub => a - b,
        BinaryOp::Mul => a.checked_mul(b)?,
        BinaryOp::And => bits(a) & bits(b),
        BinaryOp::Or => bits(a) | bits(b),
        BinaryOp::Xor => bits(a) ^ bits(b),
        BinaryOp::Div if b != 0 => a / b,
        BinaryOp::Mod if b != 0 => a % b,
        _ => return None,
    };
    Some(wrap(value, ty))
}

/// `op` of two values both of type `ty`.
fn arithmetic(op: BinaryOp, a: &PossibleValues, b: &PossibleValues, ty: Ty) -> PossibleValues {
    use PossibleValues as V;
    if matches!(a, V::Undetermined) || matches!(b, V::Undetermined) {
        return V::Undetermined;
    }
    if let (Some(xs), Some(ys)) = (a.finite(), b.finite()) {
        let mut out = Vec::with_capacity(xs.len() * ys.len());
        for x in &xs {
            for y in &ys {
                match exact(op, *x, *y, ty) {
                    Some(value) => out.push(value),
                    None => return V::Top,
                }
            }
        }
        return V::of_values(out).within(ty);
    }
    let constant = |v: &V| match v {
        V::Constant(value) => Some(*value),
        _ => None,
    };
    if op == BinaryOp::And {
        // A mask that is not negative keeps the value within it, whatever
        // the value's bits; a value within a mask of low bits is itself.
        let masked = |mask: i128, other: &V| {
            if mask < 0 {
                return None;
            }
            if (mask + 1) & mask == 0 {
                if let Some(range) = other.hull_in(ty) {
                    if (Range { lo: 0, hi: mask }).covers(range) {
                        return Some(other.clone());
                    }
                }
            }
            let hi = match other.hull_in(ty) {
                Some(range) if range.lo >= 0 => range.hi.min(mask),
                _ => mask,
            };
            Some(V::range(0, hi, 1).within(ty))
        };
        if let Some(found) = constant(b)
            .and_then(|mask| masked(mask, a))
            .or_else(|| constant(a).and_then(|mask| masked(mask, b)))
        {
            return found;
        }
    }
    let (Some(x), Some(y)) = (a.bounds(), b.bounds()) else {
        return V::Top;
    };
    let (sa, sb) = (a.step(), b.step());
    match op {
        BinaryOp::Add => wrapped(x.0 + y.0, x.1 + y.1, gcd(sa, sb), ty),
        BinaryOp::Sub => wrapped(x.0 - y.1, x.1 - y.0, gcd(sa, sb), ty),
        BinaryOp::Mul => {
            let scaled = |(lo, hi): (i128, i128), step: i128, by: i128| {
                let (Some(p), Some(q)) = (lo.checked_mul(by), hi.checked_mul(by)) else {
                    return V::Top;
                };
                wrapped(p.min(q), p.max(q), step * by.abs(), ty)
            };
            if let Some(by) = constant(b) {
                return scaled(x, sa, by);
            }
            if let Some(by) = constant(a) {
                return scaled(y, sb, by);
            }
            let products = [
                x.0.checked_mul(y.0),
                x.0.checked_mul(y.1),
                x.1.checked_mul(y.0),
                x.1.checked_mul(y.1),
            ];
            if products.iter().any(Option::is_none) {
                return V::Top;
            }
            let products: Vec<i128> = products.into_iter().flatten().collect();
            wrapped(
                *products.iter().min().expect("four"),
                *products.iter().max().expect("four"),
                1,
                ty,
            )
        }
        BinaryOp::And if x.0 >= 0 && y.0 >= 0 => V::range(0, x.1.min(y.1), 1).within(ty),
        _ => V::Top,
    }
}

/// What `node` evaluates to, given what is known of the variables it
/// reads, when that is known. Every operator is followed.
pub(crate) fn eval(node: &AstNode, known: &dyn Fn(&str) -> Option<Typed>) -> Option<Typed> {
    eval_with(node, known, true)
}

/// [`eval`] over ranges alone, as the analyst's values are followed
/// ([`crate::values`]): `+`, `-`, `*`, `&`, `<<`, `>>`, casts, the
/// comparisons, `&&`, `||` and `?:`, and nothing known where a value could
/// be any value of its type.
pub(crate) fn eval_ranges(
    node: &AstNode,
    known: &dyn Fn(&str) -> Option<(Range, Ty)>,
) -> Option<(Range, Ty)> {
    let (values, ty) = eval_with(
        node,
        &|name| known(name).map(|(range, ty)| (PossibleValues::range(range.lo, range.hi, 1), ty)),
        false,
    )?;
    let (lo, hi) = values.bounds()?;
    Some((Range { lo, hi }, ty))
}

fn eval_with(node: &AstNode, known: &dyn Fn(&str) -> Option<Typed>, every: bool) -> Option<Typed> {
    let found = eval_node(node, known, every)?;
    // Over ranges alone, a value that could be any is not known.
    if !every && !found.0.is_known() {
        return None;
    }
    Some(found)
}

fn eval_node(node: &AstNode, known: &dyn Fn(&str) -> Option<Typed>, every: bool) -> Option<Typed> {
    let side = |node: &AstNode| eval_with(node, known, every);
    let truth = |holds: Option<bool>| Some((truth_value(holds), TRUTH));
    match node {
        AstNode::Constant { value, width_bytes } => {
            let bits = (width_bytes * 8).clamp(8, 64);
            let shift = 64 - bits;
            let signed = ((*value << shift) as i64) >> shift;
            Some((PossibleValues::Constant(signed as i128), (bits, true)))
        }
        AstNode::Var { name } => known(name),
        AstNode::Cast { ty, target } => {
            let ty = type_of(ty);
            let (values, _) = side(target)?;
            Some((values.convert(ty).within(ty), ty))
        }
        AstNode::ConditionTrue => truth(Some(true)),
        AstNode::ConditionFalse => truth(Some(false)),
        AstNode::ConstantCondition { holds, .. } => truth(Some(*holds)),
        AstNode::Ternary {
            cond,
            then,
            otherwise,
        } => match side(cond).and_then(|(values, _)| values.truth()) {
            Some(true) => side(then),
            Some(false) => side(otherwise),
            None => {
                let (a, ty) = side(then)?;
                let (b, _) = side(otherwise)?;
                Some((a.join(&b), ty))
            }
        },
        AstNode::Binary { lhs, op, rhs } => match op {
            BinaryOp::LogicalAnd | BinaryOp::LogicalOr => {
                let a = side(lhs).and_then(|(values, _)| values.truth());
                let b = side(rhs).and_then(|(values, _)| values.truth());
                let and = *op == BinaryOp::LogicalAnd;
                let holds = match (a, b) {
                    (Some(x), _) | (_, Some(x)) if x != and => Some(!and),
                    (Some(_), Some(_)) => Some(and),
                    _ => None,
                };
                truth(holds)
            }
            BinaryOp::Equal
            | BinaryOp::NotEqual
            | BinaryOp::Less
            | BinaryOp::LessEqual
            | BinaryOp::Greater
            | BinaryOp::GreaterEqual => {
                let holds = (|| {
                    let (a, ta) = side(lhs)?;
                    let (b, tb) = side(rhs)?;
                    let ty = usual(ta, tb);
                    compare_values(*op, &a.convert(ty), &b.convert(ty))
                })();
                truth(holds)
            }
            BinaryOp::Shl | BinaryOp::Shr => {
                // A shift has its left operand's type.
                let (a, ty) = side(lhs)?;
                let (count, _) = side(rhs)?;
                let PossibleValues::Constant(k) = count else {
                    return None;
                };
                if k < 0 || k >= i128::from(ty.0) {
                    return None;
                }
                let k = k as u32;
                let values = if *op == BinaryOp::Shl {
                    arithmetic(BinaryOp::Mul, &a, &PossibleValues::Constant(1 << k), ty)
                } else {
                    match (&a, a.finite()) {
                        (_, Some(values)) => {
                            PossibleValues::of_values(values.into_iter().map(|value| value >> k))
                        }
                        (PossibleValues::Range { min, max, step }, None) => {
                            let step = if step % (1 << k) == 0 { step >> k } else { 1 };
                            PossibleValues::range(min >> k, max >> k, step).within(ty)
                        }
                        _ => PossibleValues::Top,
                    }
                };
                Some((values, ty))
            }
            BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::And => {
                let (a, ta) = side(lhs)?;
                let (b, tb) = side(rhs)?;
                let ty = usual(ta, tb);
                Some((arithmetic(*op, &a.convert(ty), &b.convert(ty), ty), ty))
            }
            BinaryOp::Div | BinaryOp::Mod | BinaryOp::Or | BinaryOp::Xor if every => {
                let (a, ta) = side(lhs)?;
                let (b, tb) = side(rhs)?;
                let ty = usual(ta, tb);
                let (a, b) = (a.convert(ty), b.convert(ty));
                if a.finite().is_none() || b.finite().is_none() {
                    return Some((PossibleValues::Top, ty));
                }
                Some((arithmetic(*op, &a, &b, ty), ty))
            }
            _ => None,
        },
        _ => None,
    }
}

/// What a narrowing allows a value to be, in its type's numbers.
#[derive(Debug, Clone)]
enum Allowed {
    /// One of these ranges.
    Ranges(Vec<Range>),
    /// One of these values.
    Values(BTreeSet<i128>),
    /// None of these values.
    Except(BTreeSet<i128>),
}

impl Allowed {
    /// What `values` can be that is allowed, of type `ty`.
    fn meet(&self, values: &PossibleValues, ty: Ty) -> PossibleValues {
        match self {
            Self::Ranges(ranges) => ranges
                .iter()
                .fold(PossibleValues::Undetermined, |held, range| {
                    held.join(&values.meet_range(*range, ty))
                })
                .within(ty),
            Self::Values(allowed) => values.meet_values(allowed),
            Self::Except(barred) => values.except(barred),
        }
    }

    /// What is allowed of `v`, a value of type `from` in `within`, where
    /// `sign * v + offset`, wrapped in `to`, must be allowed; `None` where
    /// that is more than can be said.
    fn preimage(&self, sign: i128, offset: i128, from: Ty, to: Ty, within: Range) -> Option<Self> {
        let m = modulus(to);
        // The value of `v` whose image before the wrap is `target`; the
        // others are a multiple of `m` from it.
        let back = |target: i128| sign * (target - offset);
        let first = |lo: i128| {
            (within.lo - lo).div_euclid(m) + i128::from((within.lo - lo).rem_euclid(m) != 0)
        };
        let last = |hi: i128| (within.hi - hi).div_euclid(m);
        match self {
            Self::Ranges(ranges) => {
                let mut pieces = Vec::new();
                for range in ranges {
                    let (a, b) = (back(range.lo), back(range.hi));
                    let raw = Range {
                        lo: a.min(b),
                        hi: a.max(b),
                    };
                    let (k0, k1) = (first(raw.hi), last(raw.lo));
                    if k1 - k0 >= 4 {
                        return None;
                    }
                    for k in k0..=k1 {
                        let shifted = Range {
                            lo: raw.lo + k * m,
                            hi: raw.hi + k * m,
                        };
                        pieces.extend(shifted.intersect(within));
                    }
                }
                Some(Self::Ranges(pieces))
            }
            Self::Values(values) | Self::Except(values) => {
                let mut found = BTreeSet::new();
                for value in values {
                    let raw = back(*value);
                    let (k0, k1) = (first(raw), last(raw));
                    if k1 - k0 >= SET_LIMIT as i128 {
                        return None;
                    }
                    found.extend((k0..=k1).map(|k| raw + k * m));
                }
                match self {
                    Self::Values(_) => Some(Self::Values(found)),
                    // A value barred bars its preimages only where no other
                    // value maps onto them too.
                    _ if from.0 <= to.0 || full(to).covers(within) => Some(Self::Except(found)),
                    _ => None,
                }
            }
        }
    }
}

/// The analysis over one function's statement graph.
struct Analysis<'a> {
    graph: &'a Graph,
    nodes: BTreeMap<(usize, Part), AstNode>,
    /// The type of each variable the analysis follows, by its number.
    types: BTreeMap<usize, Ty>,
    /// The type of every declared variable, by name.
    declared: BTreeMap<String, Ty>,
    words: &'a [PinnedValue],
}

/// What each variable can be at a point, by its number; `None` where no
/// path reaches.
type State = Option<Vec<PossibleValues>>;

/// How many rounds a loop's head is joined before it is widened.
const WIDEN_AFTER: usize = 3;

/// How many rounds, without widening, take back what the loops bound.
const NARROWING_ROUNDS: usize = 2;

impl Analysis<'_> {
    /// What either state holds, each variable's values as its type reads
    /// them.
    fn join_states(&self, a: State, b: State) -> State {
        match (a, b) {
            (None, other) | (other, None) => other,
            (Some(a), Some(b)) => Some(
                a.iter()
                    .zip(&b)
                    .enumerate()
                    .map(|(var, (x, y))| self.join_in(x, y, var))
                    .collect(),
            ),
        }
    }

    /// What either can be, as the type of the variable `var` reads it.
    fn join_in(&self, a: &PossibleValues, b: &PossibleValues, var: usize) -> PossibleValues {
        match self.types.get(&var) {
            Some(ty) => a.join(b).within(*ty),
            None => a.join(b),
        }
    }

    fn ast(&self, n: usize) -> Option<&AstNode> {
        let node = &self.graph.nodes[n];
        self.nodes.get(&(node.owner?, node.part))
    }

    fn eval(&self, node: &AstNode, state: &[PossibleValues]) -> Option<Typed> {
        eval(node, &|name| {
            let id = *self.graph.vars.get(name)?;
            match self.types.get(&id) {
                Some(ty) => Some((state[id].clone(), *ty)),
                None => self.declared.get(name).map(|ty| (PossibleValues::Top, *ty)),
            }
        })
    }

    /// What follows a node: an assignment gives its variable its value, and
    /// an analyst's definition the analyst's value.
    fn transfer(&self, n: usize, state: &[PossibleValues]) -> Vec<PossibleValues> {
        let mut out = state.to_vec();
        let Some(node @ AstNode::Assign { lhs, rhs }) = self.ast(n) else {
            return out;
        };
        let AstNode::Var { name } = strip_casts(lhs) else {
            return out;
        };
        let Some(&id) = self.graph.vars.get(name) else {
            return out;
        };
        let Some(&ty) = self.types.get(&id) else {
            return out;
        };
        let value = match pin_index(node) {
            Some(index) => {
                let word = &self.words[index];
                PossibleValues::range(i128::from(word.min), i128::from(word.max), 1).within(ty)
            }
            None => match self.eval(rhs, state) {
                Some((values, _)) => values.convert(ty).within(ty),
                None => PossibleValues::Top,
            },
        };
        out[id] = match value {
            PossibleValues::Undetermined => PossibleValues::Top,
            value => value,
        };
        out
    }

    /// What holds on the way from `from` to `to`: the arms of the branch
    /// that go there narrow what its condition compares.
    fn follow(&self, state: &[PossibleValues], from: usize, to: usize) -> State {
        let arms: Vec<&Arm> = self.graph.nodes[from]
            .branches
            .iter()
            .filter(|(target, _)| *target == to)
            .map(|(_, arm)| arm)
            .collect();
        let cond = self.ast(from).map(|node| match node {
            AstNode::IfGoto { cond, .. } => cond.as_ref(),
            node => node,
        });
        let (false, Some(cond)) = (arms.is_empty(), cond) else {
            return Some(state.to_vec());
        };
        let mut joined: State = None;
        for arm in arms {
            let narrowed = match arm {
                Arm::Holds => self.narrow_truth(cond, true, state.to_vec()),
                Arm::Fails => self.narrow_truth(cond, false, state.to_vec()),
                Arm::Cases(values) | Arm::NoCase(values) => match self.eval(cond, state) {
                    Some((_, ty)) => {
                        let values: BTreeSet<i128> =
                            values.iter().map(|v| wrap(i128::from(*v), ty)).collect();
                        let allowed = if matches!(arm, Arm::Cases(_)) {
                            Allowed::Values(values)
                        } else {
                            Allowed::Except(values)
                        };
                        self.narrow(cond, ty, &allowed, state.to_vec())
                    }
                    None => Some(state.to_vec()),
                },
            };
            joined = self.join_states(joined, narrowed);
        }
        joined
    }

    /// What holds where `cond` holds, or fails.
    fn narrow_truth(&self, cond: &AstNode, holds: bool, state: Vec<PossibleValues>) -> State {
        if let Some((values, _)) = self.eval(cond, &state) {
            if values.truth() == Some(!holds) {
                return None;
            }
        }
        match cond {
            AstNode::ConditionTrue => holds.then_some(state),
            AstNode::ConditionFalse => (!holds).then_some(state),
            AstNode::ConstantCondition { holds: always, .. } => (*always == holds).then_some(state),
            AstNode::Binary { lhs, op, rhs } => match op {
                BinaryOp::LogicalAnd | BinaryOp::LogicalOr => {
                    // Both sides go the arm's way where `&&` holds or `||`
                    // fails; otherwise the left does, or the right.
                    if (*op == BinaryOp::LogicalAnd) == holds {
                        let state = self.narrow_truth(lhs, holds, state)?;
                        self.narrow_truth(rhs, holds, state)
                    } else {
                        let left = self.narrow_truth(lhs, holds, state.clone());
                        let right = self
                            .narrow_truth(lhs, !holds, state)
                            .and_then(|state| self.narrow_truth(rhs, holds, state));
                        self.join_states(left, right)
                    }
                }
                BinaryOp::Equal
                | BinaryOp::NotEqual
                | BinaryOp::Less
                | BinaryOp::LessEqual
                | BinaryOp::Greater
                | BinaryOp::GreaterEqual => {
                    let op = if holds {
                        *op
                    } else {
                        op.negated().expect("a comparison")
                    };
                    self.compare(lhs, op, rhs, state)
                }
                _ => self.truthy(cond, holds, state),
            },
            other => self.truthy(other, holds, state),
        }
    }

    /// What holds where a value is true — not 0 — or false.
    fn truthy(&self, node: &AstNode, holds: bool, state: Vec<PossibleValues>) -> State {
        let Some((_, ty)) = self.eval(node, &state) else {
            return Some(state);
        };
        let zero = BTreeSet::from([0]);
        let allowed = if holds {
            Allowed::Except(zero)
        } else {
            Allowed::Values(zero)
        };
        self.narrow(node, ty, &allowed, state)
    }

    /// What holds where the comparison `lhs op rhs` does.
    fn compare(
        &self,
        lhs: &AstNode,
        op: BinaryOp,
        rhs: &AstNode,
        state: Vec<PossibleValues>,
    ) -> State {
        let (Some((a, ta)), Some((b, tb))) = (self.eval(lhs, &state), self.eval(rhs, &state))
        else {
            return Some(state);
        };
        let ty = usual(ta, tb);
        let (a, b) = (a.convert(ty), b.convert(ty));
        let (Some(ha), Some(hb)) = (a.hull_in(ty), b.hull_in(ty)) else {
            return None;
        };
        let bounds = full(ty);
        let between = |lo: i128, hi: i128| {
            Allowed::Ranges(Range { lo, hi }.intersect(bounds).into_iter().collect())
        };
        let equal_to = |other: &PossibleValues, hull: Range| match other.finite() {
            Some(values) => Some(Allowed::Values(values.into_iter().collect())),
            None => other.is_known().then(|| Allowed::Ranges(vec![hull])),
        };
        let apart_from = |other: &PossibleValues| match other {
            PossibleValues::Constant(value) => Some(Allowed::Except(BTreeSet::from([*value]))),
            _ => None,
        };
        let (left, right) = match op {
            BinaryOp::Less => (
                Some(between(bounds.lo, hb.hi - 1)),
                Some(between(ha.lo + 1, bounds.hi)),
            ),
            BinaryOp::LessEqual => (
                Some(between(bounds.lo, hb.hi)),
                Some(between(ha.lo, bounds.hi)),
            ),
            BinaryOp::Greater => (
                Some(between(hb.lo + 1, bounds.hi)),
                Some(between(bounds.lo, ha.hi - 1)),
            ),
            BinaryOp::GreaterEqual => (
                Some(between(hb.lo, bounds.hi)),
                Some(between(bounds.lo, ha.hi)),
            ),
            BinaryOp::Equal => (equal_to(&b, hb), equal_to(&a, ha)),
            _ => (apart_from(&b), apart_from(&a)),
        };
        let mut state = state;
        if let Some(left) = left {
            state = self.narrow(lhs, ty, &left, state)?;
        }
        if let Some(right) = right {
            state = self.narrow(rhs, ty, &right, state)?;
        }
        Some(state)
    }

    /// What holds where `node`'s value, converted to `ty`, is allowed.
    fn narrow(
        &self,
        node: &AstNode,
        ty: Ty,
        allowed: &Allowed,
        mut state: Vec<PossibleValues>,
    ) -> State {
        let Some((current, own)) = self.eval(node, &state) else {
            return Some(state);
        };
        let hull = current.hull_in(own)?;
        // The node's values as it reads them: back through the conversion.
        let allowed = if own == ty {
            allowed.clone()
        } else {
            match allowed.preimage(1, 0, own, ty, hull) {
                Some(allowed) => allowed,
                None => return Some(state),
            }
        };
        if allowed.meet(&current, own) == PossibleValues::Undetermined {
            return None;
        }
        // A variable of a few values keeps those for which the node can be
        // allowed.
        if !matches!(node, AstNode::Var { .. }) {
            if let Some((id, values)) = self.sole_finite(node, &state) {
                let kept: Vec<i128> = values
                    .into_iter()
                    .filter(|value| {
                        let mut tried = state.clone();
                        tried[id] = PossibleValues::Constant(*value);
                        self.eval(node, &tried).is_none_or(|(result, _)| {
                            allowed.meet(&result, own) != PossibleValues::Undetermined
                        })
                    })
                    .collect();
                state[id] = PossibleValues::of_values(kept);
                if state[id] == PossibleValues::Undetermined {
                    return None;
                }
            }
        }
        match node {
            AstNode::Var { name } => {
                if let Some(&id) = self.graph.vars.get(name) {
                    if self.types.contains_key(&id) {
                        state[id] = allowed.meet(&state[id], own);
                        if state[id] == PossibleValues::Undetermined {
                            return None;
                        }
                    }
                }
                Some(state)
            }
            AstNode::Cast { target, .. } => self.narrow(target, own, &allowed, state),
            AstNode::Binary { lhs, op, rhs } => {
                let constant = |node: &AstNode| match self.eval(node, &state) {
                    Some((PossibleValues::Constant(value), _)) => Some(wrap(value, own)),
                    _ => None,
                };
                // An operand's values as the operation reads them, in its
                // type.
                let operand = |node: &AstNode| {
                    self.eval(node, &state)
                        .and_then(|(values, _)| values.convert(own).hull_in(own))
                };
                let (inner, sign, offset) = match (op, constant(lhs), constant(rhs)) {
                    // `x + c`, `x - c`: `x` is the value less `c`, or plus.
                    (BinaryOp::Add, _, Some(c)) => (lhs, 1, c),
                    (BinaryOp::Add, Some(c), _) => (rhs, 1, c),
                    (BinaryOp::Sub, _, Some(c)) => (lhs, 1, -c),
                    // `c - x`: `x` is `c` less the value.
                    (BinaryOp::Sub, Some(c), _) => (rhs, -1, c),
                    (BinaryOp::And, mask_l, mask_r) if mask_l.is_some() || mask_r.is_some() => {
                        // A value within a mask of low bits is itself.
                        let (mask, other) = match mask_r {
                            Some(mask) => (mask, lhs),
                            None => (mask_l.expect("a mask"), rhs),
                        };
                        let low = mask >= 0 && (mask + 1) & mask == 0;
                        return match operand(other) {
                            Some(range) if low && (Range { lo: 0, hi: mask }).covers(range) => {
                                self.narrow(other, own, &allowed, state)
                            }
                            _ => Some(state),
                        };
                    }
                    _ => return Some(state),
                };
                let Some(within) = operand(inner) else {
                    return Some(state);
                };
                match allowed.preimage(sign, offset, own, own, within) {
                    Some(allowed) => self.narrow(inner, own, &allowed, state),
                    None => Some(state),
                }
            }
            _ => Some(state),
        }
    }

    /// The one variable the analysis follows that `node` reads, with its
    /// values, when they are few enough to list.
    fn sole_finite(&self, node: &AstNode, state: &[PossibleValues]) -> Option<(usize, Vec<i128>)> {
        let names = std::cell::RefCell::new(BTreeSet::new());
        node.any(&|n| {
            if let AstNode::Var { name } = n {
                names.borrow_mut().insert(name.clone());
            }
            false
        });
        let names = names.into_inner();
        if names.len() != 1 {
            return None;
        }
        let id = *self.graph.vars.get(names.first()?)?;
        self.types.get(&id)?;
        Some((id, state[id].finite()?))
    }

    /// The state at the entry: any value, but where the analyst said.
    fn entry(&self) -> Vec<PossibleValues> {
        let mut state = vec![PossibleValues::Top; self.graph.vars.len()];
        let mut said: BTreeMap<usize, PossibleValues> = BTreeMap::new();
        for word in self.words.iter().filter(|word| word.at.is_none()) {
            let Some(&id) = self.graph.vars.get(&word.variable) else {
                continue;
            };
            let Some(&ty) = self.types.get(&id) else {
                continue;
            };
            let range = Range {
                lo: i128::from(word.min),
                hi: i128::from(word.max),
            };
            if word.min > word.max || !full(ty).covers(range) {
                continue;
            }
            let value = PossibleValues::range(range.lo, range.hi, 1).within(ty);
            let held = said.entry(id).or_insert(PossibleValues::Undetermined);
            *held = held.join(&value);
        }
        for (id, value) in said {
            state[id] = value;
        }
        state
    }

    /// What each node starts with and ends with, to a fixed point.
    fn run(&self) -> (Vec<State>, Vec<State>) {
        let count = self.graph.nodes.len();
        let mut preds = vec![Vec::new(); count];
        for (n, node) in self.graph.nodes.iter().enumerate() {
            for s in &node.succ {
                preds[*s].push(n);
            }
        }
        // The order of a depth-first walk from the entry, reversed, and the
        // nodes a back edge goes to: the loops' heads.
        let mut order = Vec::new();
        let mut heads = BTreeSet::new();
        let mut mark = vec![0u8; count];
        let mut stack = vec![(ENTRY, 0usize)];
        mark[ENTRY] = 1;
        while let Some((n, i)) = stack.pop() {
            match self.graph.nodes[n].succ.get(i) {
                Some(&s) => {
                    stack.push((n, i + 1));
                    match mark[s] {
                        0 => {
                            mark[s] = 1;
                            stack.push((s, 0));
                        }
                        1 => {
                            heads.insert(s);
                        }
                        _ => {}
                    }
                }
                None => {
                    mark[n] = 2;
                    order.push(n);
                }
            }
        }
        order.reverse();
        let mut position = vec![usize::MAX; count];
        for (i, n) in order.iter().enumerate() {
            position[*n] = i;
        }

        let mut before: Vec<State> = vec![None; count];
        let mut after: Vec<State> = vec![None; count];
        let entry = self.entry();
        after[ENTRY] = Some(entry.clone());
        before[ENTRY] = Some(entry);
        let incoming = |n: usize, after: &[State]| -> State {
            preds[n].iter().fold(None, |held, &p| {
                let came = after[p].as_ref().and_then(|state| self.follow(state, p, n));
                self.join_states(held, came)
            })
        };
        let mut visits = vec![0usize; count];
        let mut seen = vec![false; count];
        let mut pending: BTreeSet<usize> = self.graph.nodes[ENTRY]
            .succ
            .iter()
            .map(|s| position[*s])
            .collect();
        let mut budget = 64 * count + 1024;
        while let Some(at) = pending.pop_first() {
            let n = order[at];
            budget = budget.saturating_sub(1);
            let mut new = incoming(n, &after);
            if heads.contains(&n) {
                visits[n] += 1;
                if let (Some(old), Some(fresh)) = (&before[n], &new) {
                    let widen = visits[n] > WIDEN_AFTER;
                    new = Some(
                        old.iter()
                            .zip(fresh)
                            .enumerate()
                            .map(|(var, (old, fresh))| match self.types.get(&var) {
                                Some(ty) if widen => old.widen(fresh, *ty),
                                _ => self.join_in(old, fresh, var),
                            })
                            .collect(),
                    );
                } else if new.is_none() {
                    new = before[n].clone();
                }
            }
            if seen[n] && new == before[n] {
                continue;
            }
            if budget == 0 {
                // Past every bound: what is not settled is any value.
                new = new.map(|state| vec![PossibleValues::Top; state.len()]);
            }
            seen[n] = true;
            after[n] = new.as_ref().map(|state| self.transfer(n, state));
            before[n] = new;
            for s in &self.graph.nodes[n].succ {
                if position[*s] != usize::MAX {
                    pending.insert(position[*s]);
                }
            }
        }
        // Rounds without widening take back what the loops' conditions
        // bound.
        for _ in 0..NARROWING_ROUNDS {
            for &n in order.iter().filter(|&&n| n != ENTRY) {
                let new = incoming(n, &after);
                after[n] = new.as_ref().map(|state| self.transfer(n, state));
                before[n] = new;
            }
        }
        (before, after)
    }
}

/// What the variables one statement reads and writes can be there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementValues {
    /// The statement, by its index in the walk [`crate::dead::dead_indices`]
    /// counts by.
    pub index: usize,
    /// The addresses it came from: a `for`'s init and step with its own.
    pub addresses: Vec<u64>,
    /// The variables it reads, by name, with what each can be as it reads
    /// it.
    pub reads: Vec<(String, PossibleValues)>,
    /// The variables it assigns, with what each can be after.
    pub writes: Vec<(String, PossibleValues)>,
}

impl StatementValues {
    /// `a: 0..=9; b: 5`: the variables it reads that cannot be any value,
    /// with their values; `None` when there are none.
    pub fn note(&self) -> Option<String> {
        let said: Vec<String> = self
            .reads
            .iter()
            .filter(|(_, values)| values.is_known())
            .map(|(name, values)| format!("{name}: {values}"))
            .collect();
        (!said.is_empty()).then(|| said.join("; "))
    }
}

/// Whether the analysis follows a variable of type `ty`: an integer or a
/// pointer.
fn followed(ty: &str) -> bool {
    ty.trim_end().ends_with('*')
        || !["float", "double", "struct", "union", "[", "void"]
            .iter()
            .any(|word| ty.contains(word))
}

/// What the variables of `function` can be at each of its statements, in
/// the order of the walk, the analyst's `words` seeding it. A statement
/// that reads and writes none of the variables followed is left out.
pub fn possible_values(function: &LiftedFunction, words: &[PinnedValue]) -> Vec<StatementValues> {
    if function.thunk.is_some() {
        return Vec::new();
    }
    let declared: BTreeMap<String, Ty> = function
        .params
        .iter()
        .chain(&function.locals)
        .map(|v| (v.name.clone(), type_of(&v.ty)))
        .collect();
    let follows: BTreeSet<&str> = function
        .params
        .iter()
        .chain(&function.locals)
        .filter(|v| followed(&v.ty))
        .map(|v| v.name.as_str())
        .collect();

    // The words from an address on are definitions of their own there.
    let mut copy = function.clone();
    for (index, word) in words.iter().enumerate() {
        let (Some(at), Some(ty)) = (word.at, declared.get(&word.variable)) else {
            continue;
        };
        let range = Range {
            lo: i128::from(word.min),
            hi: i128::from(word.max),
        };
        if word.min > word.max
            || !follows.contains(word.variable.as_str())
            || !full(*ty).covers(range)
        {
            continue;
        }
        let pin = Statement::plain(
            AstNode::Assign {
                lhs: Box::new(AstNode::var(&word.variable)),
                rhs: Box::new(AstNode::Intrinsic {
                    name: PINNED.to_string(),
                    args: vec![
                        AstNode::var(&word.variable),
                        AstNode::constant(index as u64, 8),
                    ],
                }),
            },
            vec![at],
        );
        insert_pin(&mut copy.body, at, &word.variable, &pin);
    }
    // The statements of the copy, by their index in the function's walk;
    // `None` for a definition of the analyst's.
    let mut own = Vec::new();
    number(&copy.body, &mut 0, &mut own);

    let graph = Graph::of(&copy);
    let types: BTreeMap<usize, Ty> = graph
        .vars
        .iter()
        .filter(|(name, id)| follows.contains(name.as_str()) && !graph.memory.contains(id))
        .map(|(name, id)| (*id, declared[name]))
        .collect();
    let names: BTreeMap<usize, &str> = graph
        .vars
        .iter()
        .map(|(name, id)| (*id, name.as_str()))
        .collect();
    let analysis = Analysis {
        graph: &graph,
        nodes: nodes_of(&copy.body),
        types,
        declared,
        words,
    };
    let (before, after) = analysis.run();

    let mut found: BTreeMap<usize, StatementValues> = BTreeMap::new();
    for (n, node) in graph.nodes.iter().enumerate() {
        let Some(index) = node
            .owner
            .and_then(|owner| own.get(owner).copied().flatten())
        else {
            continue;
        };
        let value = |state: &State, var: usize| match state {
            Some(state) => state[var].clone(),
            None => PossibleValues::Undetermined,
        };
        let reads: Vec<(String, PossibleValues)> = node
            .uses
            .iter()
            .filter(|var| analysis.types.contains_key(var))
            .map(|&var| (names[&var].to_string(), value(&before[n], var)))
            .collect();
        let writes: Vec<(String, PossibleValues)> = node
            .defs
            .iter()
            .filter(|(var, kills)| *kills && analysis.types.contains_key(var))
            .map(|&(var, _)| (names[&var].to_string(), value(&after[n], var)))
            .collect();
        let entry = found.entry(index).or_insert_with(|| StatementValues {
            index,
            addresses: Vec::new(),
            reads: Vec::new(),
            writes: Vec::new(),
        });
        entry.addresses.extend(&node.addresses);
        for (into, more) in [(&mut entry.reads, reads), (&mut entry.writes, writes)] {
            for (name, values) in more {
                match into.iter_mut().find(|(held, _)| *held == name) {
                    Some((_, held)) => {
                        let var = graph.vars[&name];
                        *held = analysis.join_in(held, &values, var);
                    }
                    None => into.push((name, values)),
                }
            }
        }
    }
    found
        .into_values()
        .map(|mut statement| {
            statement.addresses.sort_unstable();
            statement.addresses.dedup();
            statement
        })
        .filter(|statement| !statement.reads.is_empty() || !statement.writes.is_empty())
        .collect()
}

/// Number the statements in the walk's order, skipping the analyst's
/// definitions: `own[i]` is the function's index of the copy's `i`th.
fn number(statements: &[Statement], next: &mut usize, own: &mut Vec<Option<usize>>) {
    for statement in statements {
        let pin =
            matches!(statement.kind, StatementKind::Plain) && pin_index(&statement.node).is_some();
        if pin {
            own.push(None);
        } else {
            own.push(Some(*next));
            *next += 1;
        }
        for child in statement.children() {
            number(child, next, own);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lift::{SwitchArm, Variable};

    fn var(name: &str) -> AstNode {
        AstNode::var(name)
    }

    fn c(value: u64) -> AstNode {
        AstNode::constant(value, 4)
    }

    fn bin(a: AstNode, op: BinaryOp, b: AstNode) -> AstNode {
        AstNode::binary(a, op, b)
    }

    fn assign(name: &str, rhs: AstNode, at: u64) -> Statement {
        Statement::plain(
            AstNode::Assign {
                lhs: Box::new(var(name)),
                rhs: Box::new(rhs),
            },
            vec![at],
        )
    }

    fn ret(value: AstNode, at: u64) -> Statement {
        Statement::plain(
            AstNode::Return {
                value: Some(Box::new(value)),
            },
            vec![at],
        )
    }

    fn if_(
        cond: AstNode,
        at: u64,
        then_part: Vec<Statement>,
        else_part: Vec<Statement>,
    ) -> Statement {
        Statement {
            node: cond,
            addresses: vec![at],
            kind: StatementKind::If {
                then_part,
                else_part,
            },
        }
    }

    fn call(name: &str) -> AstNode {
        AstNode::Call {
            callee: Box::new(AstNode::FunctionName {
                name: name.to_string(),
                address: 0x2000,
            }),
            args: Vec::new(),
        }
    }

    fn function(params: &[&str], locals: &[&str], body: Vec<Statement>) -> LiftedFunction {
        let variable = |name: &&str| Variable {
            ty: "int".to_string(),
            name: name.to_string(),
        };
        LiftedFunction {
            name: "f".to_string(),
            address: 0x1000,
            return_type: "int".to_string(),
            params: params.iter().map(variable).collect(),
            locals: locals.iter().map(variable).collect(),
            body,
            frame: Vec::new(),
            thunk: None,
            notes: Vec::new(),
            call_notes: Vec::new(),
            noreturn_when: Vec::new(),
            return_reason: None,
        }
    }

    fn statement_at(found: &[StatementValues], at: u64) -> &StatementValues {
        found
            .iter()
            .find(|s| s.addresses.contains(&at))
            .unwrap_or_else(|| panic!("a statement at {at:#x} in {found:#?}"))
    }

    /// What `name` is read as at the statement at `at`.
    fn read(found: &[StatementValues], at: u64, name: &str) -> String {
        let statement = statement_at(found, at);
        statement
            .reads
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, values)| values.to_string())
            .unwrap_or_else(|| panic!("{name} read at {at:#x} in {statement:#?}"))
    }

    /// What `name` is written as at the statement at `at`.
    fn written(found: &[StatementValues], at: u64, name: &str) -> String {
        let statement = statement_at(found, at);
        statement
            .writes
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, values)| values.to_string())
            .unwrap_or_else(|| panic!("{name} written at {at:#x} in {statement:#?}"))
    }

    #[test]
    fn the_lattice_is_spelled_and_joins() {
        use PossibleValues as V;
        assert_eq!(V::Constant(5).to_string(), "5");
        assert_eq!(V::of_values([7, 1, 3]).to_string(), "{1, 3, 7}");
        assert_eq!(V::range(0, 9, 1).to_string(), "0..=9");
        assert_eq!(V::range(0, 36, 4).to_string(), "0..=36 step 4");
        assert_eq!(V::Undetermined.to_string(), "undetermined");
        assert_eq!(V::Top.to_string(), "any");
        assert_eq!(V::Constant(1).join(&V::Constant(3)), V::of_values([1, 3]));
        // Past the limit, a set is the range that holds it, with its step.
        let evens = V::of_values((0..20).map(|v| v * 2));
        assert_eq!(evens.to_string(), "0..=38 step 2");
        assert_eq!(V::range(0, 4, 4), V::of_values([0, 4]));
        assert_eq!(V::range(0, 8, 4).join(&V::Constant(2)), V::range(0, 8, 2));
        assert_eq!(V::range(0, 8, 4).join(&V::Constant(20)), V::range(0, 20, 4));
        assert_eq!(
            V::range(0, 9, 1).meet_range(Range { lo: 3, hi: 20 }, TRUTH),
            V::range(3, 9, 1)
        );
        assert_eq!(
            V::range(0, 36, 4).meet_range(Range { lo: 3, hi: 13 }, TRUTH),
            V::range(4, 12, 4)
        );
        assert_eq!(
            V::Top.meet_range(Range { lo: 0, hi: 1 << 40 }, (32, false)),
            V::Top
        );
        assert_eq!(
            V::range(1, 5, 1).except(&BTreeSet::from([1, 5])),
            V::range(2, 4, 1)
        );
    }

    #[test]
    fn a_constant_goes_through_assignments() {
        // a = 5; b = a * 2 + 1; return b;
        let f = function(
            &[],
            &["a", "b"],
            vec![
                assign("a", c(5), 0x1000),
                assign(
                    "b",
                    bin(bin(var("a"), BinaryOp::Mul, c(2)), BinaryOp::Add, c(1)),
                    0x1004,
                ),
                ret(var("b"), 0x1008),
            ],
        );
        let found = possible_values(&f, &[]);
        assert_eq!(written(&found, 0x1000, "a"), "5");
        assert_eq!(read(&found, 0x1004, "a"), "5");
        assert_eq!(read(&found, 0x1008, "b"), "11");
    }

    #[test]
    fn two_constants_join_to_a_set() {
        // if (p > 0) { a = 1; } else { a = 7; } return a;
        let f = function(
            &["p"],
            &["a"],
            vec![
                if_(
                    bin(var("p"), BinaryOp::Greater, c(0)),
                    0x1000,
                    vec![assign("a", c(1), 0x1004)],
                    vec![assign("a", c(7), 0x1008)],
                ),
                ret(var("a"), 0x100c),
            ],
        );
        let found = possible_values(&f, &[]);
        assert_eq!(read(&found, 0x100c, "a"), "{1, 7}");
        assert_eq!(read(&found, 0x1000, "p"), "any");
        assert_eq!(found[0].note(), None);
        assert_eq!(
            found.last().and_then(StatementValues::note).as_deref(),
            Some("a: {1, 7}")
        );
    }

    #[test]
    fn a_comparison_bounds_each_arm() {
        // if (a < 10) { return a; } return a;
        let f = function(
            &["a"],
            &[],
            vec![
                if_(
                    bin(var("a"), BinaryOp::Less, c(10)),
                    0x1000,
                    vec![ret(var("a"), 0x1004)],
                    Vec::new(),
                ),
                ret(var("a"), 0x1008),
            ],
        );
        let found = possible_values(&f, &[]);
        assert_eq!(read(&found, 0x1004, "a"), "-2147483648..=9");
        assert_eq!(read(&found, 0x1008, "a"), "10..=2147483647");
        // Unsigned, the true arm starts at 0.
        let mut f = f;
        f.params[0].ty = "unsigned int".to_string();
        let found = possible_values(&f, &[]);
        assert_eq!(read(&found, 0x1004, "a"), "0..=9");
        // An equality is the value on its arm, and not it on the other.
        let f = function(
            &["a"],
            &[],
            vec![
                if_(
                    bin(var("a"), BinaryOp::Equal, c(3)),
                    0x1000,
                    vec![ret(var("a"), 0x1004)],
                    Vec::new(),
                ),
                ret(var("a"), 0x1008),
            ],
        );
        let found = possible_values(&f, &[]);
        assert_eq!(read(&found, 0x1004, "a"), "3");
        assert_eq!(read(&found, 0x1008, "a"), "any");
    }

    #[test]
    fn a_constraint_goes_back_through_an_invertible_expression() {
        // if (a >= 0 && a <= 100) { if (a + 1 < 10) { return a; }
        // return 5 - a; } return a;
        let f = function(
            &["a"],
            &[],
            vec![
                if_(
                    bin(
                        bin(var("a"), BinaryOp::GreaterEqual, c(0)),
                        BinaryOp::LogicalAnd,
                        bin(var("a"), BinaryOp::LessEqual, c(100)),
                    ),
                    0x1000,
                    vec![
                        if_(
                            bin(bin(var("a"), BinaryOp::Add, c(1)), BinaryOp::Less, c(10)),
                            0x1004,
                            vec![ret(var("a"), 0x1008)],
                            Vec::new(),
                        ),
                        ret(bin(c(5), BinaryOp::Sub, var("a")), 0x100c),
                    ],
                    Vec::new(),
                ),
                ret(var("a"), 0x1010),
            ],
        );
        let found = possible_values(&f, &[]);
        assert_eq!(read(&found, 0x1004, "a"), "0..=100");
        assert_eq!(read(&found, 0x1008, "a"), "0..=8");
        assert_eq!(read(&found, 0x100c, "a"), "9..=100");
        // Past the `&&`, either side may have failed.
        assert_eq!(read(&found, 0x1010, "a"), "any");
        // Where `a + 1` can wrap, `a + 1 < 10` holds of the greatest `int`
        // too, and nothing is said.
        let f = function(
            &["a"],
            &[],
            vec![if_(
                bin(bin(var("a"), BinaryOp::Add, c(1)), BinaryOp::Less, c(10)),
                0x1004,
                vec![ret(var("a"), 0x1008)],
                Vec::new(),
            )],
        );
        assert_eq!(read(&possible_values(&f, &[]), 0x1008, "a"), "any");
        // Through a cast: `(unsigned int)a > 5` fails only for `a` in
        // 0..=5.
        let f = function(
            &["a"],
            &[],
            vec![
                if_(
                    bin(
                        AstNode::Cast {
                            ty: "unsigned int".into(),
                            target: Box::new(var("a")),
                        },
                        BinaryOp::Greater,
                        c(5),
                    ),
                    0x1000,
                    vec![ret(c(0), 0x1004)],
                    Vec::new(),
                ),
                ret(var("a"), 0x1008),
            ],
        );
        assert_eq!(read(&possible_values(&f, &[]), 0x1008, "a"), "0..=5");
    }

    #[test]
    fn each_case_of_a_switch_has_its_value() {
        let arm = |values: Vec<i64>, at: u64| SwitchArm {
            values,
            body: vec![ret(var("a"), at)],
        };
        let f = function(
            &["a"],
            &[],
            vec![
                Statement {
                    node: AstNode::Cast {
                        ty: "unsigned long".into(),
                        target: Box::new(AstNode::Cast {
                            ty: "unsigned int".into(),
                            target: Box::new(var("a")),
                        }),
                    },
                    addresses: vec![0x1000],
                    kind: StatementKind::Switch {
                        arms: vec![
                            arm(vec![1], 0x1010),
                            arm(vec![2, 4], 0x1020),
                            arm(Vec::new(), 0x1030),
                        ],
                    },
                },
                ret(c(0), 0x1040),
            ],
        );
        let found = possible_values(&f, &[]);
        assert_eq!(read(&found, 0x1010, "a"), "1");
        assert_eq!(read(&found, 0x1020, "a"), "{2, 4}");
        assert_eq!(read(&found, 0x1030, "a"), "any");
    }

    #[test]
    fn a_loop_widens_to_a_fixed_point_and_its_condition_bounds_it() {
        // for (i = 0; i < 10; i = i + 1) { b = i * 4; } return i;
        let f = function(
            &[],
            &["i", "b"],
            vec![
                Statement {
                    node: bin(var("i"), BinaryOp::Less, c(10)),
                    addresses: vec![0x1004],
                    kind: StatementKind::For {
                        init: Box::new(assign("i", c(0), 0x1000)),
                        step: Box::new(assign("i", bin(var("i"), BinaryOp::Add, c(1)), 0x100c)),
                        body: vec![assign("b", bin(var("i"), BinaryOp::Mul, c(4)), 0x1008)],
                    },
                },
                ret(var("i"), 0x1010),
            ],
        );
        let found = possible_values(&f, &[]);
        assert_eq!(read(&found, 0x1004, "i"), "0..=10");
        assert_eq!(read(&found, 0x1008, "i"), "0..=9");
        assert_eq!(written(&found, 0x1008, "b"), "0..=36 step 4");
        assert_eq!(read(&found, 0x1010, "i"), "10");
        // A loop its condition does not bound reaches its fixed point too,
        // its step kept.
        let f = function(
            &["n"],
            &["i"],
            vec![
                assign("i", c(0), 0x1000),
                Statement {
                    node: bin(var("i"), BinaryOp::NotEqual, var("n")),
                    addresses: vec![0x1004],
                    kind: StatementKind::While {
                        body: vec![assign("i", bin(var("i"), BinaryOp::Add, c(2)), 0x1008)],
                    },
                },
                ret(var("i"), 0x100c),
            ],
        );
        let found = possible_values(&f, &[]);
        assert_eq!(read(&found, 0x1008, "i"), "-2147483648..=2147483646 step 2");
    }

    #[test]
    fn a_stride_comes_from_a_multiplication_and_a_shift() {
        // b = (a & 7) * 4; d = (a & 7) << 3; return b + d;
        let f = function(
            &["a"],
            &["b", "d"],
            vec![
                assign(
                    "b",
                    bin(bin(var("a"), BinaryOp::And, c(7)), BinaryOp::Mul, c(4)),
                    0x1000,
                ),
                assign(
                    "d",
                    bin(bin(var("a"), BinaryOp::And, c(7)), BinaryOp::Shl, c(3)),
                    0x1004,
                ),
                ret(bin(var("b"), BinaryOp::Add, var("d")), 0x1008),
            ],
        );
        let found = possible_values(&f, &[]);
        assert_eq!(written(&found, 0x1000, "b"), "0..=28 step 4");
        assert_eq!(written(&found, 0x1004, "d"), "0..=56 step 8");
        assert_eq!(read(&found, 0x1008, "b"), "0..=28 step 4");
    }

    #[test]
    fn the_analysts_value_seeds_it() {
        let pin = |at: Option<u64>, min: i64, max: i64| PinnedValue {
            variable: "a".to_string(),
            at,
            min,
            max,
        };
        // b = a + 1; a = g(); return a + b;
        let f = function(
            &["a"],
            &["b"],
            vec![
                assign("b", bin(var("a"), BinaryOp::Add, c(1)), 0x1000),
                assign("a", call("g"), 0x1004),
                ret(bin(var("a"), BinaryOp::Add, var("b")), 0x1008),
            ],
        );
        let found = possible_values(&f, &[pin(None, 0, 7)]);
        assert_eq!(read(&found, 0x1000, "a"), "0..=7");
        assert_eq!(written(&found, 0x1000, "b"), "1..=8");
        assert_eq!(read(&found, 0x1008, "a"), "any");
        // From an address on, of the value the statement there gives.
        let found = possible_values(&f, &[pin(Some(0x1004), 3, 3)]);
        assert_eq!(read(&found, 0x1000, "a"), "any");
        assert_eq!(read(&found, 0x1008, "a"), "3");
        // The analyst's definition is no statement of the function's.
        assert_eq!(found.iter().map(|s| s.index).collect::<Vec<_>>(), [0, 1, 2]);
    }

    #[test]
    fn an_arm_no_value_takes_is_undetermined() {
        // a = 3; if (a > 5) { return a; } return a;
        let f = function(
            &[],
            &["a"],
            vec![
                assign("a", c(3), 0x1000),
                if_(
                    bin(var("a"), BinaryOp::Greater, c(5)),
                    0x1004,
                    vec![ret(var("a"), 0x1008)],
                    Vec::new(),
                ),
                ret(var("a"), 0x100c),
            ],
        );
        let found = possible_values(&f, &[]);
        assert_eq!(read(&found, 0x1008, "a"), "undetermined");
        assert_eq!(read(&found, 0x100c, "a"), "3");
        // A few values keep those for which the condition goes the arm's
        // way.
        let f = function(
            &["p"],
            &["a"],
            vec![
                if_(
                    bin(var("p"), BinaryOp::Greater, c(0)),
                    0x1000,
                    vec![assign("a", c(3), 0x1004)],
                    vec![assign("a", c(12), 0x1008)],
                ),
                if_(
                    bin(bin(var("a"), BinaryOp::And, c(7)), BinaryOp::Equal, c(4)),
                    0x100c,
                    vec![ret(var("a"), 0x1010)],
                    Vec::new(),
                ),
                ret(var("a"), 0x1014),
            ],
        );
        let found = possible_values(&f, &[]);
        assert_eq!(read(&found, 0x1010, "a"), "12");
        assert_eq!(read(&found, 0x1014, "a"), "3");
    }
}
