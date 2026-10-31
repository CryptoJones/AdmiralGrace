//! Jump arrows in the listing's margin.
//!
//! A linear listing hides the shape of the control flow: a branch names
//! its target as an address, and the eye has to find it. The margin to the
//! left of the rows draws each branch as an arrow from its row to its
//! target's — down the margin for a jump forward, up it for a jump back,
//! each its own color — so loops and skips are visible at a glance.
//!
//! The arrows are the taken edges of the function's graph, the same ones
//! the Graph tab draws: a block's last instruction jumps to the block the
//! edge arrives at. A fall-through is no arrow. A jump out of the listing
//! — a tail call, a jump into another function — is a stub leaving the
//! margin to the left.
//!
//! Each arrow runs in a lane, the shortest arrows nearest the text; two
//! arrows share a lane when their rows do not overlap. The margin is drawn
//! a row at a time, as a small canvas beside each row, so it scrolls with
//! the rows and needs no knowledge of their height.

use iced::widget::canvas;
use iced::{mouse, Color, Element, Length, Point, Rectangle, Renderer, Theme};

use crate::app::Message;
use crate::data::Graph;
use crate::theme::color;

/// One branch, drawn from its row to its target's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arrow {
    /// The address of the branch.
    pub source: u64,
    /// The address it jumps to.
    pub target: u64,
    /// The row the branch is on.
    pub from: usize,
    /// The row the target is on, when it is in the listing.
    pub to: Option<usize>,
    /// The lane the arrow runs in: 0 nearest the text.
    pub lane: usize,
}

impl Arrow {
    /// Whether the arrow points down the listing.
    fn down(&self) -> bool {
        self.to.is_some_and(|to| to > self.from)
    }

    /// The first and last rows the arrow touches.
    fn span(&self) -> (usize, usize) {
        let to = self.to.unwrap_or(self.from);
        (self.from.min(to), self.from.max(to))
    }
}

/// The arrows of a listing, and how many lanes they take.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Arrows {
    pub arrows: Vec<Arrow>,
    pub lanes: usize,
}

/// The width of a lane.
pub const LANE_WIDTH: f32 = 7.0;
/// The room at the margin's right, where an arrow turns in to its row.
const TURN: f32 = 10.0;
/// No more lanes than this: an arrow past them shares the outermost.
pub const MOST_LANES: usize = 6;
/// The size of an arrowhead.
const HEAD: f32 = 5.0;

impl Arrows {
    /// The arrows of a listing whose rows are `rows` — the address of the
    /// instruction on each, or none for a row of the analyst's comment —
    /// drawn from the taken edges of `graph`.
    pub fn of(rows: &[Option<u64>], graph: &Graph) -> Self {
        let row_of = |address: u64| rows.iter().position(|row| *row == Some(address));
        let mut arrows: Vec<Arrow> = Vec::new();
        for edge in &graph.edges {
            if edge.kind != ag_image::EdgeKind::Taken {
                continue;
            }
            // The branch is the last instruction of the block the edge
            // leaves.
            let Some(block) = graph.blocks.iter().find(|block| block.from == edge.from) else {
                continue;
            };
            let source = block
                .instructions
                .last()
                .map_or(block.from, |line| line.address);
            let Some(from) = row_of(source) else {
                continue;
            };
            if arrows
                .iter()
                .any(|arrow| arrow.source == source && arrow.target == edge.to)
            {
                continue;
            }
            arrows.push(Arrow {
                source,
                target: edge.to,
                from,
                to: row_of(edge.to),
                lane: 0,
            });
        }
        // The shortest arrows nearest the text; an arrow takes the first
        // lane no arrow over the same rows has.
        arrows.sort_by_key(|arrow| {
            let (first, last) = arrow.span();
            (last - first, first, arrow.target)
        });
        let mut taken: Vec<Vec<(usize, usize)>> = Vec::new();
        for arrow in &mut arrows {
            let span = arrow.span();
            let free = taken
                .iter()
                .position(|spans| spans.iter().all(|other| !overlap(*other, span)));
            let lane = match free {
                Some(lane) => lane,
                None if taken.len() < MOST_LANES => {
                    taken.push(Vec::new());
                    taken.len() - 1
                }
                None => MOST_LANES - 1,
            };
            taken[lane].push(span);
            arrow.lane = lane;
        }
        let lanes = taken.len();
        Self { arrows, lanes }
    }

    /// The width of the margin: room for every lane, and one lane's worth
    /// when there are none, so the rows do not shift as the function
    /// changes.
    pub fn width(&self) -> f32 {
        TURN + self.lanes.max(1) as f32 * LANE_WIDTH
    }

    /// The margin beside row `row`: the pieces of every arrow that passes,
    /// starts or ends there, the ones to or from `selected` brightened.
    pub fn margin(&self, row: usize, selected: Option<u64>) -> Element<'static, Message> {
        let mut pieces = Vec::new();
        for arrow in &self.arrows {
            let (first, last) = arrow.span();
            if row < first || row > last {
                continue;
            }
            let bright =
                selected.is_some_and(|address| address == arrow.source || address == arrow.target);
            let tint = match (bright, arrow.to, arrow.down()) {
                (true, _, _) => color::CYAN,
                (false, None, _) => color::MUTED,
                (false, Some(_), true) => color::BLUE,
                (false, Some(_), false) => color::AMBER,
            };
            let shape = match arrow.to {
                None => Shape::Out,
                Some(to) if to == arrow.from => Shape::Here,
                Some(to) => {
                    let down = to > arrow.from;
                    if row == arrow.from {
                        Shape::Start { down }
                    } else if row == to {
                        Shape::End { down }
                    } else {
                        Shape::Through
                    }
                }
            };
            pieces.push(Piece {
                lane: arrow.lane,
                shape,
                tint,
            });
        }
        canvas(Margin {
            width: self.width(),
            pieces,
        })
        .width(Length::Fixed(self.width()))
        .height(Length::Fill)
        .into()
    }
}

/// Whether two row spans share a row.
fn overlap(a: (usize, usize), b: (usize, usize)) -> bool {
    a.0 <= b.1 && b.0 <= a.1
}

/// The part of an arrow on one row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// The arrow passes this row in its lane.
    Through,
    /// The arrow leaves this row, going down or up.
    Start { down: bool },
    /// The arrow arrives at this row from above (`down`) or below.
    End { down: bool },
    /// The branch jumps to itself.
    Here,
    /// The branch leaves the listing.
    Out,
}

#[derive(Debug, Clone, PartialEq)]
struct Piece {
    lane: usize,
    shape: Shape,
    tint: Color,
}

/// The margin beside one row.
#[derive(Debug, Clone, PartialEq)]
struct Margin {
    width: f32,
    pieces: Vec<Piece>,
}

impl Margin {
    /// Where lane `lane` runs: lane 0 just left of the turn-in room.
    fn lane_x(&self, lane: usize) -> f32 {
        self.width - TURN - LANE_WIDTH / 2.0 - lane as f32 * LANE_WIDTH
    }
}

impl canvas::Program<Message> for Margin {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let height = bounds.height;
        let mid = (height / 2.0).round() + 0.5;
        let right = self.width - 1.0;
        for piece in &self.pieces {
            let x = self.lane_x(piece.lane).round() + 0.5;
            let stroke = canvas::Stroke::default()
                .with_color(piece.tint)
                .with_width(1.5);
            let line = |frame: &mut canvas::Frame, points: &[Point]| {
                let path = canvas::Path::new(|builder| {
                    builder.move_to(points[0]);
                    for point in &points[1..] {
                        builder.line_to(*point);
                    }
                });
                frame.stroke(&path, stroke);
            };
            match piece.shape {
                Shape::Through => {
                    line(&mut frame, &[Point::new(x, 0.0), Point::new(x, height)]);
                }
                Shape::Start { down } => {
                    let end = if down { height } else { 0.0 };
                    line(
                        &mut frame,
                        &[
                            Point::new(right, mid),
                            Point::new(x, mid),
                            Point::new(x, end),
                        ],
                    );
                }
                Shape::End { down } => {
                    let start = if down { 0.0 } else { height };
                    line(
                        &mut frame,
                        &[
                            Point::new(x, start),
                            Point::new(x, mid),
                            Point::new(right - HEAD, mid),
                        ],
                    );
                    frame.fill(
                        &head(Point::new(right, mid), Point::new(x, mid)),
                        piece.tint,
                    );
                }
                Shape::Here => {
                    // Out above the middle, back in below it.
                    let (above, below) = (mid - 3.0, mid + 3.0);
                    line(
                        &mut frame,
                        &[
                            Point::new(right, above),
                            Point::new(x, above),
                            Point::new(x, below),
                            Point::new(right - HEAD, below),
                        ],
                    );
                    frame.fill(
                        &head(Point::new(right, below), Point::new(x, below)),
                        piece.tint,
                    );
                }
                Shape::Out => {
                    // Off to the left, past every lane.
                    line(
                        &mut frame,
                        &[Point::new(right, mid), Point::new(HEAD + 1.0, mid)],
                    );
                    frame.fill(
                        &head(Point::new(1.0, mid), Point::new(right, mid)),
                        piece.tint,
                    );
                }
            }
        }
        vec![frame.into_geometry()]
    }
}

/// An arrowhead at `tip`, pointing away from `from`.
fn head(tip: Point, from: Point) -> canvas::Path {
    let dx = tip.x - from.x;
    let dy = tip.y - from.y;
    let length = (dx * dx + dy * dy).sqrt().max(0.0001);
    let (ux, uy) = (dx / length, dy / length);
    let (px, py) = (-uy, ux);
    let base = Point::new(tip.x - ux * HEAD, tip.y - uy * HEAD);
    canvas::Path::new(|builder| {
        builder.move_to(tip);
        builder.line_to(Point::new(
            base.x + px * HEAD * 0.5,
            base.y + py * HEAD * 0.5,
        ));
        builder.line_to(Point::new(
            base.x - px * HEAD * 0.5,
            base.y - py * HEAD * 0.5,
        ));
        builder.close();
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{GraphBlock, ListingLine};

    fn line(address: u64) -> ListingLine {
        ListingLine {
            address,
            bytes: String::new(),
            mnemonic: "nop".into(),
            operands: String::new(),
            call_target: None,
            registers: Vec::new(),
            comment: None,
        }
    }

    fn block(from: u64, to: u64, successors: Vec<u64>) -> GraphBlock {
        GraphBlock {
            from,
            to,
            successors,
            instructions: (from..to).step_by(4).map(line).collect(),
        }
    }

    fn graph_of(blocks: Vec<GraphBlock>) -> Graph {
        let edges = Graph::edges_of_blocks(&blocks);
        Graph { blocks, edges }
    }

    #[test]
    fn a_branch_is_an_arrow_from_its_row_to_its_targets_row() {
        // 0x1000..0x1008 falls to 0x1008 or jumps to 0x100c; 0x100c jumps
        // back to 0x1000 or falls to 0x1010, which returns.
        let graph = graph_of(vec![
            block(0x1000, 0x1008, vec![0x1008, 0x100c]),
            block(0x1008, 0x100c, vec![0x100c]),
            block(0x100c, 0x1010, vec![0x1000, 0x1010]),
            block(0x1010, 0x1014, vec![]),
        ]);
        let rows: Vec<Option<u64>> = (0x1000..0x1014).step_by(4).map(Some).collect();
        let arrows = Arrows::of(&rows, &graph);
        let mut found: Vec<(u64, u64, usize, Option<usize>)> = arrows
            .arrows
            .iter()
            .map(|arrow| (arrow.source, arrow.target, arrow.from, arrow.to))
            .collect();
        found.sort_unstable();
        assert_eq!(
            found,
            [(0x1004, 0x100c, 1, Some(3)), (0x100c, 0x1000, 3, Some(0)),]
        );
        let back = arrows
            .arrows
            .iter()
            .find(|arrow| arrow.target == 0x1000)
            .unwrap();
        assert!(!back.down());
        // The two overlap on rows 1..3, so they take two lanes; the
        // shorter is nearest the text.
        assert_eq!(arrows.lanes, 2);
        let forward = arrows
            .arrows
            .iter()
            .find(|arrow| arrow.target == 0x100c)
            .unwrap();
        assert_ne!(forward.lane, back.lane);
        assert_eq!(forward.lane, 0);
        assert_eq!(arrows.width(), TURN + 2.0 * LANE_WIDTH);
    }

    #[test]
    fn arrows_over_different_rows_share_a_lane_and_comment_rows_count() {
        // Two skips one after the other, with a comment row above the
        // second block's first instruction.
        let graph = graph_of(vec![
            block(0x1000, 0x1008, vec![0x1008, 0x100c]),
            block(0x1008, 0x100c, vec![0x100c]),
            block(0x100c, 0x1014, vec![0x1014, 0x1018]),
            block(0x1014, 0x1018, vec![0x1018]),
            block(0x1018, 0x101c, vec![]),
        ]);
        let mut rows: Vec<Option<u64>> = Vec::new();
        for address in (0x1000..0x101c).step_by(4) {
            if address == 0x1008 {
                rows.push(None);
            }
            rows.push(Some(address));
        }
        let arrows = Arrows::of(&rows, &graph);
        assert_eq!(arrows.arrows.len(), 2);
        assert_eq!(arrows.lanes, 1);
        let first = arrows
            .arrows
            .iter()
            .find(|arrow| arrow.target == 0x100c)
            .unwrap();
        // The comment row sits between the branch and its target.
        assert_eq!((first.from, first.to), (1, Some(4)));
        assert!(first.down());
    }

    #[test]
    fn a_jump_out_of_the_listing_is_a_stub_and_a_graph_without_branches_has_a_margin() {
        let graph = graph_of(vec![block(0x1000, 0x1008, vec![0x2000])]);
        let rows = vec![Some(0x1000), Some(0x1004)];
        let arrows = Arrows::of(&rows, &graph);
        assert_eq!(arrows.arrows.len(), 1);
        assert_eq!(arrows.arrows[0].to, None);
        assert_eq!(arrows.arrows[0].from, 1);
        assert!(!arrows.arrows[0].down());
        let none = Arrows::of(&rows, &graph_of(vec![block(0x1000, 0x1008, vec![])]));
        assert!(none.arrows.is_empty());
        assert_eq!(none.lanes, 0);
        assert_eq!(none.width(), TURN + LANE_WIDTH);
    }

    #[test]
    fn the_lanes_are_capped() {
        // Nested skips, each inside the last: more than the lanes allow.
        let n = MOST_LANES + 3;
        let mut blocks = Vec::new();
        let step = 4;
        for i in 0..n {
            let from = 0x1000 + (i * step) as u64;
            let to = from + step as u64;
            let target = 0x1000 + ((2 * n - i) * step) as u64;
            blocks.push(block(from, to, vec![to, target]));
        }
        let rest_from = 0x1000 + (n * step) as u64;
        let end = 0x1000 + ((2 * n + 1) * step) as u64;
        blocks.push(block(rest_from, end, vec![]));
        let graph = graph_of(blocks);
        let rows: Vec<Option<u64>> = (0x1000..end).step_by(step).map(Some).collect();
        let arrows = Arrows::of(&rows, &graph);
        assert_eq!(arrows.arrows.len(), n);
        assert_eq!(arrows.lanes, MOST_LANES);
        assert!(arrows.arrows.iter().all(|arrow| arrow.lane < MOST_LANES));
    }
}
