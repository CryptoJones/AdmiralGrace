//! The control-flow graph view.
//!
//! The layout is pure: it takes the blocks of a function and says where
//! every block is drawn, so it can be tested without a window. The canvas
//! on top of it draws the blocks, the edges between them, and takes the
//! mouse: a click picks a block, a drag moves the graph, the wheel zooms
//! it.

use std::collections::{HashMap, HashSet};

use iced::mouse;
use iced::widget::canvas;
use iced::widget::text::{Alignment, LineHeight, Shaping};
use iced::{Color, Element, Length, Pixels, Point, Rectangle, Renderer, Size, Theme, Vector};

use crate::app::{App, Message};
use crate::data::{Graph, GraphBlock, ListingLine};
use crate::theme::{color, tinted, MONO};

/// The width of a block, in graph units.
pub const NODE_WIDTH: f32 = 570.0;
/// The height of one line of instructions.
pub const LINE_HEIGHT: f32 = 15.0;
/// The height of the header of a block.
pub const HEADER_HEIGHT: f32 = 22.0;
/// The padding inside a block.
pub const PADDING: f32 = 8.0;
/// The gap between two blocks that sit side by side.
pub const GAP_X: f32 = 56.0;
/// The gap between two rows of blocks.
pub const GAP_Y: f32 = 44.0;

/// The room a route takes to the side of a row of blocks.
const LANE: f32 = 28.0;
/// The smallest zoom the reader can choose.
pub const MIN_ZOOM: f32 = 0.2;
/// The largest zoom the reader can choose.
pub const MAX_ZOOM: f32 = 4.0;

/// How far the mouse has to move for a press to be a drag, not a click.
const CLICK_SLOP: f32 = 4.0;

/// One line of a block, as the graph draws it.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphLine {
    /// The address of the instruction.
    pub address: String,
    /// The bytes of the instruction.
    pub bytes: String,
    /// The mnemonic of the instruction.
    pub mnemonic: String,
    /// The operands of the instruction.
    pub operands: String,
    /// The analyst's note at this address, when one is there.
    pub comment: Option<String>,
    /// Whether the note stands on its own line above the instruction,
    /// rather than inline at the end of it.
    pub comment_above: bool,
    /// The row the instruction is drawn on, counting the comment lines the
    /// block inserts above it.
    pub row: usize,
    /// The analyst's highlight on this one line, when there is one.
    pub color: Option<Color>,
}

impl GraphLine {
    /// The line of a listing instruction.
    ///
    /// A call shows the callee by the analyst's name when it has one, so
    /// the graph reads the same as the listing beside it. The analyst's note
    /// rides with it: inline at the end, or on a row of its own above.
    fn of(line: &ListingLine, renamed: &crate::app::Renames) -> Self {
        let note = renamed.comment_for(line.address);
        Self {
            address: format!("{:08X}", line.address),
            bytes: short_bytes(&line.bytes),
            mnemonic: line.mnemonic.clone(),
            operands: crate::app::App::shown_operands(line, renamed),
            comment: note.map(|note| note.text.clone()),
            comment_above: note.is_some_and(|note| note.above),
            row: 0,
            color: renamed.address_color(line.address),
        }
    }

    /// How many rows this instruction takes: one, plus one more when its
    /// note stands above it.
    fn rows(&self) -> usize {
        if self.comment_above {
            2
        } else {
            1
        }
    }
}

/// How many bytes of an instruction the graph shows.
const MAX_BYTES: usize = 8;

/// The bytes of an instruction, cut short when there are many.
///
/// The block is a fixed width, so a long instruction is shown with its
/// first bytes and a mark that says the rest was left out.
fn short_bytes(bytes: &str) -> String {
    let mut out = String::new();

    for (kept, part) in bytes.split_whitespace().enumerate() {
        if kept == MAX_BYTES {
            out.push('\u{2026}');
            break;
        }

        if !out.is_empty() {
            out.push(' ');
        }

        out.push_str(part);
    }

    out
}

/// One block of the graph, and where it is drawn.
#[derive(Debug, Clone)]
pub struct GraphNode {
    /// Where the block starts.
    pub from: u64,
    /// Where the block ends.
    pub to: u64,
    /// The row the block sits in.
    pub rank: usize,
    /// The left edge of the block.
    pub x: f32,
    /// The top edge of the block.
    pub y: f32,
    /// The width of the block.
    pub width: f32,
    /// The height of the block.
    pub height: f32,
    /// The instructions of the block.
    pub lines: Vec<GraphLine>,
    /// Whether the block goes on in more than one way.
    pub branching: bool,
    /// The analyst's highlight on the block — its own, or its function's —
    /// when there is one.
    pub color: Option<Color>,
    /// The analyst's text on the block, when there is one: its title, in
    /// place of the range of addresses.
    pub label: Option<String>,
    /// The group the node stands for, when it is several blocks drawn as
    /// one: the group's name, and how many blocks are in it.
    pub group: Option<(String, usize)>,
    /// The blocks the node stands for, as `(from, to)`: the one block, or
    /// a group's members — which need not be side by side, so the span
    /// from `from` to `to` may hold blocks of other nodes.
    pub members: Vec<(u64, u64)>,
}

impl GraphNode {
    /// Whether `address` is in a block the node stands for.
    pub fn contains(&self, address: u64) -> bool {
        self.members
            .iter()
            .any(|(from, to)| *from <= address && address < *to)
    }
}

/// A way the selection moves through the graph by the keyboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// To a block that reaches this one.
    Up,
    /// To a block this one goes on to.
    Down,
    /// To the block beside this one on the left.
    Left,
    /// To the block beside this one on the right.
    Right,
}

/// An edge between two blocks.
#[derive(Debug, Clone)]
pub struct GraphEdge {
    /// The block the edge leaves.
    pub from: u64,
    /// The block the edge arrives at.
    pub to: u64,
    /// What the edge means.
    ///
    /// The kind comes from the provider, worked out by the rule the CLI
    /// reports by, so the workbench and the command line name an edge the
    /// same way.
    pub kind: ag_image::EdgeKind,
    /// The points the edge is drawn through, in graph units.
    pub route: Vec<Point>,
}

impl GraphEdge {
    /// The point the label of the edge sits at, in graph units.
    ///
    /// The label sits at the last bend of the route, so every edge that
    /// leaves a block names itself by the block it goes to.
    pub fn label_point(&self) -> Option<Point> {
        if self.route.len() < 2 {
            return None;
        }

        Some(self.route[self.route.len() - 2])
    }
}

/// A row of blocks in the graph.
#[derive(Debug, Clone, Copy)]
pub struct GraphRow {
    /// The top of the row.
    pub y: f32,
    /// The bottom of the row.
    pub bottom: f32,
}

/// The graph of a function, laid out.
#[derive(Debug, Clone, Default)]
pub struct GraphLayout {
    /// The blocks, in the order they were laid out.
    pub nodes: Vec<GraphNode>,
    /// The edges between the blocks.
    pub edges: Vec<GraphEdge>,
    /// The width of the whole graph.
    pub width: f32,
    /// The height of the whole graph.
    pub height: f32,
}

/// How the graph is drawn in a viewport.
#[derive(Debug, Clone, Copy)]
pub struct View {
    /// How big the graph is drawn.
    pub scale: f32,
    /// Where the top left corner of the graph is drawn.
    pub offset: Point,
}

/// Lay a control-flow graph out.
///
/// The blocks are ranked by a depth-first walk from the entry block: the
/// block the walk starts at is at the top, the ones it reaches next are
/// below it. The blocks of a rank sit side by side, in address order, and
/// the ranks stack.
///
/// The edges come from the provider, with the kind each edge has, and are
/// routed around the blocks they do not connect.
pub fn layout(graph: &Graph, renamed: &crate::app::Renames) -> GraphLayout {
    // The blocks the analyst grouped are drawn as one: every group is one
    // synthetic block spanning its members, with the ways out of the group
    // as its successors, and one line per member.
    let (grouped, groups) = grouped_blocks(graph, renamed);
    let blocks = &grouped;

    let mut nodes: Vec<GraphNode> = blocks
        .iter()
        .map(|block| {
            if let Some((name, members)) = groups.get(&block.from) {
                let lines: Vec<GraphLine> = members
                    .iter()
                    .enumerate()
                    .map(|(row, (from, to, count))| GraphLine {
                        address: format!("{from:08X}"),
                        bytes: String::new(),
                        mnemonic: format!("{from:#x} - {to:#x}"),
                        operands: format!(
                            "{count} instruction{}",
                            if *count == 1 { "" } else { "s" }
                        ),
                        comment: None,
                        comment_above: false,
                        row,
                        color: None,
                    })
                    .collect();
                let height = HEADER_HEIGHT + PADDING * 2.0 + lines.len() as f32 * LINE_HEIGHT;
                return GraphNode {
                    from: block.from,
                    to: block.to,
                    rank: 0,
                    x: 0.0,
                    y: 0.0,
                    width: NODE_WIDTH,
                    height,
                    lines,
                    branching: block.successors.len() > 1,
                    color: renamed.block_color(block.from).or(renamed.function_color()),
                    label: renamed.block_label(block.from).map(str::to_string),
                    group: Some((name.clone(), members.len())),
                    members: members.iter().map(|(from, to, _)| (*from, *to)).collect(),
                };
            }
            // Each instruction takes a row, and an above-comment takes one
            // more over it. The rows are numbered as they are laid out so
            // the painter draws a note directly over its instruction, and
            // the block grows to hold every row it inserts.
            let mut row = 0;
            let lines: Vec<GraphLine> = block
                .instructions
                .iter()
                .map(|line| {
                    let mut graph_line = GraphLine::of(line, renamed);
                    if graph_line.comment_above {
                        graph_line.row = row + 1;
                    } else {
                        graph_line.row = row;
                    }
                    row += graph_line.rows();
                    graph_line
                })
                .collect();
            let height = HEADER_HEIGHT + PADDING * 2.0 + row as f32 * LINE_HEIGHT;
            GraphNode {
                from: block.from,
                to: block.to,
                rank: 0,
                x: 0.0,
                y: 0.0,
                width: NODE_WIDTH,
                height,
                lines,
                branching: block.successors.len() > 1,
                // The block's own color, or the function's for every
                // block the analyst did not color apart.
                color: renamed.block_color(block.from).or(renamed.function_color()),
                label: renamed.block_label(block.from).map(str::to_string),
                group: None,
                members: vec![(block.from, block.to)],
            }
        })
        .collect();

    for (node, rank) in nodes.iter_mut().zip(ranks(blocks)) {
        node.rank = rank;
    }

    // The blocks of a rank sit side by side, and the ranks stack.
    let mut rows: Vec<Vec<usize>> = Vec::new();

    for (index, node) in nodes.iter().enumerate() {
        while rows.len() <= node.rank {
            rows.push(Vec::new());
        }

        rows[node.rank].push(index);
    }

    let mut y = 0.0_f32;
    let mut graph_rows: Vec<GraphRow> = Vec::new();

    for row in &rows {
        let mut row_height = 0.0_f32;

        for (column, index) in row.iter().enumerate() {
            let node = &mut nodes[*index];
            node.x = column as f32 * (NODE_WIDTH + GAP_X);
            node.y = y;
            row_height = row_height.max(node.height);
        }

        graph_rows.push(GraphRow {
            y,
            bottom: y + row_height,
        });

        y += row_height + GAP_Y;
    }

    let mut edges = drawn_edges(graph);
    // An edge into or out of a group's member is the group's; one inside
    // the group is not drawn; the same way twice is drawn once.
    if !groups.is_empty() {
        let node_of = |address: u64| -> u64 {
            groups
                .iter()
                .find(|(_, (_, members))| members.iter().any(|(from, _, _)| *from == address))
                .map(|(from, _)| *from)
                .unwrap_or(address)
        };
        for edge in &mut edges {
            edge.from = node_of(edge.from);
            edge.to = node_of(edge.to);
        }
        edges.retain(|edge| edge.from != edge.to || !groups.contains_key(&edge.from));
        // The first of the two keeps its kind: a node standing for several
        // blocks has no one way out to color the arrow by.
        let mut seen = HashSet::new();
        edges.retain(|edge| seen.insert((edge.from, edge.to)));
    }

    // Every edge is routed around the blocks it does not connect.
    for edge in &mut edges {
        let source = nodes.iter().find(|node| node.from == edge.from);
        let target = nodes.iter().find(|node| node.from == edge.to);

        if let (Some(source), Some(target)) = (source, target) {
            edge.route = route(&nodes, &graph_rows, source, target);
        }
    }

    // The routes run to the side of the blocks, so the graph is moved
    // until everything is inside it.
    let left = nodes
        .iter()
        .map(|node| node.x)
        .chain(
            edges
                .iter()
                .flat_map(|edge| edge.route.iter().map(|point| point.x)),
        )
        .fold(f32::INFINITY, f32::min);

    if left.is_finite() && left != 0.0 {
        for node in &mut nodes {
            node.x -= left;
        }

        for edge in &mut edges {
            for point in &mut edge.route {
                point.x -= left;
            }
        }
    }

    let width = nodes
        .iter()
        .map(|node| node.x + node.width)
        .chain(
            edges
                .iter()
                .flat_map(|edge| edge.route.iter().map(|point| point.x)),
        )
        .fold(0.0_f32, f32::max);

    let height = nodes
        .iter()
        .map(|node| node.y + node.height)
        .chain(
            edges
                .iter()
                .flat_map(|edge| edge.route.iter().map(|point| point.y)),
        )
        .fold(0.0_f32, f32::max);

    GraphLayout {
        nodes,
        edges,
        width,
        height,
    }
}

/// The blocks of a graph with the analyst's groups merged: each group is
/// one block spanning its members, its successors the ways out of the
/// group; and, by the merged block's start, each group's name and its
/// members as `(from, to, instructions)`. A block in no group is itself.
#[allow(clippy::type_complexity)]
fn grouped_blocks(
    graph: &Graph,
    renamed: &crate::app::Renames,
) -> (
    Vec<GraphBlock>,
    HashMap<u64, (String, Vec<(u64, u64, usize)>)>,
) {
    let mut by_name: Vec<(String, Vec<&GraphBlock>)> = Vec::new();
    for block in &graph.blocks {
        if let Some(name) = renamed.block_group(block.from) {
            match by_name.iter_mut().find(|(group, _)| group == name) {
                Some((_, members)) => members.push(block),
                None => by_name.push((name.to_string(), vec![block])),
            }
        }
    }
    if by_name.is_empty() {
        return (graph.blocks.clone(), HashMap::new());
    }
    // Every member's start is the start of its group, so a way into a
    // member of any group — this one or another — is a way to the group.
    let mut merged: HashMap<u64, u64> = HashMap::new();
    for (_, members) in &by_name {
        let from = members.iter().map(|block| block.from).min().unwrap_or(0);
        for block in members {
            merged.insert(block.from, from);
        }
    }
    let mut groups = HashMap::new();
    let mut blocks = Vec::new();
    for (name, members) in &by_name {
        let from = members.iter().map(|block| block.from).min().unwrap_or(0);
        let to = members.iter().map(|block| block.to).max().unwrap_or(0);
        let mut successors: Vec<u64> = members
            .iter()
            .flat_map(|block| block.successors.iter().copied())
            .map(|successor| merged.get(&successor).copied().unwrap_or(successor))
            .filter(|successor| *successor != from)
            .collect();
        successors.sort_unstable();
        successors.dedup();
        groups.insert(
            from,
            (
                name.clone(),
                members
                    .iter()
                    .map(|block| (block.from, block.to, block.instructions.len()))
                    .collect(),
            ),
        );
        blocks.push(GraphBlock {
            from,
            to,
            successors,
            instructions: Vec::new(),
        });
    }
    // The blocks in no group keep their place, their successors pointing
    // at a group where a member was.
    let mut all: Vec<GraphBlock> = graph
        .blocks
        .iter()
        .filter(|block| !merged.contains_key(&block.from))
        .map(|block| {
            let mut block = block.clone();
            for successor in &mut block.successors {
                if let Some(group) = merged.get(successor) {
                    *successor = *group;
                }
            }
            block.successors.sort_unstable();
            block.successors.dedup();
            block
        })
        .collect();
    all.extend(blocks);
    all.sort_by_key(|block| block.from);
    (all, groups)
}

/// The block the selection moves to from `current` in `direction`, by its
/// start: down an edge that leaves the block holding `current` — the
/// fall-through first — or to the nearest block of the row below; up an
/// edge that arrives, or to the nearest block of the row above; left or
/// right to the block beside it in its row.
pub fn neighbour(layout: &GraphLayout, current: u64, direction: Direction) -> Option<u64> {
    let node = layout
        .nodes
        .iter()
        .find(|node| node.contains(current))
        .or_else(|| layout.nodes.iter().find(|node| node.from == current))?;
    let by_start = |from: u64| layout.nodes.iter().find(|node| node.from == from);
    let nearest = |rank: usize| -> Option<u64> {
        layout
            .nodes
            .iter()
            .filter(|other| other.rank == rank)
            .min_by(|a, b| {
                let da = (a.x - node.x).abs();
                let db = (b.x - node.x).abs();
                da.partial_cmp(&db).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|other| other.from)
    };
    match direction {
        Direction::Down => {
            let mut out: Vec<&GraphEdge> = layout
                .edges
                .iter()
                .filter(|edge| edge.from == node.from && edge.to != node.from)
                .collect();
            // The fall-through first, then a way to a row below before a
            // way back up, the nearest row first.
            out.sort_by_key(|edge| {
                let rank = by_start(edge.to).map_or(usize::MAX, |other| other.rank);
                (
                    edge.kind != ag_image::EdgeKind::Fallthrough,
                    rank <= node.rank,
                    rank,
                )
            });
            out.first()
                .map(|edge| edge.to)
                .or_else(|| nearest(node.rank + 1))
        }
        Direction::Up => {
            let mut into: Vec<&GraphEdge> = layout
                .edges
                .iter()
                .filter(|edge| edge.to == node.from && edge.from != node.from)
                .collect();
            // A way from a row above before a loop back from below, the
            // nearest row first.
            into.sort_by_key(|edge| {
                let rank = by_start(edge.from).map_or(0, |other| other.rank);
                (rank >= node.rank, std::cmp::Reverse(rank))
            });
            into.first()
                .map(|edge| edge.from)
                .or_else(|| node.rank.checked_sub(1).and_then(nearest))
        }
        Direction::Left | Direction::Right => {
            let mut row: Vec<&GraphNode> = layout
                .nodes
                .iter()
                .filter(|other| other.rank == node.rank)
                .collect();
            row.sort_by(|a, b| a.x.partial_cmp(&b.x).unwrap_or(std::cmp::Ordering::Equal));
            let index = row.iter().position(|other| other.from == node.from)?;
            let next = if direction == Direction::Left {
                index.checked_sub(1)?
            } else {
                index + 1
            };
            row.get(next).map(|other| other.from)
        }
    }
}

/// The layout as a picture to write: every node a box with the header the
/// tab shows and a line per row — a note above its instruction on a row of
/// its own, an inline note at the end — the analyst's highlight as the
/// box's color, the selected block marked, and every arrow along the route
/// the tab draws it by.
pub fn drawing(
    layout: &GraphLayout,
    title: String,
    selected: Option<u64>,
) -> ag_image::graph_export::Drawing {
    use ag_image::graph_export::{Drawing, DrawnEdge, DrawnNode, MARGIN};
    let channel = |value: f32| (value.clamp(0.0, 1.0) * 255.0).round() as u8;
    let nodes = layout
        .nodes
        .iter()
        .map(|node| {
            let header = match (&node.group, &node.label) {
                (Some((name, members)), _) => format!(
                    "{name} ({members} block{})",
                    if *members == 1 { "" } else { "s" }
                ),
                (None, Some(label)) => label.clone(),
                (None, None) => format!("{:#x} - {:#x}", node.from, node.to),
            };
            let mut lines = Vec::new();
            for line in &node.lines {
                if line.comment_above {
                    if let Some(comment) = &line.comment {
                        lines.push(format!("; {comment}"));
                    }
                }
                let mut text = if node.group.is_some() {
                    format!("{} {}", line.mnemonic, line.operands)
                } else if line.operands.is_empty() {
                    format!("{}  {}", line.address, line.mnemonic)
                } else {
                    format!("{}  {} {}", line.address, line.mnemonic, line.operands)
                };
                if !line.comment_above {
                    if let Some(comment) = &line.comment {
                        text.push_str(&format!("  ; {comment}"));
                    }
                }
                lines.push(text);
            }
            DrawnNode {
                x: node.x + MARGIN,
                y: node.y + MARGIN,
                width: node.width,
                height: node.height,
                title: header,
                lines,
                color: node
                    .color
                    .map(|color| [channel(color.r), channel(color.g), channel(color.b)]),
                selected: selected.is_some_and(|address| node.contains(address)),
            }
        })
        .collect();
    // An edge whose block was not found has no route, and is no arrow.
    let edges = layout
        .edges
        .iter()
        .filter(|edge| edge.route.len() >= 2)
        .map(|edge| DrawnEdge {
            points: edge
                .route
                .iter()
                .map(|point| (point.x + MARGIN, point.y + MARGIN))
                .collect(),
            kind: edge.kind,
        })
        .collect();
    Drawing {
        width: layout.width + MARGIN * 2.0,
        height: layout.height + MARGIN * 2.0,
        title,
        nodes,
        edges,
    }
}

/// The width of the minimap, and the most height it takes.
const MINIMAP_WIDTH: f32 = 160.0;
const MINIMAP_MAX_HEIGHT: f32 = 110.0;
/// The gap between the minimap and the pane's edge.
const MINIMAP_MARGIN: f32 = 12.0;

/// Where the minimap of the whole graph sits in a viewport: the bottom
/// right corner, as wide as [`MINIMAP_WIDTH`] and as tall as the graph's
/// shape asks, up to [`MINIMAP_MAX_HEIGHT`]. `None` for a graph of nothing,
/// and for a viewport too small to spare the room.
pub fn minimap_rect(layout: &GraphLayout, viewport: Size) -> Option<Rectangle> {
    if layout.nodes.is_empty() || layout.width <= 0.0 || layout.height <= 0.0 {
        return None;
    }
    if viewport.width < MINIMAP_WIDTH * 2.5 || viewport.height < MINIMAP_MAX_HEIGHT * 2.5 {
        return None;
    }
    let height = (MINIMAP_WIDTH * layout.height / layout.width).clamp(24.0, MINIMAP_MAX_HEIGHT);
    Some(Rectangle {
        x: viewport.width - MINIMAP_WIDTH - MINIMAP_MARGIN,
        y: viewport.height - height - MINIMAP_MARGIN,
        width: MINIMAP_WIDTH,
        height,
    })
}

/// How the whole graph is drawn inside the minimap: fitted, and centred.
pub fn minimap_view(layout: &GraphLayout, rect: Rectangle) -> View {
    let inset = 4.0;
    let scale = ((rect.width - inset * 2.0) / layout.width)
        .min((rect.height - inset * 2.0) / layout.height)
        .max(f32::MIN_POSITIVE);
    View {
        scale,
        offset: Point::new(
            rect.x + (rect.width - layout.width * scale) / 2.0,
            rect.y + (rect.height - layout.height * scale) / 2.0,
        ),
    }
}

/// The pan that puts the graph point under `point` of the minimap at the
/// centre of the viewport, at the zoom in force.
pub fn minimap_pan(
    layout: &GraphLayout,
    viewport: Size,
    rect: Rectangle,
    zoom: f32,
    point: Point,
) -> Vector {
    let mini = minimap_view(layout, rect);
    let graph = Point::new(
        (point.x - mini.offset.x) / mini.scale,
        (point.y - mini.offset.y) / mini.scale,
    );
    let base = fit(layout, viewport);
    let scale = base.scale * zoom;
    Vector::new(
        viewport.width / 2.0 - base.offset.x - graph.x * scale,
        viewport.height / 2.0 - base.offset.y - graph.y * scale,
    )
}

/// The edges of a graph, as the view draws them.
///
/// The kind of each edge is the one the provider gave it: the view lays
/// the edges out, it does not decide what they mean.
fn drawn_edges(graph: &Graph) -> Vec<GraphEdge> {
    graph
        .edges
        .iter()
        .map(|edge| GraphEdge {
            from: edge.from,
            to: edge.to,
            kind: edge.kind,
            route: Vec::new(),
        })
        .collect()
}

/// The rank of every block.
///
/// A block sits one row below the deepest block that reaches it, so a
/// block that two ways reach sits below both of them. A loop back to a
/// block that is already open does not push anything further down, and
/// a block nothing reaches is put below the ones that are.
fn ranks(blocks: &[GraphBlock]) -> Vec<usize> {
    let index: HashMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(position, block)| (block.from, position))
        .collect();

    // The edges that go back up the graph are the loops, and they do not
    // decide the rows.
    let loops = loops_of(blocks, &index);

    let mut edges: Vec<(usize, usize)> = Vec::new();

    for (node, block) in blocks.iter().enumerate() {
        for &successor in &block.successors {
            let Some(&target) = index.get(&successor) else {
                continue;
            };

            if loops.contains(&(node, target)) {
                continue;
            }

            edges.push((node, target));
        }
    }

    // The depth of a block is one below the deepest block that reaches it.
    let mut depth = vec![0_usize; blocks.len()];
    let mut waiting = vec![0_usize; blocks.len()];
    let mut outgoing: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];

    for &(node, target) in &edges {
        waiting[target] += 1;
        outgoing[node].push(target);
    }

    let mut queue: Vec<usize> = (0..blocks.len())
        .filter(|node| waiting[*node] == 0)
        .collect();
    let mut at = 0;

    while at < queue.len() {
        let node = queue[at];
        at += 1;

        for &target in &outgoing[node] {
            depth[target] = depth[target].max(depth[node] + 1);
            waiting[target] -= 1;

            if waiting[target] == 0 {
                queue.push(target);
            }
        }
    }

    // A block the entry cannot reach is put below the ones it can.
    let entry = blocks
        .iter()
        .enumerate()
        .min_by_key(|(_, block)| block.from)
        .map(|(position, _)| position);

    if let Some(entry) = entry {
        let reachable = reachable_from(entry, blocks, &index);
        let floor = reachable.iter().map(|&node| depth[node]).max().unwrap_or(0) + 1;

        for (node, level) in depth.iter_mut().enumerate() {
            if !reachable.contains(&node) {
                *level += floor;
            }
        }
    }

    depth
}

/// The edges that go back to a block that is already open.
///
/// These are the loops of the graph: they are drawn as loops, and they
/// do not decide which row a block sits in.
fn loops_of(blocks: &[GraphBlock], index: &HashMap<u64, usize>) -> HashSet<(usize, usize)> {
    let mut loops = HashSet::new();
    // 0 is unvisited, 1 is open, 2 is done.
    let mut state = vec![0_u8; blocks.len()];

    for start in 0..blocks.len() {
        if state[start] != 0 {
            continue;
        }

        let mut stack: Vec<(usize, usize)> = vec![(start, 0)];
        state[start] = 1;

        while let Some((node, next)) = stack.pop() {
            if next >= blocks[node].successors.len() {
                state[node] = 2;
                continue;
            }

            stack.push((node, next + 1));

            let Some(&target) = index.get(&blocks[node].successors[next]) else {
                continue;
            };

            match state[target] {
                1 => {
                    loops.insert((node, target));
                }
                0 => {
                    state[target] = 1;
                    stack.push((target, 0));
                }
                _ => {}
            }
        }
    }

    loops
}

/// The blocks the entry block can reach.
fn reachable_from(
    entry: usize,
    blocks: &[GraphBlock],
    index: &HashMap<u64, usize>,
) -> HashSet<usize> {
    let mut reached = HashSet::new();
    let mut stack = vec![entry];

    while let Some(node) = stack.pop() {
        if !reached.insert(node) {
            continue;
        }

        for &successor in &blocks[node].successors {
            if let Some(&target) = index.get(&successor) {
                stack.push(target);
            }
        }
    }

    reached
}

/// The view that fits the whole graph into a viewport.
pub fn fit(layout: &GraphLayout, viewport: Size) -> View {
    if layout.width <= 0.0
        || layout.height <= 0.0
        || viewport.width <= 0.0
        || viewport.height <= 0.0
    {
        return View {
            scale: 1.0,
            offset: Point::ORIGIN,
        };
    }

    let scale = (viewport.width / layout.width)
        .min(viewport.height / layout.height)
        .min(1.0);

    View {
        scale,
        offset: Point::new(
            (viewport.width - layout.width * scale) / 2.0,
            (viewport.height - layout.height * scale) / 2.0,
        ),
    }
}

/// The block under a point, if there is one.
pub fn node_at(layout: &GraphLayout, view: View, point: Point) -> Option<u64> {
    let x = (point.x - view.offset.x) / view.scale;
    let y = (point.y - view.offset.y) / view.scale;

    layout
        .nodes
        .iter()
        .find(|node| {
            x >= node.x && x <= node.x + node.width && y >= node.y && y <= node.y + node.height
        })
        .map(|node| node.from)
}

/// The graph of the selected function, drawn on a canvas.
pub fn view(app: &App) -> Element<'_, Message> {
    let program = GraphProgram {
        layout: layout(&app.work.graph, &app.renames()),
        selected: app.selection.address(),
    };

    canvas(program)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

/// The canvas that draws the graph.
struct GraphProgram {
    /// Where the blocks are drawn.
    layout: GraphLayout,
    /// The address the reader has selected.
    selected: Option<u64>,
}

/// What the reader has done to the graph.
#[derive(Debug)]
pub struct GraphState {
    /// How far the graph has been dragged, in screen pixels.
    pan: Vector,
    /// The zoom the reader has chosen, over the fitted scale.
    zoom: f32,
    /// Where the mouse was pressed, if it was.
    press: Option<Point>,
    /// Where the mouse was the last time it moved.
    last: Option<Point>,
    /// The graph the state belongs to, so a new graph starts over.
    graph: Option<u64>,
}

impl Default for GraphState {
    fn default() -> Self {
        Self {
            pan: Vector::ZERO,
            zoom: 1.0,
            press: None,
            last: None,
            graph: None,
        }
    }
}

impl GraphProgram {
    /// The address that tells one graph from another.
    fn id(&self) -> Option<u64> {
        self.layout.nodes.first().map(|node| node.from)
    }

    /// The view of the graph, with the reader's pan and zoom.
    fn view(&self, state: &GraphState, viewport: Size) -> View {
        let base = fit(&self.layout, viewport);

        let (pan, zoom) = if state.graph == self.id() {
            (state.pan, state.zoom)
        } else {
            (Vector::ZERO, 1.0)
        };

        View {
            scale: base.scale * zoom,
            offset: Point::new(base.offset.x + pan.x, base.offset.y + pan.y),
        }
    }

    /// The block a point is over.
    fn node_at(&self, state: &GraphState, viewport: Size, point: Point) -> Option<u64> {
        node_at(&self.layout, self.view(state, viewport), point)
    }

    /// Draw one block.
    fn draw_node(
        &self,
        frame: &mut canvas::Frame,
        node: &GraphNode,
        view: View,
        selected: Option<u64>,
    ) {
        let scale = view.scale;
        let x = view.offset.x + node.x * scale;
        let y = view.offset.y + node.y * scale;
        let width = node.width * scale;
        let height = node.height * scale;

        let focused = selected.is_some_and(|address| node.contains(address));

        let path = canvas::Path::rounded_rectangle(
            Point::new(x, y),
            Size::new(width, height),
            (4.0 * scale).min(6.0).into(),
        );

        let surface = match (focused, node.color) {
            (true, _) => color::FOCUS_BG,
            (false, Some(tint)) => tinted(color::CARD, tint, 0.28),
            (false, None) => color::CARD,
        };
        frame.fill(&path, surface);
        frame.stroke(
            &path,
            canvas::Stroke::default()
                .with_color(if focused { color::CYAN } else { color::LINE })
                .with_width(if focused { 2.0 } else { 1.0 }),
        );

        let size = (12.0 * scale).max(1.0);

        // The header: the analyst's text on the block, the group's name
        // and size, or the range of addresses the block covers.
        let header = match (&node.group, &node.label) {
            (Some((name, members)), _) => format!(
                "⊞ {name} ({members} block{})",
                if *members == 1 { "" } else { "s" }
            ),
            (None, Some(label)) => label.clone(),
            (None, None) => format!("{:#x} - {:#x}", node.from, node.to),
        };
        frame.fill_text(text(
            &header,
            Point::new(x + PADDING * scale, y + 4.0 * scale),
            if node.label.is_some() || node.group.is_some() {
                color::TEXT
            } else {
                color::MUTED
            },
            size,
        ));

        for line in &node.lines {
            let line_y = y + (HEADER_HEIGHT + PADDING + line.row as f32 * LINE_HEIGHT) * scale;

            // A line's own highlight is a band across the block behind its
            // text, mixed stronger than the block's so it stands out from
            // the surface around it.
            if let Some(tint) = line.color {
                frame.fill_rectangle(
                    Point::new(x + 2.0 * scale, line_y),
                    Size::new(width - 4.0 * scale, LINE_HEIGHT * scale),
                    tinted(surface, tint, 0.45),
                );
            }

            // A note that stands above its instruction is drawn on the row
            // just over it, indented to the operands so it reads as
            // belonging to the line below.
            if line.comment_above {
                if let Some(comment) = &line.comment {
                    frame.fill_text(text(
                        &format!("; {comment}"),
                        Point::new(x + 352.0 * scale, line_y - LINE_HEIGHT * scale),
                        color::AMBER,
                        size,
                    ));
                }
            }

            frame.fill_text(text(
                &line.address,
                Point::new(x + 8.0 * scale, line_y),
                color::ADDR,
                size,
            ));
            frame.fill_text(text(
                &line.bytes,
                Point::new(x + 80.0 * scale, line_y),
                color::BYTES,
                size,
            ));
            frame.fill_text(text(
                &line.mnemonic,
                Point::new(x + 260.0 * scale, line_y),
                color::PURPLE,
                size,
            ));
            frame.fill_text(text(
                &line.operands,
                Point::new(x + 352.0 * scale, line_y),
                color::TEXT,
                size,
            ));
            // An inline note rides at the end of the line, past the
            // operands column, in the analyst's color.
            if !line.comment_above {
                if let Some(comment) = &line.comment {
                    frame.fill_text(text(
                        &format!("; {comment}"),
                        Point::new(x + 470.0 * scale, line_y),
                        color::AMBER,
                        size,
                    ));
                }
            }
        }
    }

    /// Draw one edge, with the arrow that points at the next block.
    fn draw_edge(&self, frame: &mut canvas::Frame, edge: &GraphEdge, view: View) {
        let Some(source) = self.layout.nodes.iter().find(|node| node.from == edge.from) else {
            return;
        };

        let points = edge_points(&edge.route, view);

        if points.len() < 2 {
            return;
        }

        let path = canvas::Path::new(|builder| {
            builder.move_to(points[0]);

            for point in &points[1..] {
                builder.line_to(*point);
            }
        });

        let stroke = if edge.kind == ag_image::EdgeKind::Taken {
            color::AMBER
        } else {
            color::LINE
        };

        frame.stroke(
            &path,
            canvas::Stroke::default()
                .with_color(stroke)
                .with_width((1.5 * view.scale).max(1.0)),
        );

        let tip = points[points.len() - 1];
        let before = points[points.len() - 2];

        frame.fill(
            &arrow_head(tip, before, (7.0 * view.scale).max(4.0)),
            stroke,
        );

        // A branch says which way is which; a block that goes on in one way
        // does not need saying.
        if !source.branching {
            return;
        }

        let label = edge.kind.name();

        // The label sits at the last bend of the edge, so the edges that
        // leave a block name themselves by the block they go to.
        let Some(anchor) = edge.label_point() else {
            return;
        };

        let anchor = Point::new(
            view.offset.x + anchor.x * view.scale,
            view.offset.y + anchor.y * view.scale,
        );

        frame.fill_text(text(
            label,
            Point::new(anchor.x + 4.0, anchor.y + 1.0),
            color::DIM,
            (10.0 * view.scale).max(1.0),
        ));
    }
}

/// The points an edge is drawn through, in graph units.
///
/// The route leaves the source, travels in the gap between the rows, and
/// comes into the target. It never crosses a block it does not connect:
/// the horizontal runs are in the gaps between the rows, where no block
/// sits, and the vertical runs are either in a column of their own or to
/// the side of the blocks they pass.
fn route(
    nodes: &[GraphNode],
    rows: &[GraphRow],
    source: &GraphNode,
    target: &GraphNode,
) -> Vec<Point> {
    let source_x = source.x + source.width / 2.0;
    let target_x = target.x + target.width / 2.0;

    let below = band_below(rows, source.rank);
    let above = band_above(rows, target.rank);

    if target.rank == source.rank + 1 {
        // Down the side of the source, across, and down into the target.
        vec![
            Point::new(source_x, source.y + source.height),
            Point::new(source_x, below),
            Point::new(target_x, below),
            Point::new(target_x, target.y),
        ]
    } else if target.rank > source.rank {
        // The target is more than one row down, so the blocks in between
        // are in the way: go around them, to the side.
        let lane = lane_beside(nodes, source.rank + 1, target.rank - 1, target_x);

        vec![
            Point::new(source_x, source.y + source.height),
            Point::new(source_x, below),
            Point::new(lane, below),
            Point::new(lane, above),
            Point::new(target_x, above),
            Point::new(target_x, target.y),
        ]
    } else {
        // A loop back: out to the side of the whole graph, along, and in
        // again from below.
        let lane = lane_beside(nodes, 0, rows.len().saturating_sub(1), target_x);
        let under = band_below(rows, target.rank);

        vec![
            Point::new(source_x, source.y + source.height),
            Point::new(source_x, below),
            Point::new(lane, below),
            Point::new(lane, under),
            Point::new(target_x, under),
            Point::new(target_x, target.y + target.height),
        ]
    }
}

/// The middle of the gap under a row.
fn band_below(rows: &[GraphRow], rank: usize) -> f32 {
    match rows.get(rank) {
        Some(row) => row.bottom + GAP_Y / 2.0,
        None => 0.0,
    }
}

/// The middle of the gap over a row.
fn band_above(rows: &[GraphRow], rank: usize) -> f32 {
    match rows.get(rank) {
        Some(row) => row.y - GAP_Y / 2.0,
        None => 0.0,
    }
}

/// The lane to the side of the blocks in the given rows.
///
/// The lane is clear of every block in those rows, so an edge that runs
/// along it crosses none of them. The side that keeps the edge nearest to
/// where it is going is the one it takes.
fn lane_beside(nodes: &[GraphNode], first: usize, last: usize, prefer: f32) -> f32 {
    let mut left = f32::INFINITY;
    let mut right = f32::NEG_INFINITY;

    for node in nodes {
        if node.rank >= first && node.rank <= last {
            left = left.min(node.x);
            right = right.max(node.x + node.width);
        }
    }

    if !left.is_finite() {
        // Nothing is in the way, so the edge goes straight down.
        return prefer;
    }

    let left = left - LANE;
    let right = right + LANE;

    if (prefer - left).abs() < (right - prefer).abs() {
        left
    } else {
        right
    }
}

/// The points of a route, as they are drawn.
fn edge_points(route: &[Point], view: View) -> Vec<Point> {
    route
        .iter()
        .map(|point| {
            Point::new(
                view.offset.x + point.x * view.scale,
                view.offset.y + point.y * view.scale,
            )
        })
        .collect()
}

/// The arrow that points at the next block.
fn arrow_head(tip: Point, from: Point, size: f32) -> canvas::Path {
    let dx = tip.x - from.x;
    let dy = tip.y - from.y;
    let length = (dx * dx + dy * dy).sqrt().max(0.0001);
    let (ux, uy) = (dx / length, dy / length);
    let (px, py) = (-uy, ux);

    let base = Point::new(tip.x - ux * size, tip.y - uy * size);
    let left = Point::new(base.x + px * size * 0.5, base.y + py * size * 0.5);
    let right = Point::new(base.x - px * size * 0.5, base.y - py * size * 0.5);

    canvas::Path::new(|builder| {
        builder.move_to(tip);
        builder.line_to(left);
        builder.line_to(right);
        builder.close();
    })
}

/// A piece of text on the canvas.
fn text(content: &str, position: Point, tint: iced::Color, size: f32) -> canvas::Text {
    canvas::Text {
        content: content.to_string(),
        position,
        max_width: f32::INFINITY,
        color: tint,
        size: Pixels::from(size),
        // The line height is a factor of the size of the text, not a
        // height in pixels: a factor of eight would push the glyphs a long
        // way down the block.
        line_height: LineHeight::Relative(1.3),
        font: MONO,
        align_x: Alignment::Left,
        align_y: iced::Top,
        shaping: Shaping::default(),
    }
}

impl canvas::Program<Message> for GraphProgram {
    type State = GraphState;

    fn update(
        &self,
        state: &mut GraphState,
        event: &canvas::Event,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Option<canvas::Action<Message>> {
        // A new graph starts over: the pan and the zoom belonged to the
        // last one.
        if state.graph != self.id() {
            state.graph = self.id();
            state.pan = Vector::ZERO;
            state.zoom = 1.0;
            state.press = None;
            state.last = None;
        }

        let position = cursor.position();

        match event {
            canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)) => {
                // A press on the minimap moves the view there, and starts
                // no drag.
                if let Some(position) = position {
                    let local = Point::new(
                        position.x - bounds.position().x,
                        position.y - bounds.position().y,
                    );
                    if let Some(rect) = minimap_rect(&self.layout, bounds.size()) {
                        if rect.contains(local) {
                            let zoom = if state.graph == self.id() {
                                state.zoom
                            } else {
                                1.0
                            };
                            state.pan = minimap_pan(&self.layout, bounds.size(), rect, zoom, local);
                            state.press = None;
                            state.last = None;
                            return Some(canvas::Action::request_redraw());
                        }
                    }
                }
                state.press = position;
                state.last = position;
                None
            }

            canvas::Event::Mouse(mouse::Event::ButtonReleased(mouse::Button::Left)) => {
                let press = state.press.take();
                state.last = None;

                // A press that did not move is a click on a block.
                let clicked = match (press, position) {
                    (Some(press), Some(position)) => {
                        (position.x - press.x).abs() < CLICK_SLOP
                            && (position.y - press.y).abs() < CLICK_SLOP
                    }
                    _ => false,
                };

                if !clicked {
                    return None;
                }

                let position = position?;

                let local = Point::new(
                    position.x - bounds.position().x,
                    position.y - bounds.position().y,
                );

                self.node_at(state, bounds.size(), local)
                    .map(|address| canvas::Action::publish(Message::AddressSelected(address)))
            }

            canvas::Event::Mouse(mouse::Event::CursorMoved { position }) => {
                let delta = match (state.press, state.last) {
                    (Some(_), Some(last)) => Some(*position - last),
                    _ => None,
                };

                state.last = Some(*position);

                match delta {
                    Some(delta) if state.press.is_some() => {
                        state.pan += delta;
                        Some(canvas::Action::request_redraw())
                    }
                    _ => None,
                }
            }

            canvas::Event::Mouse(mouse::Event::WheelScrolled { delta }) => {
                let lines = match delta {
                    mouse::ScrollDelta::Lines { y, .. } => *y,
                    mouse::ScrollDelta::Pixels { y, .. } => *y / 40.0,
                };

                if lines == 0.0 {
                    return None;
                }

                let factor = if lines > 0.0 { 1.1 } else { 1.0 / 1.1 };
                let zoom = (state.zoom * factor).clamp(MIN_ZOOM, MAX_ZOOM);

                if zoom == state.zoom {
                    return None;
                }

                // Keep the point under the mouse where it is.
                let base = fit(&self.layout, bounds.size());
                let local = position
                    .map(|position| {
                        Point::new(
                            position.x - bounds.position().x,
                            position.y - bounds.position().y,
                        )
                    })
                    .unwrap_or(Point::ORIGIN);

                let old_scale = base.scale * state.zoom;
                let new_scale = base.scale * zoom;
                let graph_x = (local.x - base.offset.x - state.pan.x) / old_scale;
                let graph_y = (local.y - base.offset.y - state.pan.y) / old_scale;

                state.pan = Vector::new(
                    local.x - base.offset.x - graph_x * new_scale,
                    local.y - base.offset.y - graph_y * new_scale,
                );
                state.zoom = zoom;

                Some(canvas::Action::request_redraw())
            }

            _ => None,
        }
    }

    fn draw(
        &self,
        state: &GraphState,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let view = self.view(state, bounds.size());

        // The edges first, so the blocks are drawn over them.
        for edge in &self.layout.edges {
            self.draw_edge(&mut frame, edge, view);
        }

        for node in &self.layout.nodes {
            self.draw_node(&mut frame, node, view, self.selected);
        }

        // The minimap: the whole graph small in the corner, every block a
        // mark, the selected one bright, and the part of it the pane shows
        // outlined.
        if let Some(rect) = minimap_rect(&self.layout, bounds.size()) {
            let mini = minimap_view(&self.layout, rect);
            let panel = canvas::Path::rounded_rectangle(
                Point::new(rect.x, rect.y),
                Size::new(rect.width, rect.height),
                4.0.into(),
            );
            frame.fill(&panel, color::PANEL);
            frame.stroke(
                &panel,
                canvas::Stroke::default()
                    .with_color(color::LINE)
                    .with_width(1.0),
            );
            for node in &self.layout.nodes {
                let focused = self.selected.is_some_and(|address| node.contains(address));
                let tint = match (focused, node.color) {
                    (true, _) => color::CYAN,
                    (false, Some(tint)) => tinted(color::CARD, tint, 0.6),
                    (false, None) => color::MUTED,
                };
                frame.fill_rectangle(
                    Point::new(
                        mini.offset.x + node.x * mini.scale,
                        mini.offset.y + node.y * mini.scale,
                    ),
                    Size::new(
                        (node.width * mini.scale).max(2.0),
                        (node.height * mini.scale).max(1.5),
                    ),
                    tint,
                );
            }
            // What the pane shows, in graph units, then in the minimap's.
            let shown_x0 = ((0.0 - view.offset.x) / view.scale).clamp(0.0, self.layout.width);
            let shown_y0 = ((0.0 - view.offset.y) / view.scale).clamp(0.0, self.layout.height);
            let shown_x1 =
                ((bounds.width - view.offset.x) / view.scale).clamp(0.0, self.layout.width);
            let shown_y1 =
                ((bounds.height - view.offset.y) / view.scale).clamp(0.0, self.layout.height);
            if shown_x1 > shown_x0 && shown_y1 > shown_y0 {
                let outline = canvas::Path::rectangle(
                    Point::new(
                        mini.offset.x + shown_x0 * mini.scale,
                        mini.offset.y + shown_y0 * mini.scale,
                    ),
                    Size::new(
                        (shown_x1 - shown_x0) * mini.scale,
                        (shown_y1 - shown_y0) * mini.scale,
                    ),
                );
                frame.stroke(
                    &outline,
                    canvas::Stroke::default()
                        .with_color(color::CYAN)
                        .with_width(1.0),
                );
            }
        }

        vec![frame.into_geometry()]
    }

    fn mouse_interaction(
        &self,
        _state: &GraphState,
        _bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> mouse::Interaction {
        mouse::Interaction::Pointer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A block with the given instructions.
    fn block(from: u64, to: u64, successors: Vec<u64>, lines: usize) -> GraphBlock {
        GraphBlock {
            from,
            to,
            successors,
            instructions: (0..lines)
                .map(|index| ListingLine {
                    address: from + index as u64,
                    bytes: "48 89 E5".into(),
                    mnemonic: "mov".into(),
                    operands: "rbp, rsp".into(),
                    call_target: None,
                    tail: false,
                    registers: Vec::new(),
                    comment: None,
                })
                .collect(),
        }
    }

    /// A graph of the blocks, with the edges the shared rule gives them.
    ///
    /// The view does not decide what an edge means, so the edges come from
    /// the rule the CLI reports by.
    fn graph_of(blocks: Vec<GraphBlock>) -> Graph {
        Graph {
            edges: Graph::edges_of_blocks(&blocks),
            blocks,
        }
    }

    #[test]
    fn an_above_comment_takes_a_row_of_its_own() {
        // Two instructions, a note standing above the first. The block
        // grows by one row, the note owns the first row, and the
        // instructions follow below it.
        let blocks = vec![block(0x1000, 0x1010, vec![], 2)];
        let renamed = crate::app::Renames::with_comment(0x1000, "the loop head", true);

        let layout = layout(&graph_of(blocks), &renamed);
        let node = layout
            .nodes
            .iter()
            .find(|node| node.from == 0x1000)
            .expect("the block is laid out");

        assert_eq!(node.lines.len(), 2);
        assert_eq!(node.lines[0].row, 1, "the note takes the row above");
        assert_eq!(node.lines[1].row, 2, "the second instruction follows");
        assert!(node.lines[0].comment_above);
        assert_eq!(
            node.height,
            HEADER_HEIGHT + PADDING * 2.0 + 3.0 * LINE_HEIGHT,
            "two instructions and the note between them"
        );
    }

    #[test]
    fn a_highlight_colors_its_line_its_block_or_the_function() {
        use ag_corpus::project::TargetKind;
        let blocks = || {
            vec![
                block(0x1000, 0x1010, vec![0x1010], 2),
                block(0x1010, 0x1020, vec![], 2),
            ]
        };

        // On one address: that line, and nothing else.
        let renamed = crate::app::Renames::with_color(0x1001, "#e07a6a", TargetKind::Address);
        let laid = layout(&graph_of(blocks()), &renamed);
        let first = laid.nodes.iter().find(|n| n.from == 0x1000).unwrap();
        assert!(first.color.is_none());
        assert!(first.lines[0].color.is_none());
        assert!(first.lines[1].color.is_some());

        // On a block: the block, and no line apart.
        let renamed = crate::app::Renames::with_color(0x1010, "#8bcf9c", TargetKind::Region);
        let laid = layout(&graph_of(blocks()), &renamed);
        assert!(laid
            .nodes
            .iter()
            .find(|n| n.from == 0x1000)
            .unwrap()
            .color
            .is_none());
        let second = laid.nodes.iter().find(|n| n.from == 0x1010).unwrap();
        assert!(second.color.is_some());
        assert!(second.lines.iter().all(|line| line.color.is_none()));

        // On the function: every block.
        let renamed = crate::app::Renames::with_color(0x1000, "#86aef3", TargetKind::Function);
        let laid = layout(&graph_of(blocks()), &renamed);
        assert!(laid.nodes.iter().all(|n| n.color.is_some()));
    }

    #[test]
    fn an_inline_comment_takes_no_row() {
        let blocks = vec![block(0x1000, 0x1010, vec![], 2)];
        let renamed = crate::app::Renames::with_comment(0x1000, "the entry", false);

        let layout = layout(&graph_of(blocks), &renamed);
        let node = layout
            .nodes
            .iter()
            .find(|node| node.from == 0x1000)
            .expect("the block is laid out");

        assert_eq!(node.lines[0].row, 0, "an inline note rides, not stands");
        assert_eq!(node.lines[0].comment.as_deref(), Some("the entry"));
        assert_eq!(
            node.height,
            HEADER_HEIGHT + PADDING * 2.0 + 2.0 * LINE_HEIGHT,
            "the block is no taller for an inline note"
        );
    }

    #[test]
    fn the_blocks_are_ranked_by_the_depth_of_the_walk_that_reaches_them() {
        let blocks = vec![
            block(0x1000, 0x1010, vec![0x1010], 2),
            block(0x1010, 0x1020, vec![0x1020, 0x1030], 2),
            block(0x1020, 0x1030, vec![], 1),
            block(0x1030, 0x1040, vec![], 1),
        ];

        let layout = layout(&graph_of(blocks), &crate::app::Renames::default());

        let rank = |from: u64| {
            layout
                .nodes
                .iter()
                .find(|node| node.from == from)
                .map(|node| node.rank)
        };

        assert_eq!(rank(0x1000), Some(0));
        assert_eq!(rank(0x1010), Some(1));
        assert_eq!(rank(0x1020), Some(2));
        assert_eq!(rank(0x1030), Some(2));
    }

    #[test]
    fn the_blocks_of_a_rank_sit_side_by_side() {
        let blocks = vec![
            block(0x1000, 0x1010, vec![0x1010], 2),
            block(0x1010, 0x1020, vec![0x1020, 0x1030], 2),
            block(0x1020, 0x1030, vec![], 1),
            block(0x1030, 0x1040, vec![], 1),
        ];

        let layout = layout(&graph_of(blocks), &crate::app::Renames::default());

        let left = layout
            .nodes
            .iter()
            .find(|node| node.from == 0x1020)
            .map(|node| node.x)
            .unwrap();
        let right = layout
            .nodes
            .iter()
            .find(|node| node.from == 0x1030)
            .map(|node| node.x)
            .unwrap();

        assert_eq!(left, 0.0);
        assert_eq!(right, NODE_WIDTH + GAP_X);
    }

    #[test]
    fn a_block_that_two_ways_reach_sits_below_both_of_them() {
        // The first block reaches the second one two ways: straight down
        // and through the third one. The second sits below the third.
        let blocks = vec![
            block(0x1000, 0x1010, vec![0x1010, 0x1020], 1),
            block(0x1010, 0x1020, vec![], 1),
            block(0x1020, 0x1030, vec![0x1010], 1),
        ];

        let layout = layout(&graph_of(blocks), &crate::app::Renames::default());

        let rank = |from: u64| {
            layout
                .nodes
                .iter()
                .find(|node| node.from == from)
                .map(|node| node.rank)
        };

        assert_eq!(rank(0x1000), Some(0));
        assert_eq!(rank(0x1020), Some(1));
        assert_eq!(rank(0x1010), Some(2));
    }

    #[test]
    fn a_loop_does_not_send_the_walk_round_again() {
        let blocks = vec![
            block(0x1000, 0x1010, vec![0x1010], 1),
            block(0x1010, 0x1020, vec![0x1000], 1),
        ];

        let layout = layout(&graph_of(blocks), &crate::app::Renames::default());

        assert_eq!(layout.nodes.len(), 2);
        assert!(layout.nodes.iter().all(|node| node.rank < 2));
    }

    #[test]
    fn a_block_the_walk_never_reaches_is_put_below_the_others() {
        let blocks = vec![
            block(0x1000, 0x1010, vec![], 1),
            block(0x2000, 0x2010, vec![], 1),
        ];

        let layout = layout(&graph_of(blocks), &crate::app::Renames::default());

        let rank = |from: u64| {
            layout
                .nodes
                .iter()
                .find(|node| node.from == from)
                .map(|node| node.rank)
        };

        assert_eq!(rank(0x1000), Some(0));
        assert_eq!(rank(0x2000), Some(1));
    }

    #[test]
    fn the_branch_says_which_way_is_the_fall_through() {
        let blocks = vec![
            block(0x1000, 0x1010, vec![0x1010], 1),
            block(0x1010, 0x1020, vec![0x1020, 0x1030], 1),
            block(0x1020, 0x1030, vec![], 1),
            block(0x1030, 0x1040, vec![], 1),
        ];

        let layout = layout(&graph_of(blocks), &crate::app::Renames::default());

        let kind = |to: u64| {
            layout
                .edges
                .iter()
                .find(|edge| edge.from == 0x1010 && edge.to == to)
                .map(|edge| edge.kind)
        };

        assert_eq!(kind(0x1020), Some(ag_image::EdgeKind::Fallthrough));
        assert_eq!(kind(0x1030), Some(ag_image::EdgeKind::Taken));
    }

    #[test]
    fn a_block_that_goes_on_in_one_way_falls_through() {
        let blocks = vec![block(0x1000, 0x1010, vec![0x1010], 1)];

        let layout = layout(&graph_of(blocks), &crate::app::Renames::default());

        assert_eq!(layout.edges.len(), 1);
        assert_eq!(layout.edges[0].kind, ag_image::EdgeKind::Fallthrough);
        assert!(!layout.nodes[0].branching, "one way is not a branch");
    }

    #[test]
    fn a_block_that_goes_on_in_two_ways_is_a_branch() {
        let blocks = vec![
            block(0x1000, 0x1010, vec![0x1010, 0x1020], 1),
            block(0x1010, 0x1020, vec![], 1),
            block(0x1020, 0x1030, vec![], 1),
        ];

        let layout = layout(&graph_of(blocks), &crate::app::Renames::default());

        assert!(layout.nodes[0].branching, "two ways is a branch");

        let kind = |to: u64| {
            layout
                .edges
                .iter()
                .find(|edge| edge.from == 0x1000 && edge.to == to)
                .map(|edge| edge.kind)
        };

        assert_eq!(kind(0x1010), Some(ag_image::EdgeKind::Fallthrough));
        assert_eq!(kind(0x1020), Some(ag_image::EdgeKind::Taken));
    }

    #[test]
    fn a_jump_that_does_not_fall_through_is_taken() {
        // The block jumps away: the address after it is not where it goes.
        let blocks = vec![
            block(0x1000, 0x1010, vec![0x1020], 1),
            block(0x1020, 0x1030, vec![], 1),
        ];

        let layout = layout(&graph_of(blocks), &crate::app::Renames::default());

        assert_eq!(layout.edges[0].kind, ag_image::EdgeKind::Taken);
    }

    #[test]
    fn the_blocks_of_a_group_are_one_node_with_the_edges_remapped() {
        // 0x1000 -> {0x1010, 0x1020}; 0x1010 -> 0x1030; 0x1020 -> 0x1030.
        let graph = graph_of(vec![
            block(0x1000, 0x1010, vec![0x1010, 0x1020], 2),
            block(0x1010, 0x1020, vec![0x1030], 3),
            block(0x1020, 0x1030, vec![0x1030], 1),
            block(0x1030, 0x1040, vec![], 1),
        ]);
        let mut renamed = crate::app::Renames::default();
        renamed.set_block_group(0x1010, "arms");
        renamed.set_block_group(0x1020, "arms");
        renamed.set_block_label(0x1030, "join");
        let layout = layout(&graph, &renamed);
        let starts: Vec<u64> = layout.nodes.iter().map(|node| node.from).collect();
        assert_eq!(starts, [0x1000, 0x1010, 0x1030]);
        let group = layout
            .nodes
            .iter()
            .find(|node| node.from == 0x1010)
            .expect("the group");
        assert_eq!(group.to, 0x1030);
        assert_eq!(group.group, Some(("arms".to_string(), 2)));
        assert_eq!(group.lines.len(), 2);
        assert_eq!(group.lines[1].mnemonic, "0x1020 - 0x1030");
        assert_eq!(group.lines[1].operands, "1 instruction");
        let join = layout
            .nodes
            .iter()
            .find(|node| node.from == 0x1030)
            .expect("the join");
        assert_eq!(join.label.as_deref(), Some("join"));
        // Two edges into the group are one; the group goes on once.
        let mut edges: Vec<(u64, u64)> = layout
            .edges
            .iter()
            .map(|edge| (edge.from, edge.to))
            .collect();
        edges.sort_unstable();
        assert_eq!(edges, [(0x1000, 0x1010), (0x1010, 0x1030)]);
        // The group sits below the entry and above the join.
        assert!(group.rank > layout.nodes[0].rank);
        assert!(join.rank > group.rank);
    }

    #[test]
    fn a_way_from_one_group_to_another_reaches_the_other_group() {
        // 0x1000 -> 0x1010 -> 0x1030; 0x1000 -> 0x1020 -> 0x1030; with
        // {0x1010} one group and {0x1020, 0x1030} another, so the first
        // group's way out lands in a member of the second.
        let graph = graph_of(vec![
            block(0x1000, 0x1010, vec![0x1010, 0x1020], 2),
            block(0x1010, 0x1020, vec![0x1030], 3),
            block(0x1020, 0x1030, vec![0x1030], 1),
            block(0x1030, 0x1040, vec![], 1),
        ]);
        let mut renamed = crate::app::Renames::default();
        renamed.set_block_group(0x1010, "a");
        renamed.set_block_group(0x1020, "b");
        renamed.set_block_group(0x1030, "b");
        let (blocks, _) = grouped_blocks(&graph, &renamed);
        let a = blocks.iter().find(|block| block.from == 0x1010).expect("a");
        assert_eq!(a.successors, [0x1020]);
        let layout = layout(&graph, &renamed);
        let rank_of = |from: u64| layout.nodes.iter().find(|n| n.from == from).unwrap().rank;
        assert!(rank_of(0x1010) > rank_of(0x1000));
        assert!(rank_of(0x1020) > rank_of(0x1010));
        // A group of blocks apart holds its members and nothing between.
        let mut renamed = crate::app::Renames::default();
        renamed.set_block_group(0x1000, "ends");
        renamed.set_block_group(0x1030, "ends");
        let apart = super::layout(&graph, &renamed);
        let ends = apart.nodes.iter().find(|n| n.from == 0x1000).unwrap();
        assert_eq!(ends.members, [(0x1000, 0x1010), (0x1030, 0x1040)]);
        assert!(ends.contains(0x1034));
        assert!(!ends.contains(0x1014));
        assert_eq!(neighbour(&apart, 0x1014, Direction::Right), Some(0x1020));
    }

    #[test]
    fn the_drawing_of_a_layout_keeps_its_boxes_notes_and_arrows() {
        let graph = graph_of(vec![
            block(0x1000, 0x1010, vec![0x1010, 0x1020], 2),
            block(0x1010, 0x1020, vec![0x1030], 3),
            block(0x1020, 0x1030, vec![0x1030], 1),
            block(0x1030, 0x1040, vec![], 1),
        ]);
        let mut renamed = crate::app::Renames::default();
        renamed.set_block_label(0x1030, "done");
        renamed.set_block_group(0x1010, "arms");
        renamed.set_block_group(0x1020, "arms");
        let layout = layout(&graph, &renamed);
        let drawing = drawing(&layout, "f at 0x1000".to_string(), Some(0x1034));
        assert_eq!(drawing.title, "f at 0x1000");
        assert_eq!(drawing.nodes.len(), 3);
        assert_eq!(drawing.edges.len(), layout.edges.len());
        // An edge with no route is left out.
        let mut cut = layout.clone();
        cut.edges[0].route.clear();
        let fewer = super::drawing(&cut, String::new(), None);
        assert_eq!(fewer.edges.len(), layout.edges.len() - 1);
        let group = drawing
            .nodes
            .iter()
            .find(|node| node.title == "arms (2 blocks)")
            .expect("the group");
        assert_eq!(group.lines[0], "0x1010 - 0x1020 3 instructions");
        let done = drawing
            .nodes
            .iter()
            .find(|node| node.title == "done")
            .expect("the labelled block");
        assert!(done.selected);
        assert!(!group.selected);
        let entry = &drawing.nodes[0];
        assert!(
            entry.lines[0].starts_with("00001000  "),
            "{:?}",
            entry.lines
        );
        // Every box and every arrow is inside the picture.
        for node in &drawing.nodes {
            assert!(node.x >= 0.0 && node.y >= 0.0);
            assert!(node.x + node.width <= drawing.width);
            assert!(node.y + node.height <= drawing.height);
        }
        for edge in &drawing.edges {
            assert!(edge.points.len() >= 2);
            for (x, y) in &edge.points {
                assert!(*x >= 0.0 && *x <= drawing.width);
                assert!(*y >= 0.0 && *y <= drawing.height);
            }
        }
        // The SVG and the PDF both carry the text.
        let svg = ag_image::graph_export::svg(&drawing);
        assert!(svg.contains("arms (2 blocks)"));
        assert!(svg.contains("00001000  "));
        let pdf = ag_image::graph_export::pdf(&drawing);
        assert!(pdf.starts_with(b"%PDF-1.4"));
    }

    #[test]
    fn the_arrows_prefer_the_rows_they_are_named_for() {
        // A loop: 0x1000 -> 0x1010 (header) -> 0x1020 -> 0x1030 -> 0x1010;
        // 0x1030 -> 0x1040 leaves.
        let graph = graph_of(vec![
            block(0x1000, 0x1010, vec![0x1010], 1),
            block(0x1010, 0x1020, vec![0x1020], 1),
            block(0x1020, 0x1030, vec![0x1030], 1),
            block(0x1030, 0x1040, vec![0x1010, 0x1040], 2),
            block(0x1040, 0x1050, vec![], 1),
        ]);
        let layout = layout(&graph, &crate::app::Renames::default());
        // Up from the header goes to the entry above, not the latch below.
        assert_eq!(neighbour(&layout, 0x1010, Direction::Up), Some(0x1000));
        // Down from the latch takes the way out below over the loop back.
        assert_eq!(neighbour(&layout, 0x1030, Direction::Down), Some(0x1040));
    }

    #[test]
    fn the_arrows_walk_the_graph_from_block_to_block() {
        let graph = graph_of(vec![
            block(0x1000, 0x1010, vec![0x1010, 0x1020], 2),
            block(0x1010, 0x1020, vec![0x1030], 3),
            block(0x1020, 0x1030, vec![0x1030], 1),
            block(0x1030, 0x1040, vec![], 1),
        ]);
        let layout = layout(&graph, &crate::app::Renames::default());
        // Down follows the fall-through first; up comes back; left and
        // right move along the row; off the edge there is nowhere.
        assert_eq!(neighbour(&layout, 0x1000, Direction::Down), Some(0x1010));
        assert_eq!(neighbour(&layout, 0x1010, Direction::Right), Some(0x1020));
        assert_eq!(neighbour(&layout, 0x1020, Direction::Left), Some(0x1010));
        assert_eq!(neighbour(&layout, 0x1010, Direction::Left), None);
        assert_eq!(neighbour(&layout, 0x1020, Direction::Down), Some(0x1030));
        assert_eq!(neighbour(&layout, 0x1030, Direction::Up), Some(0x1010));
        assert_eq!(neighbour(&layout, 0x1000, Direction::Up), None);
        // An address inside a block moves from that block.
        assert_eq!(neighbour(&layout, 0x1004, Direction::Down), Some(0x1010));
        assert_eq!(neighbour(&layout, 0x9999, Direction::Down), None);
    }

    #[test]
    fn the_minimap_sits_in_the_corner_and_maps_the_graph() {
        let graph = graph_of(vec![
            block(0x1000, 0x1010, vec![0x1010], 2),
            block(0x1010, 0x1020, vec![], 3),
        ]);
        let layout = layout(&graph, &crate::app::Renames::default());
        let viewport = Size::new(800.0, 600.0);
        let rect = minimap_rect(&layout, viewport).expect("room for a minimap");
        assert_eq!(rect.width, MINIMAP_WIDTH);
        assert!(rect.x + rect.width <= viewport.width);
        assert!(rect.y + rect.height <= viewport.height);
        assert!(rect.height <= MINIMAP_MAX_HEIGHT);
        // The whole graph fits inside it.
        let mini = minimap_view(&layout, rect);
        assert!(mini.offset.x >= rect.x && mini.offset.y >= rect.y);
        assert!(mini.offset.x + layout.width * mini.scale <= rect.x + rect.width + 0.01);
        assert!(mini.offset.y + layout.height * mini.scale <= rect.y + rect.height + 0.01);
        // A click in the middle of the minimap centres the graph's middle.
        let middle = Point::new(
            mini.offset.x + layout.width * mini.scale / 2.0,
            mini.offset.y + layout.height * mini.scale / 2.0,
        );
        let pan = minimap_pan(&layout, viewport, rect, 1.0, middle);
        let base = fit(&layout, viewport);
        let centre_x = base.offset.x + pan.x + layout.width * base.scale / 2.0;
        let centre_y = base.offset.y + pan.y + layout.height * base.scale / 2.0;
        assert!((centre_x - viewport.width / 2.0).abs() < 0.01);
        assert!((centre_y - viewport.height / 2.0).abs() < 0.01);
        // No room, no minimap; no graph, no minimap.
        assert!(minimap_rect(&layout, Size::new(200.0, 150.0)).is_none());
        assert!(minimap_rect(&GraphLayout::default(), viewport).is_none());
    }

    #[test]
    fn the_graph_is_fitted_to_the_viewport() {
        let blocks = vec![
            block(0x1000, 0x1010, vec![0x1010], 2),
            block(0x1010, 0x1020, vec![], 2),
        ];

        let layout = layout(&graph_of(blocks), &crate::app::Renames::default());
        let view = fit(&layout, Size::new(1000.0, 1000.0));

        assert!(view.scale <= 1.0);
        assert!(view.scale > 0.0);

        // The whole graph is inside the viewport.
        assert!(layout.width * view.scale <= 1000.0);
        assert!(layout.height * view.scale <= 1000.0);
    }

    #[test]
    fn the_block_under_a_point_is_found() {
        let blocks = vec![block(0x1000, 0x1010, vec![], 2)];

        let layout = layout(&graph_of(blocks), &crate::app::Renames::default());
        let view = fit(&layout, Size::new(1000.0, 1000.0));

        let inside = Point::new(view.offset.x + 10.0, view.offset.y + 10.0);
        let outside = Point::new(view.offset.x - 40.0, view.offset.y - 40.0);

        assert_eq!(node_at(&layout, view, inside), Some(0x1000));
        assert_eq!(node_at(&layout, view, outside), None);
    }

    #[test]
    fn the_graph_of_nothing_is_empty() {
        let layout = layout(&graph_of(Vec::new()), &crate::app::Renames::default());

        assert!(layout.nodes.is_empty());
        assert!(layout.edges.is_empty());
        assert_eq!(layout.width, 0.0);
        assert_eq!(layout.height, 0.0);
    }

    #[test]
    fn the_bytes_of_a_long_instruction_are_cut_short() {
        assert_eq!(short_bytes("48 89 E5"), "48 89 E5");
        assert_eq!(
            short_bytes("48 8D 05 2B 0E 00 00 01 02 03"),
            "48 8D 05 2B 0E 00 00 01\u{2026}"
        );
    }

    /// The blocks of _init in the sample image.
    ///
    /// The block at 0x1000 goes on in two ways: it falls through to the
    /// block at 0x1014 and takes the branch to 0x1016, which is a row
    /// further down and behind the block at 0x1014.
    fn init_blocks() -> Vec<GraphBlock> {
        vec![
            block(0x1000, 0x1014, vec![0x1016, 0x1014], 5),
            block(0x1014, 0x1016, vec![0x1016], 1),
            block(0x1016, 0x101b, vec![], 2),
        ]
    }

    /// Whether a straight run from one point to another crosses a block.
    ///
    /// The test is Liang and Barsky's: the run is clipped against the
    /// four sides of the block, and it crosses when what is left of it
    /// is not empty.
    fn segment_hits_rectangle(from: Point, to: Point, node: &GraphNode) -> bool {
        let (left, top, right, bottom) =
            (node.x, node.y, node.x + node.width, node.y + node.height);

        // Each side of the block, with the run that pushes out of it.
        let directions = [
            -(to.x - from.x),
            to.x - from.x,
            -(to.y - from.y),
            to.y - from.y,
        ];
        let distances = [from.x - left, right - from.x, from.y - top, bottom - from.y];

        let mut start = 0.0_f32;
        let mut end = 1.0_f32;

        for index in 0..4 {
            if directions[index] == 0.0 {
                // The run is parallel to this side, so it either misses
                // the block or lies outside it.
                if distances[index] < 0.0 {
                    return false;
                }

                continue;
            }

            let crossing = distances[index] / directions[index];

            if directions[index] < 0.0 {
                end = end.min(crossing);
            } else {
                start = start.max(crossing);
            }

            if start > end {
                return false;
            }
        }

        true
    }

    /// Whether the route of an edge runs through a block.
    fn route_hits_block(route: &[Point], node: &GraphNode) -> bool {
        route
            .iter()
            .zip(route.iter().skip(1))
            .any(|(from, to)| segment_hits_rectangle(*from, *to, node))
    }

    #[test]
    fn the_route_of_an_edge_avoids_the_blocks_it_does_not_connect() {
        let layout = layout(&graph_of(init_blocks()), &crate::app::Renames::default());

        for edge in &layout.edges {
            for node in &layout.nodes {
                if node.from == edge.from || node.from == edge.to {
                    continue;
                }

                assert!(
                    !route_hits_block(&edge.route, node),
                    "the edge from {:#x} to {:#x} runs through the block at {:#x}",
                    edge.from,
                    edge.to,
                    node.from
                );
            }
        }
    }

    #[test]
    fn an_edge_that_skips_a_row_goes_around_the_block_in_between() {
        let layout = layout(&graph_of(init_blocks()), &crate::app::Renames::default());

        let edge = layout
            .edges
            .iter()
            .find(|edge| edge.from == 0x1000 && edge.to == 0x1016)
            .expect("the branch of _init");

        let between = layout
            .nodes
            .iter()
            .find(|node| node.from == 0x1014)
            .expect("the block in between");

        // The route leaves the column of the block and comes back to it.
        assert!(
            edge.route
                .iter()
                .any(|point| point.x < between.x || point.x > between.x + between.width),
            "the edge does not go around the block at {:#x}",
            between.from
        );

        assert!(!route_hits_block(&edge.route, between));
    }

    #[test]
    fn the_labels_of_the_edges_leaving_a_block_are_apart() {
        let layout = layout(&graph_of(init_blocks()), &crate::app::Renames::default());

        let anchors: Vec<Point> = layout
            .edges
            .iter()
            .filter(|edge| edge.from == 0x1000)
            .filter_map(|edge| edge.label_point())
            .collect();

        assert_eq!(anchors.len(), 2, "both ways out of the block are named");

        let apart =
            ((anchors[0].x - anchors[1].x).powi(2) + (anchors[0].y - anchors[1].y).powi(2)).sqrt();

        assert!(
            apart >= 16.0,
            "the labels of the two ways out of the block are {apart} apart"
        );

        // And neither of them is painted over a block.
        for anchor in &anchors {
            for node in &layout.nodes {
                assert!(
                    !segment_hits_rectangle(*anchor, *anchor, node),
                    "a label sits on the block at {:#x}",
                    node.from
                );
            }
        }
    }
}
