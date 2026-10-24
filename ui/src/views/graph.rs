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
use iced::{Element, Length, Pixels, Point, Rectangle, Renderer, Size, Theme, Vector};

use crate::app::{App, Message};
use crate::data::{GraphBlock, ListingLine};
use crate::theme::{color, MONO};

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
/// The smallest zoom the reader can choose.
pub const MIN_ZOOM: f32 = 0.2;
/// The largest zoom the reader can choose.
pub const MAX_ZOOM: f32 = 4.0;

/// How far the mouse has to move for a press to be a drag, not a click.
const CLICK_SLOP: f32 = 4.0;

/// One line of a block, as the graph draws it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphLine {
    /// The address of the instruction.
    pub address: String,
    /// The bytes of the instruction.
    pub bytes: String,
    /// The mnemonic of the instruction.
    pub mnemonic: String,
    /// The operands of the instruction.
    pub operands: String,
}

impl GraphLine {
    /// The line of a listing instruction.
    fn of(line: &ListingLine) -> Self {
        Self {
            address: format!("{:08X}", line.address),
            bytes: short_bytes(&line.bytes),
            mnemonic: line.mnemonic.clone(),
            operands: line.operands.clone(),
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

/// What an edge between two blocks means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    /// The block falls into the next one.
    Fallthrough,
    /// The block branches to the next one.
    Taken,
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
}

/// An edge between two blocks.
#[derive(Debug, Clone)]
pub struct GraphEdge {
    /// The block the edge leaves.
    pub from: u64,
    /// The block the edge arrives at.
    pub to: u64,
    /// What the edge means.
    pub kind: EdgeKind,
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

/// Lay the blocks of a function out.
///
/// The blocks are ranked by a depth-first walk from the entry block: the
/// block the walk starts at is at the top, the ones it reaches next are
/// below it. The blocks of a rank sit side by side, in address order, and
/// the ranks stack.
pub fn layout(blocks: &[GraphBlock]) -> GraphLayout {
    let mut nodes: Vec<GraphNode> = blocks
        .iter()
        .map(|block| GraphNode {
            from: block.from,
            to: block.to,
            rank: 0,
            x: 0.0,
            y: 0.0,
            width: NODE_WIDTH,
            height: height_of(block),
            lines: block.instructions.iter().map(GraphLine::of).collect(),
            branching: block.successors.len() > 1,
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

    for row in &rows {
        let mut row_height = 0.0_f32;

        for (column, index) in row.iter().enumerate() {
            let node = &mut nodes[*index];
            node.x = column as f32 * (NODE_WIDTH + GAP_X);
            node.y = y;
            row_height = row_height.max(node.height);
        }

        y += row_height + GAP_Y;
    }

    let width = rows
        .iter()
        .map(|row| row.len() as f32 * (NODE_WIDTH + GAP_X) - GAP_X)
        .fold(0.0_f32, f32::max);

    let height = if rows.is_empty() { 0.0 } else { y - GAP_Y };

    GraphLayout {
        nodes,
        edges: edges_of(blocks),
        width,
        height,
    }
}

/// The edges between the blocks.
///
/// A block that goes on in two ways is a branch: the way that is the
/// address after the block is the fall-through, and the other one is the
/// branch that is taken.
fn edges_of(blocks: &[GraphBlock]) -> Vec<GraphEdge> {
    let mut edges = Vec::new();

    for block in blocks {
        for &successor in &block.successors {
            // The address after the block is the way the code falls off the
            // end of it; every other way is a branch that is taken.
            let kind = if successor == block.to {
                EdgeKind::Fallthrough
            } else {
                EdgeKind::Taken
            };

            edges.push(GraphEdge {
                from: block.from,
                to: successor,
                kind,
            });
        }
    }

    edges
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

/// The height of a block: a header and the lines under it.
fn height_of(block: &GraphBlock) -> f32 {
    HEADER_HEIGHT + PADDING * 2.0 + block.instructions.len() as f32 * LINE_HEIGHT
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
        layout: layout(&app.work.graph),
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

        let focused = selected.is_some_and(|address| address >= node.from && address < node.to);

        let path = canvas::Path::rounded_rectangle(
            Point::new(x, y),
            Size::new(width, height),
            (4.0 * scale).min(6.0).into(),
        );

        frame.fill(
            &path,
            if focused {
                color::FOCUS_BG
            } else {
                color::CARD
            },
        );
        frame.stroke(
            &path,
            canvas::Stroke::default()
                .with_color(if focused { color::CYAN } else { color::LINE })
                .with_width(if focused { 2.0 } else { 1.0 }),
        );

        let size = (12.0 * scale).max(1.0);

        // The header: the range of addresses the block covers.
        frame.fill_text(text(
            &format!("{:#x} - {:#x}", node.from, node.to),
            Point::new(x + PADDING * scale, y + 4.0 * scale),
            color::MUTED,
            size,
        ));

        for (index, line) in node.lines.iter().enumerate() {
            let line_y = y + (HEADER_HEIGHT + PADDING + index as f32 * LINE_HEIGHT) * scale;

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
        }
    }

    /// Draw one edge, with the arrow that points at the next block.
    fn draw_edge(&self, frame: &mut canvas::Frame, edge: &GraphEdge, view: View) {
        let (Some(source), Some(target)) = (
            self.layout.nodes.iter().find(|node| node.from == edge.from),
            self.layout.nodes.iter().find(|node| node.from == edge.to),
        ) else {
            return;
        };

        let points = edge_points(source, target, view);

        if points.len() < 2 {
            return;
        }

        let path = canvas::Path::new(|builder| {
            builder.move_to(points[0]);

            for point in &points[1..] {
                builder.line_to(*point);
            }
        });

        let stroke = if edge.kind == EdgeKind::Taken {
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

        let label = match edge.kind {
            EdgeKind::Fallthrough => "fall-through",
            EdgeKind::Taken => "taken",
        };

        let middle = points[points.len() / 2];

        frame.fill_text(text(
            label,
            Point::new(middle.x + 4.0, middle.y - 12.0),
            color::DIM,
            (10.0 * view.scale).max(1.0),
        ));
    }
}

/// The points an edge is drawn through.
fn edge_points(source: &GraphNode, target: &GraphNode, view: View) -> Vec<Point> {
    let scale = view.scale;
    let place = |x: f32, y: f32| Point::new(view.offset.x + x * scale, view.offset.y + y * scale);

    if target.rank > source.rank {
        // Down the side of the source, across, and down into the target.
        let middle = source.y + source.height + GAP_Y / 2.0;

        vec![
            place(source.x + source.width / 2.0, source.y + source.height),
            place(source.x + source.width / 2.0, middle),
            place(target.x + target.width / 2.0, middle),
            place(target.x + target.width / 2.0, target.y),
        ]
    } else {
        // A loop back: out to the right, along, and in again.
        let side = source.x + source.width + 28.0;

        vec![
            place(source.x + source.width, source.y + source.height / 2.0),
            place(side, source.y + source.height / 2.0),
            place(side, target.y + target.height / 2.0),
            place(target.x + target.width, target.y + target.height / 2.0),
        ]
    }
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
                    comment: None,
                })
                .collect(),
        }
    }

    #[test]
    fn the_blocks_are_ranked_by_the_depth_of_the_walk_that_reaches_them() {
        let blocks = vec![
            block(0x1000, 0x1010, vec![0x1010], 2),
            block(0x1010, 0x1020, vec![0x1020, 0x1030], 2),
            block(0x1020, 0x1030, vec![], 1),
            block(0x1030, 0x1040, vec![], 1),
        ];

        let layout = layout(&blocks);

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

        let layout = layout(&blocks);

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

        let layout = layout(&blocks);

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

        let layout = layout(&blocks);

        assert_eq!(layout.nodes.len(), 2);
        assert!(layout.nodes.iter().all(|node| node.rank < 2));
    }

    #[test]
    fn a_block_the_walk_never_reaches_is_put_below_the_others() {
        let blocks = vec![
            block(0x1000, 0x1010, vec![], 1),
            block(0x2000, 0x2010, vec![], 1),
        ];

        let layout = layout(&blocks);

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

        let layout = layout(&blocks);

        let kind = |to: u64| {
            layout
                .edges
                .iter()
                .find(|edge| edge.from == 0x1010 && edge.to == to)
                .map(|edge| edge.kind)
        };

        assert_eq!(kind(0x1020), Some(EdgeKind::Fallthrough));
        assert_eq!(kind(0x1030), Some(EdgeKind::Taken));
    }

    #[test]
    fn a_block_that_goes_on_in_one_way_falls_through() {
        let blocks = vec![block(0x1000, 0x1010, vec![0x1010], 1)];

        let layout = layout(&blocks);

        assert_eq!(layout.edges.len(), 1);
        assert_eq!(layout.edges[0].kind, EdgeKind::Fallthrough);
        assert!(!layout.nodes[0].branching, "one way is not a branch");
    }

    #[test]
    fn a_block_that_goes_on_in_two_ways_is_a_branch() {
        let blocks = vec![
            block(0x1000, 0x1010, vec![0x1010, 0x1020], 1),
            block(0x1010, 0x1020, vec![], 1),
            block(0x1020, 0x1030, vec![], 1),
        ];

        let layout = layout(&blocks);

        assert!(layout.nodes[0].branching, "two ways is a branch");

        let kind = |to: u64| {
            layout
                .edges
                .iter()
                .find(|edge| edge.from == 0x1000 && edge.to == to)
                .map(|edge| edge.kind)
        };

        assert_eq!(kind(0x1010), Some(EdgeKind::Fallthrough));
        assert_eq!(kind(0x1020), Some(EdgeKind::Taken));
    }

    #[test]
    fn a_jump_that_does_not_fall_through_is_taken() {
        // The block jumps away: the address after it is not where it goes.
        let blocks = vec![
            block(0x1000, 0x1010, vec![0x1020], 1),
            block(0x1020, 0x1030, vec![], 1),
        ];

        let layout = layout(&blocks);

        assert_eq!(layout.edges[0].kind, EdgeKind::Taken);
    }

    #[test]
    fn the_graph_is_fitted_to_the_viewport() {
        let blocks = vec![
            block(0x1000, 0x1010, vec![0x1010], 2),
            block(0x1010, 0x1020, vec![], 2),
        ];

        let layout = layout(&blocks);
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

        let layout = layout(&blocks);
        let view = fit(&layout, Size::new(1000.0, 1000.0));

        let inside = Point::new(view.offset.x + 10.0, view.offset.y + 10.0);
        let outside = Point::new(view.offset.x - 40.0, view.offset.y - 40.0);

        assert_eq!(node_at(&layout, view, inside), Some(0x1000));
        assert_eq!(node_at(&layout, view, outside), None);
    }

    #[test]
    fn the_graph_of_nothing_is_empty() {
        let layout = layout(&[]);

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
}
