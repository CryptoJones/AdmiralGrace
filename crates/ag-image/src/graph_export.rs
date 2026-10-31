//! A control-flow graph drawn to a file: SVG, or PDF.
//!
//! Graphs are often needed in reports and write-ups, so the graph a function
//! has in the workbench — or the one `ag image cfg` reports — can be written
//! as a picture. The picture is described first, as a [`Drawing`]: boxes
//! with a title and lines of text, each with a color when the analyst gave
//! the block one, and arrows between them along the points they are routed
//! through. The workbench hands over the drawing it has on screen, routes
//! and highlights and all; the command line lays the graph out here, by the
//! same rule the workbench ranks by — a block sits one row below the deepest
//! block that reaches it, the blocks of a row side by side in address order
//! — with the arrows run straight down, or round the right side back up.
//!
//! Both pictures are written by hand: an SVG as text, a PDF as the objects
//! and the cross-reference table a reader expects, with no library between.
//! The PDF uses the standard Courier and Helvetica fonts every reader has,
//! and one page the size of the drawing in points.

use std::collections::{HashMap, HashSet};

use crate::{ControlFlowGraph, EdgeKind};

/// One box of the drawing: a block of the graph.
#[derive(Debug, Clone, PartialEq)]
pub struct DrawnNode {
    /// The left edge of the box, in points.
    pub x: f32,
    /// The top edge of the box, in points.
    pub y: f32,
    pub width: f32,
    pub height: f32,
    /// The title: the block's range of addresses, or the analyst's text.
    pub title: String,
    /// The lines of text in the box.
    pub lines: Vec<String>,
    /// The analyst's highlight on the block, as red, green and blue.
    pub color: Option<[u8; 3]>,
    /// Whether the block holds the selection: drawn stronger.
    pub selected: bool,
}

/// One arrow of the drawing: an edge of the graph.
#[derive(Debug, Clone, PartialEq)]
pub struct DrawnEdge {
    /// The points the arrow runs through, the last its tip.
    pub points: Vec<(f32, f32)>,
    pub kind: EdgeKind,
}

/// A picture of a graph, in points, the origin at the top left.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Drawing {
    pub width: f32,
    pub height: f32,
    /// The caption: the function's name and address.
    pub title: String,
    pub nodes: Vec<DrawnNode>,
    pub edges: Vec<DrawnEdge>,
}

/// A block as the layout takes it: where it is, where it goes, and the
/// text of its box.
#[derive(Debug, Clone, PartialEq)]
pub struct LaidBlock {
    pub from: u64,
    pub to: u64,
    pub successors: Vec<u64>,
    pub title: String,
    pub lines: Vec<String>,
}

/// The height of a line of text, in points.
pub const LINE_HEIGHT: f32 = 14.0;
/// The height of a box's title row.
pub const HEADER_HEIGHT: f32 = 18.0;
/// The padding inside a box.
pub const PADDING: f32 = 8.0;
/// The gap between boxes in a row, and between rows.
pub const GAP_X: f32 = 40.0;
pub const GAP_Y: f32 = 48.0;
/// The margin round the whole drawing.
pub const MARGIN: f32 = 24.0;
/// The width of one character of the monospace text.
const CHAR_WIDTH: f32 = 6.6;
/// No box is narrower.
const LEAST_WIDTH: f32 = 200.0;
/// The distance between two lanes at the right of the rows.
const LANE: f32 = 8.0;

/// Lay a control-flow graph out as a drawing, with every instruction of
/// every block as a line.
pub fn layout(graph: &ControlFlowGraph) -> Drawing {
    let title = format!(
        "{} at {:#x}",
        graph.name.as_deref().unwrap_or("entry"),
        graph.function
    );
    let blocks: Vec<LaidBlock> = graph
        .blocks
        .iter()
        .map(|block| {
            let lines = block
                .instructions
                .iter()
                .map(|ins| {
                    if ins.operands.is_empty() {
                        format!("{:08x}  {}", ins.address, ins.mnemonic)
                    } else {
                        format!("{:08x}  {} {}", ins.address, ins.mnemonic, ins.operands)
                    }
                })
                .collect();
            LaidBlock {
                from: block.from,
                to: block.to,
                successors: block.successors.clone(),
                title: format!("{:#x} - {:#x}", block.from, block.to),
                lines,
            }
        })
        .collect();
    let edges: Vec<(u64, u64, EdgeKind)> = graph
        .edges
        .iter()
        .map(|edge| (edge.from, edge.to, edge.kind))
        .collect();
    arrange(title, graph.function, blocks, edges)
}

/// Arrange blocks and the edges between them into a drawing, `entry` the
/// block the function starts at.
pub fn arrange(
    title: String,
    entry: u64,
    blocks: Vec<LaidBlock>,
    edges: Vec<(u64, u64, EdgeKind)>,
) -> Drawing {
    if blocks.is_empty() {
        return Drawing {
            title,
            ..Drawing::default()
        };
    }
    let index: HashMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(i, block)| (block.from, i))
        .collect();
    let ranks = ranks(&blocks, &index, index.get(&entry).copied());

    // The boxes: wide enough for their longest line, tall enough for every
    // line.
    let mut nodes: Vec<DrawnNode> = blocks
        .iter()
        .map(|LaidBlock { title, lines, .. }| {
            let longest = lines
                .iter()
                .map(|line| line.chars().count())
                .chain([title.chars().count()])
                .max()
                .unwrap_or(0) as f32;
            DrawnNode {
                x: 0.0,
                y: 0.0,
                width: (longest * CHAR_WIDTH + PADDING * 2.0).max(LEAST_WIDTH),
                height: HEADER_HEIGHT + PADDING * 2.0 + lines.len() as f32 * LINE_HEIGHT,
                title: title.clone(),
                lines: lines.clone(),
                color: None,
                selected: false,
            }
        })
        .collect();

    // The rows: the blocks of a rank side by side, in address order.
    let most_rank = ranks.iter().copied().max().unwrap_or(0);
    let mut rows: Vec<Vec<usize>> = vec![Vec::new(); most_rank + 1];
    for (i, rank) in ranks.iter().enumerate() {
        rows[*rank].push(i);
    }
    for row in &mut rows {
        row.sort_by_key(|i| blocks[*i].from);
    }
    let mut y = MARGIN;
    let mut row_tops = Vec::new();
    let mut row_bottoms = Vec::new();
    for row in &rows {
        let mut x = MARGIN;
        let mut tallest = 0.0_f32;
        for i in row {
            nodes[*i].x = x;
            nodes[*i].y = y;
            x += nodes[*i].width + GAP_X;
            tallest = tallest.max(nodes[*i].height);
        }
        row_tops.push(y);
        row_bottoms.push(y + tallest);
        y += tallest + GAP_Y;
    }
    let right = nodes
        .iter()
        .map(|node| node.x + node.width)
        .fold(0.0_f32, f32::max);

    // The arrows. One to the row below runs down from the bottom of the
    // source to the top of the target, bending in the gap between the
    // rows. One over a row or more, and one back up, runs round the right
    // of the rows in a lane of its own, so it crosses no box between: it
    // leaves in the gap under its row and arrives in the gap over the
    // target's — a loop a little nearer the rows than a skip, so the two
    // do not lie on one line.
    let mut drawn = Vec::new();
    let mut lanes = 0usize;
    for (from, to, kind) in edges {
        let (Some(&s), Some(&t)) = (index.get(&from), index.get(&to)) else {
            continue;
        };
        let source = &nodes[s];
        let target = &nodes[t];
        let sx = source.x + source.width / 2.0;
        let sy = source.y + source.height;
        let tx = target.x + target.width / 2.0;
        let ty = target.y;
        let points = if ranks[t] == ranks[s] + 1 {
            let bend = row_bottoms[ranks[s]] + GAP_Y / 2.0;
            if (sx - tx).abs() < 0.5 {
                vec![(sx, sy), (tx, ty)]
            } else {
                vec![(sx, sy), (sx, bend), (tx, bend), (tx, ty)]
            }
        } else {
            let lane = right + GAP_X / 2.0 + LANE * lanes as f32;
            lanes += 1;
            let (leave, arrive) = if ranks[t] > ranks[s] {
                (
                    row_bottoms[ranks[s]] + GAP_Y / 2.0,
                    row_tops[ranks[t]] - GAP_Y / 3.0,
                )
            } else {
                (
                    row_bottoms[ranks[s]] + GAP_Y / 4.0,
                    (row_tops[ranks[t]] - GAP_Y / 4.0).max(MARGIN / 2.0),
                )
            };
            vec![
                (sx, sy),
                (sx, leave),
                (lane, leave),
                (lane, arrive),
                (tx, arrive),
                (tx, ty),
            ]
        };
        drawn.push(DrawnEdge { points, kind });
    }
    let width = drawn
        .iter()
        .flat_map(|edge| edge.points.iter().map(|point| point.0))
        .chain([right])
        .fold(0.0_f32, f32::max)
        + MARGIN;
    let height = row_bottoms.last().copied().unwrap_or(MARGIN) + MARGIN;
    Drawing {
        width,
        height,
        title,
        nodes,
        edges: drawn,
    }
}

/// The rank of every block: one row below the deepest block that reaches
/// it, a loop back to a block already open pushing nothing further down,
/// and a block the entry cannot reach below the ones it can — the rule
/// the workbench ranks by.
fn ranks(blocks: &[LaidBlock], index: &HashMap<u64, usize>, entry: Option<usize>) -> Vec<usize> {
    let n = blocks.len();
    // Depth-first walks find the back edges — the ways to a block still
    // open on the stack — from the entry first, then from every block no
    // walk has reached, so every cycle has one.
    let mut back: HashSet<(usize, usize)> = HashSet::new();
    let mut reached = vec![false; n];
    let mut on_stack = vec![false; n];
    for start in entry.into_iter().chain(0..n) {
        if reached[start] {
            continue;
        }
        reached[start] = true;
        on_stack[start] = true;
        let mut stack: Vec<(usize, usize)> = vec![(start, 0)];
        while let Some((node, next)) = stack.last().copied() {
            let successors = &blocks[node].successors;
            if next >= successors.len() {
                on_stack[node] = false;
                stack.pop();
                continue;
            }
            stack.last_mut().expect("the top").1 += 1;
            let Some(&to) = index.get(&successors[next]) else {
                continue;
            };
            if on_stack[to] {
                back.insert((node, to));
            } else if !reached[to] {
                reached[to] = true;
                on_stack[to] = true;
                stack.push((to, 0));
            }
        }
    }
    // The forward edges make a graph without cycles; the longest way to a
    // block from any start is its rank, found in one pass in their
    // topological order.
    let mut forward: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut waiting = vec![0usize; n];
    for (from, block) in blocks.iter().enumerate() {
        let mut seen = HashSet::new();
        for successor in &block.successors {
            let Some(&to) = index.get(successor) else {
                continue;
            };
            if to == from || back.contains(&(from, to)) || !seen.insert(to) {
                continue;
            }
            forward[from].push(to);
            waiting[to] += 1;
        }
    }
    let mut rank = vec![0usize; n];
    let mut queue: Vec<usize> = (0..n).filter(|i| waiting[*i] == 0).collect();
    let mut head = 0;
    while head < queue.len() {
        let node = queue[head];
        head += 1;
        for &to in &forward[node] {
            rank[to] = rank[to].max(rank[node] + 1);
            waiting[to] -= 1;
            if waiting[to] == 0 {
                queue.push(to);
            }
        }
    }
    // A block the entry cannot reach is put below the ones it can.
    if let Some(entry) = entry {
        let mut from_entry = vec![false; n];
        from_entry[entry] = true;
        let mut stack = vec![entry];
        while let Some(node) = stack.pop() {
            for successor in &blocks[node].successors {
                if let Some(&to) = index.get(successor) {
                    if !from_entry[to] {
                        from_entry[to] = true;
                        stack.push(to);
                    }
                }
            }
        }
        let floor = (0..n)
            .filter(|i| from_entry[*i])
            .map(|i| rank[i])
            .max()
            .map_or(0, |deepest| deepest + 1);
        for i in 0..n {
            if !from_entry[i] {
                rank[i] += floor;
            }
        }
    }
    rank
}

/// The color an edge is drawn in: blue for a fall-through, orange for a
/// branch taken.
fn edge_color(kind: EdgeKind) -> [u8; 3] {
    match kind {
        EdgeKind::Fallthrough => [0x4c, 0x8e, 0xd8],
        EdgeKind::Taken => [0xd8, 0x8c, 0x3a],
    }
}

/// The fill of a box: the analyst's color lightened, or a plain card.
fn node_fill(node: &DrawnNode) -> [u8; 3] {
    match node.color {
        Some([r, g, b]) => [
            (r as u16 * 3 / 10 + 0xf4 * 7 / 10) as u8,
            (g as u16 * 3 / 10 + 0xf4 * 7 / 10) as u8,
            (b as u16 * 3 / 10 + 0xf4 * 7 / 10) as u8,
        ],
        None => [0xf4, 0xf4, 0xf4],
    }
}

/// No PDF page is longer than this, in points: the format's limit.
const LONGEST_PAGE: f32 = 14400.0;

/// The drawing as an SVG document.
pub fn svg(drawing: &Drawing) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{w}\" height=\"{h}\" viewBox=\"0 0 {w} {h}\">\n",
        w = round(drawing.width.max(1.0)),
        h = round(drawing.height.max(1.0))
    ));
    out.push_str("  <title>");
    out.push_str(&escape_xml(&drawing.title));
    out.push_str("</title>\n");
    out.push_str("  <defs>\n");
    for (name, kind) in [("fall", EdgeKind::Fallthrough), ("taken", EdgeKind::Taken)] {
        let [r, g, b] = edge_color(kind);
        out.push_str(&format!(
            "    <marker id=\"arrow-{name}\" viewBox=\"0 0 10 10\" refX=\"9\" refY=\"5\" markerWidth=\"8\" markerHeight=\"8\" orient=\"auto\"><path d=\"M 0 0 L 10 5 L 0 10 z\" fill=\"#{r:02x}{g:02x}{b:02x}\"/></marker>\n"
        ));
    }
    out.push_str("  </defs>\n");
    out.push_str("  <rect width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>\n");
    for edge in &drawing.edges {
        if edge.points.len() < 2 {
            continue;
        }
        let [r, g, b] = edge_color(edge.kind);
        let name = match edge.kind {
            EdgeKind::Fallthrough => "fall",
            EdgeKind::Taken => "taken",
        };
        let points: Vec<String> = edge
            .points
            .iter()
            .map(|(x, y)| format!("{},{}", round(*x), round(*y)))
            .collect();
        out.push_str(&format!(
            "  <polyline points=\"{}\" fill=\"none\" stroke=\"#{r:02x}{g:02x}{b:02x}\" stroke-width=\"1.5\" marker-end=\"url(#arrow-{name})\"/>\n",
            points.join(" ")
        ));
    }
    for node in &drawing.nodes {
        let [r, g, b] = node_fill(node);
        let stroke = if node.selected { "#1e9ad6" } else { "#8c9aa8" };
        let stroke_width = if node.selected { 2.0 } else { 1.0 };
        out.push_str(&format!(
            "  <rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" rx=\"4\" fill=\"#{r:02x}{g:02x}{b:02x}\" stroke=\"{stroke}\" stroke-width=\"{stroke_width}\"/>\n",
            round(node.x),
            round(node.y),
            round(node.width),
            round(node.height)
        ));
        out.push_str(&format!(
            "  <text x=\"{}\" y=\"{}\" font-family=\"Helvetica, Arial, sans-serif\" font-size=\"11\" fill=\"#5c6a78\">{}</text>\n",
            round(node.x + PADDING),
            round(node.y + 13.0),
            escape_xml(&node.title)
        ));
        for (row, line) in node.lines.iter().enumerate() {
            out.push_str(&format!(
                "  <text x=\"{}\" y=\"{}\" font-family=\"Courier New, monospace\" font-size=\"11\" fill=\"#1c242c\" xml:space=\"preserve\" style=\"white-space:pre\">{}</text>\n",
                round(node.x + PADDING),
                round(node.y + HEADER_HEIGHT + PADDING + (row as f32 + 0.75) * LINE_HEIGHT),
                escape_xml(line)
            ));
        }
    }
    out.push_str("</svg>\n");
    out
}

/// The drawing as a PDF document: one page the size of the drawing, or
/// scaled down to the longest page the format allows.
pub fn pdf(drawing: &Drawing) -> Vec<u8> {
    let width = drawing.width.max(1.0);
    let height = drawing.height.max(1.0);
    let scale = (LONGEST_PAGE / width.max(height)).min(1.0);
    // PDF's origin is the bottom left; the drawing's the top left.
    let flip = |y: f32| height - y;

    let mut content = String::new();
    if scale < 1.0 {
        let s = round(scale);
        content.push_str(&format!("{s} 0 0 {s} 0 0 cm\n"));
    }
    content.push_str("1 1 1 rg 0 0 ");
    content.push_str(&format!("{} {} re f\n", round(width), round(height)));
    for edge in &drawing.edges {
        if edge.points.len() < 2 {
            continue;
        }
        let [r, g, b] = edge_color(edge.kind);
        content.push_str(&format!(
            "{} {} {} RG {} {} {} rg 1.5 w\n",
            frac(r),
            frac(g),
            frac(b),
            frac(r),
            frac(g),
            frac(b)
        ));
        let mut points = edge.points.iter();
        if let Some((x, y)) = points.next() {
            content.push_str(&format!("{} {} m\n", round(*x), round(flip(*y))));
        }
        for (x, y) in points {
            content.push_str(&format!("{} {} l\n", round(*x), round(flip(*y))));
        }
        content.push_str("S\n");
        // The arrowhead: a triangle at the tip, pointing the way of the
        // last run that goes anywhere.
        let (tx, ty) = edge.points[edge.points.len() - 1];
        let before = edge.points[..edge.points.len() - 1]
            .iter()
            .rev()
            .find(|(x, y)| (x - tx).abs() > 0.01 || (y - ty).abs() > 0.01);
        if let Some(&(px, py)) = before {
            let (dx, dy) = (tx - px, ty - py);
            let length = (dx * dx + dy * dy).sqrt();
            let (ux, uy) = (dx / length, dy / length);
            let (nx, ny) = (-uy, ux);
            let base_x = tx - ux * 8.0;
            let base_y = ty - uy * 8.0;
            content.push_str(&format!(
                "{} {} m {} {} l {} {} l f\n",
                round(tx),
                round(flip(ty)),
                round(base_x + nx * 4.0),
                round(flip(base_y + ny * 4.0)),
                round(base_x - nx * 4.0),
                round(flip(base_y - ny * 4.0))
            ));
        }
    }
    for node in &drawing.nodes {
        let [r, g, b] = node_fill(node);
        let (sr, sg, sb) = if node.selected {
            (0x1e, 0x9a, 0xd6)
        } else {
            (0x8c, 0x9a, 0xa8)
        };
        content.push_str(&format!(
            "{} {} {} rg {} {} {} RG {} w {} {} {} {} re B\n",
            frac(r),
            frac(g),
            frac(b),
            frac(sr),
            frac(sg),
            frac(sb),
            if node.selected { 2 } else { 1 },
            round(node.x),
            round(flip(node.y + node.height)),
            round(node.width),
            round(node.height)
        ));
        content.push_str(&format!(
            "BT /F2 11 Tf 0.36 0.42 0.47 rg {} {} Td ({}) Tj ET\n",
            round(node.x + PADDING),
            round(flip(node.y + 13.0)),
            escape_pdf(&node.title)
        ));
        for (row, line) in node.lines.iter().enumerate() {
            content.push_str(&format!(
                "BT /F1 10 Tf 0.11 0.14 0.17 rg {} {} Td ({}) Tj ET\n",
                round(node.x + PADDING),
                round(flip(
                    node.y + HEADER_HEIGHT + PADDING + (row as f32 + 0.75) * LINE_HEIGHT
                )),
                escape_pdf(line)
            ));
        }
    }

    // The title, as the document's: in UTF-16 with its byte-order mark, so
    // any name survives.
    let title_hex: String = std::iter::once(0xfeffu16)
        .chain(drawing.title.encode_utf16())
        .map(|unit| format!("{unit:04X}"))
        .collect();
    let objects: Vec<Vec<u8>> = vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {} {}] /Contents 4 0 R /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>",
            round(width * scale),
            round(height * scale)
        )
        .into_bytes(),
        {
            let mut stream = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
            stream.extend_from_slice(content.as_bytes());
            stream.extend_from_slice(b"\nendstream");
            stream
        },
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>".to_vec(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>".to_vec(),
        format!("<< /Title <{title_hex}> /Producer (ag) >>").into_bytes(),
    ];
    let mut out = Vec::new();
    out.extend_from_slice(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n");
    let mut offsets = Vec::new();
    for (number, object) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", number + 1).as_bytes());
        out.extend_from_slice(object);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R /Info 7 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

/// A length to two decimals, as the formats like it.
fn round(value: f32) -> String {
    let text = format!("{value:.2}");
    let text = text.trim_end_matches('0').trim_end_matches('.');
    if text.is_empty() || text == "-" {
        "0".to_string()
    } else {
        text.to_string()
    }
}

/// A color channel as the fraction PDF takes.
fn frac(channel: u8) -> String {
    round(channel as f32 / 255.0)
}

/// Text inside an SVG element: the markup escaped, and the characters XML
/// has no place for — control characters other than tab and newline, and
/// the two non-characters — shown as the replacement character.
fn escape_xml(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\t' | '\n' | '\r' => c.to_string(),
            c if (c as u32) < 0x20 || c == '\u{fffe}' || c == '\u{ffff}' => '\u{fffd}'.to_string(),
            c => c.to_string(),
        })
        .collect()
}

/// Text inside a PDF string, for a font in WinAnsi encoding: the
/// delimiters escaped, Latin-1 as octal escapes, and anything the encoding
/// has no glyph for — the C1 controls, and everything past Latin-1 — as a
/// question mark.
fn escape_pdf(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        match c {
            '(' | ')' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\r' | '\n' => out.push(' '),
            c if (c as u32) < 0x80 => out.push(c),
            c if (0xa0..0x100).contains(&(c as u32)) => {
                out.push_str(&format!("\\{:03o}", c as u32))
            }
            _ => out.push('?'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn laid(from: u64, to: u64, successors: Vec<u64>, lines: &[&str]) -> LaidBlock {
        LaidBlock {
            from,
            to,
            successors,
            title: format!("{from:#x} - {to:#x}"),
            lines: lines.iter().map(|line| line.to_string()).collect(),
        }
    }

    fn drawing() -> Drawing {
        arrange(
            "f at 0x1000".to_string(),
            0x1000,
            vec![
                laid(
                    0x1000,
                    0x1010,
                    vec![0x1010, 0x1020],
                    &["00001000  cmp eax, 1", "00001004  jne 0x1020"],
                ),
                laid(0x1010, 0x1020, vec![0x1030], &["00001010  mov eax, 2"]),
                laid(
                    0x1020,
                    0x1030,
                    vec![0x1030, 0x1000],
                    &["00001020  mov eax, 3", "00001024  jl 0x1000"],
                ),
                laid(0x1030, 0x1040, vec![], &["00001030  ret"]),
            ],
            vec![
                (0x1000, 0x1010, EdgeKind::Fallthrough),
                (0x1000, 0x1020, EdgeKind::Taken),
                (0x1010, 0x1030, EdgeKind::Fallthrough),
                (0x1020, 0x1030, EdgeKind::Fallthrough),
                (0x1020, 0x1000, EdgeKind::Taken),
            ],
        )
    }

    #[test]
    fn the_blocks_are_ranked_and_laid_in_rows() {
        let drawing = drawing();
        assert_eq!(drawing.nodes.len(), 4);
        let y = |title: &str| {
            drawing
                .nodes
                .iter()
                .find(|node| node.title == title)
                .expect(title)
                .y
        };
        // The entry on top, its two successors side by side, the join below.
        assert!(y("0x1000 - 0x1010") < y("0x1010 - 0x1020"));
        assert_eq!(y("0x1010 - 0x1020"), y("0x1020 - 0x1030"));
        assert!(y("0x1020 - 0x1030") < y("0x1030 - 0x1040"));
        let (left, right) = (
            drawing
                .nodes
                .iter()
                .find(|n| n.title == "0x1010 - 0x1020")
                .unwrap(),
            drawing
                .nodes
                .iter()
                .find(|n| n.title == "0x1020 - 0x1030")
                .unwrap(),
        );
        assert!(left.x + left.width <= right.x);
        // Every box is inside the drawing; the loop's arrow runs back up.
        for node in &drawing.nodes {
            assert!(node.x >= 0.0 && node.y >= 0.0);
            assert!(node.x + node.width <= drawing.width);
            assert!(node.y + node.height <= drawing.height);
        }
        assert_eq!(drawing.edges.len(), 5);
        let back = &drawing.edges[4];
        assert!(back.points.len() == 6, "{back:?}");
        assert!(back.points.last().unwrap().1 < back.points[0].1);
    }

    #[test]
    fn the_svg_holds_a_box_and_its_text_for_every_block() {
        let svg = svg(&drawing());
        assert!(svg.starts_with("<svg xmlns=\"http://www.w3.org/2000/svg\""));
        assert!(svg.ends_with("</svg>\n"));
        assert_eq!(svg.matches("<rect x=").count(), 4);
        assert_eq!(svg.matches("<polyline").count(), 5);
        assert!(svg.contains("00001004  jne 0x1020"), "{svg}");
        assert!(svg.contains("<title>f at 0x1000</title>"));
        // Text is escaped.
        let mut odd = drawing();
        odd.nodes[0].lines[0] = "mov rax, [rbx<rcx] & \"x\"".to_string();
        let svg = super::svg(&odd);
        assert!(svg.contains("[rbx&lt;rcx] &amp; &quot;x&quot;"), "{svg}");
    }

    #[test]
    fn the_pdf_is_one_page_whose_cross_references_are_right() {
        let pdf = pdf(&drawing());
        assert!(pdf.starts_with(b"%PDF-1.4\n"));
        assert!(pdf.ends_with(b"%%EOF\n"));
        // The offsets count bytes, and the header holds four that are not
        // text, so the table is checked against the bytes themselves.
        let find = |needle: &[u8]| {
            pdf.windows(needle.len())
                .position(|window| window == needle)
                .expect("the needle")
        };
        let number_at = |offset: usize| -> usize {
            let digits: Vec<u8> = pdf[offset..]
                .iter()
                .copied()
                .take_while(u8::is_ascii_digit)
                .collect();
            String::from_utf8(digits)
                .unwrap()
                .parse()
                .expect("a number")
        };
        // startxref names where the table is, and each entry where its
        // object is.
        let start = number_at(find(b"startxref\n") + 10);
        assert!(pdf[start..].starts_with(b"xref\n0 8\n"));
        let mut entry = start + b"xref\n0 8\n".len() + b"0000000000 65535 f \n".len();
        for number in 1..=7 {
            let offset = number_at(entry);
            let expected = format!("{number} 0 obj\n");
            assert!(
                pdf[offset..].starts_with(expected.as_bytes()),
                "object {number}"
            );
            entry += 20;
        }
        // The content stream's length is exact, and the text is in it.
        let stream_start = find(b"stream\n") + 7;
        let stream_end = find(b"\nendstream");
        let length = number_at(find(b"/Length ") + 8);
        assert_eq!(stream_end - stream_start, length);
        let text = String::from_utf8_lossy(&pdf).into_owned();
        assert!(text.contains("(00001004  jne 0x1020) Tj"), "{text}");
        assert!(text.contains("/BaseFont /Courier /Encoding /WinAnsiEncoding"));
        assert!(text.contains("/Info 7 0 R"));
        // The title in UTF-16 with its byte-order mark.
        assert!(
            text.contains("/Title <FEFF00660020006100740020003000780031003000300030>"),
            "{text}"
        );
        // Delimiters and Latin-1 are escaped; the C1 controls and anything
        // past Latin-1 have no glyph.
        assert_eq!(
            escape_pdf("a(b)c\\d é \u{85} ☃"),
            "a\\(b\\)c\\\\d \\351 ? ?"
        );
    }

    #[test]
    fn a_long_drawing_is_scaled_onto_the_longest_page() {
        let mut long = drawing();
        long.height = 30_000.0;
        let pdf = pdf(&long);
        let text = String::from_utf8_lossy(&pdf).into_owned();
        let media = text
            .split("/MediaBox [0 0 ")
            .nth(1)
            .and_then(|rest| rest.split(']').next())
            .expect("the box");
        let sides: Vec<f32> = media
            .split(' ')
            .map(|side| side.parse().expect("a length"))
            .collect();
        assert!(sides.iter().all(|side| *side <= LONGEST_PAGE), "{media}");
        assert!((sides[1] - LONGEST_PAGE).abs() < 0.01, "{media}");
        assert!(text.contains("0.48 0 0 0.48 0 0 cm\n"), "{text}");
        // One that fits is not scaled.
        assert!(!String::from_utf8_lossy(&super::pdf(&drawing())).contains(" cm\n"));
    }

    #[test]
    fn an_edge_without_a_route_and_bad_characters_are_left_out() {
        let mut odd = drawing();
        odd.edges.push(DrawnEdge {
            points: vec![(1.0, 1.0)],
            kind: EdgeKind::Taken,
        });
        odd.edges.push(DrawnEdge {
            points: Vec::new(),
            kind: EdgeKind::Taken,
        });
        odd.nodes[0].lines[0] = "esc\u{1b} nul\0 tab\t ok \u{fffe}".to_string();
        let svg = svg(&odd);
        assert_eq!(svg.matches("<polyline").count(), 5);
        assert!(
            svg.contains("esc\u{fffd} nul\u{fffd} tab\t ok \u{fffd}"),
            "{svg}"
        );
        let pdf = pdf(&odd);
        let text = String::from_utf8_lossy(&pdf).into_owned();
        // Five routes stroked, no stroke without a path.
        assert_eq!(text.matches("\nS\n").count(), 5, "{text}");
        assert!(!text.contains("w\nS\n"));
    }

    #[test]
    fn an_edge_over_a_row_runs_round_the_boxes_between() {
        // The if-then shape: A -> B, A -> C, B -> C.
        let drawing = arrange(
            "f".to_string(),
            0x1000,
            vec![
                laid(
                    0x1000,
                    0x1010,
                    vec![0x1010, 0x1020],
                    &["00001000  test eax, eax", "00001004  je 0x1020"],
                ),
                laid(0x1010, 0x1020, vec![0x1020], &["00001010  mov eax, 1"]),
                laid(0x1020, 0x1030, vec![], &["00001020  ret"]),
            ],
            vec![
                (0x1000, 0x1010, EdgeKind::Fallthrough),
                (0x1000, 0x1020, EdgeKind::Taken),
                (0x1010, 0x1020, EdgeKind::Fallthrough),
            ],
        );
        assert_eq!(drawing.edges.len(), 3);
        for edge in &drawing.edges {
            for pair in edge.points.windows(2) {
                let ((x1, y1), (x2, y2)) = (pair[0], pair[1]);
                for node in &drawing.nodes {
                    let (left, right) = (node.x, node.x + node.width);
                    let (top, bottom) = (node.y, node.y + node.height);
                    let inside_x = |x: f32| x > left + 0.01 && x < right - 0.01;
                    let inside_y = |y: f32| y > top + 0.01 && y < bottom - 0.01;
                    let crosses = if (x1 - x2).abs() < 0.01 {
                        inside_x(x1) && y1.min(y2) < bottom - 0.01 && y1.max(y2) > top + 0.01
                    } else {
                        inside_y(y1) && x1.min(x2) < right - 0.01 && x1.max(x2) > left + 0.01
                    };
                    assert!(!crosses, "{edge:?} crosses {}", node.title);
                }
            }
        }
        // The skip leaves to the right of every box and comes back over C.
        let skip = &drawing.edges[1];
        assert_eq!(skip.points.len(), 6);
        let right = drawing
            .nodes
            .iter()
            .map(|n| n.x + n.width)
            .fold(0.0, f32::max);
        assert!(skip.points[2].0 > right);
        assert!(skip.points[2].0 < drawing.width);
    }

    #[test]
    fn the_entry_is_on_top_even_when_it_is_not_first_and_a_stray_block_goes_below() {
        // The entry at 0x1010 jumps to 0x1020, which goes on to the tail
        // at 0x1000; 0x1030 jumps into the tail too but nothing reaches it.
        let drawing = arrange(
            "f".to_string(),
            0x1010,
            vec![
                laid(0x1000, 0x1010, vec![], &["ret"]),
                laid(0x1010, 0x1020, vec![0x1020], &["jmp"]),
                laid(0x1020, 0x1030, vec![0x1000], &["jmp"]),
                laid(0x1030, 0x1040, vec![0x1000], &["jmp"]),
            ],
            vec![
                (0x1010, 0x1020, EdgeKind::Fallthrough),
                (0x1020, 0x1000, EdgeKind::Taken),
                (0x1030, 0x1000, EdgeKind::Taken),
            ],
        );
        let y = |from: &str| {
            drawing
                .nodes
                .iter()
                .find(|n| n.title.starts_with(from))
                .unwrap()
                .y
        };
        assert!(y("0x1010") < y("0x1020"));
        assert!(y("0x1020") < y("0x1000"));
        assert!(y("0x1000") < y("0x1030"));
        // Odd shapes do not panic: a self loop, an edge to a block that is
        // not there, and two blocks at one address.
        let odd = arrange(
            "g".to_string(),
            0x1000,
            vec![
                laid(0x1000, 0x1010, vec![0x1000, 0x9999, 0x1010], &["x"]),
                laid(0x1010, 0x1020, vec![], &["y"]),
                laid(0x1010, 0x1020, vec![0x1000], &["z"]),
            ],
            vec![
                (0x1000, 0x1000, EdgeKind::Taken),
                (0x1000, 0x9999, EdgeKind::Taken),
                (0x1000, 0x1010, EdgeKind::Fallthrough),
            ],
        );
        assert_eq!(odd.nodes.len(), 3);
        assert_eq!(odd.edges.len(), 2);
        assert!(svg(&odd).contains("<svg"));
    }

    #[test]
    fn a_graph_of_nothing_is_an_empty_picture() {
        let drawing = arrange("f".to_string(), 0, Vec::new(), Vec::new());
        assert!(drawing.nodes.is_empty());
        assert!(svg(&drawing).contains("<svg"));
        assert!(pdf(&drawing).starts_with(b"%PDF-1.4"));
    }
}
