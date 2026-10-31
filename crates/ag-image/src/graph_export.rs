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
/// No real graph has more blocks: a bound on the rank relaxation.
const MOST_ROUNDS: usize = 1 << 14;

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
    arrange(title, blocks, edges)
}

/// Arrange blocks and the edges between them into a drawing.
pub fn arrange(title: String, blocks: Vec<LaidBlock>, edges: Vec<(u64, u64, EdgeKind)>) -> Drawing {
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
    let ranks = ranks(&blocks, &index);

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
        row_bottoms.push(y + tallest);
        y += tallest + GAP_Y;
    }
    let right = nodes
        .iter()
        .map(|node| node.x + node.width)
        .fold(0.0_f32, f32::max);

    // The arrows: down from the bottom of the source to the top of the
    // target, bending at the row's gap; back up round the right side.
    let mut drawn = Vec::new();
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
        let points = if ranks[t] > ranks[s] {
            let bend = row_bottoms[ranks[s]] + GAP_Y / 2.0;
            if (sx - tx).abs() < 0.5 {
                vec![(sx, sy), (tx, ty)]
            } else {
                vec![(sx, sy), (sx, bend), (tx, bend), (tx, ty)]
            }
        } else {
            // A loop, or a jump to a block beside: round the right.
            let lane = right + GAP_X / 2.0 + 8.0 * (s % 3) as f32;
            vec![
                (sx, sy),
                (sx, sy + 10.0),
                (lane, sy + 10.0),
                (lane, ty - 10.0),
                (tx, ty - 10.0),
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
/// and a block nothing reaches below the ones that are.
fn ranks(blocks: &[LaidBlock], index: &HashMap<u64, usize>) -> Vec<usize> {
    let n = blocks.len();
    // A depth-first walk from the entry finds the back edges: the ways to
    // a block still open on the stack.
    let mut back: HashSet<(usize, usize)> = HashSet::new();
    let mut reached = vec![false; n];
    let mut on_stack = vec![false; n];
    let mut stack: Vec<(usize, usize)> = vec![(0, 0)];
    reached[0] = true;
    on_stack[0] = true;
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
    // Then the ranks relax over the forward edges until they settle.
    let mut rank = vec![0usize; n];
    for _ in 0..MOST_ROUNDS {
        let mut changed = false;
        for (from, block) in blocks.iter().enumerate() {
            if !reached[from] {
                continue;
            }
            for successor in &block.successors {
                let Some(&to) = index.get(successor) else {
                    continue;
                };
                if back.contains(&(from, to)) || to == from {
                    continue;
                }
                if rank[to] < rank[from] + 1 {
                    rank[to] = rank[from] + 1;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    let deepest = rank.iter().copied().max().unwrap_or(0);
    for i in 0..n {
        if !reached[i] {
            rank[i] = deepest + 1;
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
                "  <text x=\"{}\" y=\"{}\" font-family=\"Courier New, monospace\" font-size=\"11\" fill=\"#1c242c\" xml:space=\"preserve\">{}</text>\n",
                round(node.x + PADDING),
                round(node.y + HEADER_HEIGHT + PADDING + (row as f32 + 0.75) * LINE_HEIGHT),
                escape_xml(line)
            ));
        }
    }
    out.push_str("</svg>\n");
    out
}

/// The drawing as a PDF document: one page the size of the drawing.
pub fn pdf(drawing: &Drawing) -> Vec<u8> {
    let width = drawing.width.max(1.0);
    let height = drawing.height.max(1.0);
    // PDF's origin is the bottom left; the drawing's the top left.
    let flip = |y: f32| height - y;

    let mut content = String::new();
    content.push_str("1 1 1 rg 0 0 ");
    content.push_str(&format!("{} {} re f\n", round(width), round(height)));
    for edge in &drawing.edges {
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
        // The arrowhead: a triangle at the tip, pointing the last way.
        if edge.points.len() >= 2 {
            let (tx, ty) = edge.points[edge.points.len() - 1];
            let (px, py) = edge.points[edge.points.len() - 2];
            let (dx, dy) = (tx - px, ty - py);
            let length = (dx * dx + dy * dy).sqrt().max(0.001);
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

    let objects: Vec<Vec<u8>> = vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {} {}] /Contents 4 0 R /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>",
            round(width),
            round(height)
        )
        .into_bytes(),
        {
            let mut stream = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
            stream.extend_from_slice(content.as_bytes());
            stream.extend_from_slice(b"\nendstream");
            stream
        },
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>".to_vec(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
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
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
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

/// Text inside an SVG element.
fn escape_xml(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            c => c.to_string(),
        })
        .collect()
}

/// Text inside a PDF string: the delimiters escaped, and anything past
/// Latin-1 as a question mark, since the standard fonts reach no further.
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
            c if (c as u32) < 0x100 => out.push_str(&format!("\\{:03o}", c as u32)),
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
        assert!(pdf[start..].starts_with(b"xref\n0 7\n"));
        let mut entry = start + b"xref\n0 7\n".len() + b"0000000000 65535 f \n".len();
        for number in 1..=6 {
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
        assert!(text.contains("/BaseFont /Courier"));
        // Delimiters and non-ASCII are escaped.
        assert_eq!(escape_pdf("a(b)c\\d é ☃"), "a\\(b\\)c\\\\d \\351 ?");
    }

    #[test]
    fn a_graph_of_nothing_is_an_empty_picture() {
        let drawing = arrange("f".to_string(), Vec::new(), Vec::new());
        assert!(drawing.nodes.is_empty());
        assert!(svg(&drawing).contains("<svg"));
        assert!(pdf(&drawing).starts_with(b"%PDF-1.4"));
    }
}
