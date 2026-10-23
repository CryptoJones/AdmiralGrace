use crate::ast::{AstNode, BinaryOp, LoopKind};
use crate::cfg::HighLevelProcedure;
use std::fmt::Write;

pub fn emit_procedure(
    sig: Option<&crate::procedure::FunctionSignature>,
    p: &HighLevelProcedure,
) -> String {
    let mut out = String::new();
    let mut indent = 0usize;
    if let Some(s) = sig {
        let name = s.name.clone().unwrap_or_else(|| "sub_".to_owned());
        let ty = s.return_type.clone().unwrap_or_else(|| "void".to_owned());
        let args = s
            .args
            .iter()
            .map(|a| a.name.clone().unwrap_or_else(|| "arg".into()))
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(out, "{ty} {name}({args})").ok();
        writeln!(out, "{{").ok();
        indent = 1;
    }
    for node in &p.nodes {
        if let Some(ast) = &node.ast {
            for line in emit_node(ast).lines() {
                for _ in 0..indent {
                    out.push_str("  ");
                }
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    if indent == 1 {
        writeln!(out, "}}").ok();
    }
    out
}

pub fn emit_node(n: &AstNode) -> String {
    let mut s = String::new();
    emit_into(n, &mut s, 0);
    let _ = writeln!(s);
    s
}

fn emit_into(n: &AstNode, out: &mut String, ind: usize) {
    let pad = |o: &mut String, i: usize| {
        for _ in 0..(i * 2) {
            o.push(' ');
        }
    };
    match n {
        AstNode::Label { name, address } => {
            let _ = writeln!(out, "{name}: // {address:#x}");
        }
        AstNode::Goto { label, .. } => {
            pad(out, ind);
            let _ = writeln!(out, "goto {label};");
        }
        AstNode::If {
            cond,
            then_part,
            else_part,
            ..
        } => {
            pad(out, ind);
            let _ = write!(out, "if (");
            expr(cond, out);
            let _ = write!(out, ") {{\n");
            emit_into(then_part, out, ind + 1);
            pad(out, ind);
            let _ = writeln!(out, "}}");
            if let Some(e) = else_part {
                pad(out, ind);
                let _ = writeln!(out, "else {{");
                emit_into(e, out, ind + 1);
                pad(out, ind);
                let _ = writeln!(out, "}}");
            }
        }
        AstNode::Loop { cond, body, kind } => {
            pad(out, ind);
            match kind {
                LoopKind::While | LoopKind::For => {
                    let _ = write!(out, "while (");
                    if let Some(c) = cond {
                        expr(c, out);
                    } else {
                        let _ = out.push_str("1");
                    }
                    let _ = writeln!(out, ") {{");
                    emit_into(body, out, ind + 1);
                    pad(out, ind);
                    let _ = writeln!(out, "}}");
                }
                LoopKind::DoWhile => {
                    let _ = writeln!(out, "do {{");
                    emit_into(body, out, ind + 1);
                    pad(out, ind);
                    let _ = write!(out, "}} while (");
                    if let Some(c) = cond {
                        expr(c, out);
                    }
                    let _ = writeln!(out, ");");
                }
            }
        }
        other => {
            pad(out, ind);
            expr(other, out);
            let _ = writeln!(out, ";");
        }
    }
}

fn expr(n: &AstNode, out: &mut String) {
    match n {
        AstNode::Register { reg } => {
            let _ = write!(out, "r{}_{}{}", reg.class, reg.index, size_suffix(reg.bit_size));
        }
        AstNode::Var { name } => {
            let _ = write!(out, "{name}");
        }
        AstNode::Constant { value, .. } => {
            let _ = write!(out, "{value:#x}");
        }
        AstNode::Assign { lhs, rhs } => {
            expr(lhs, out);
            let _ = out.push_str(" = ");
            expr(rhs, out);
        }
        AstNode::Binary { lhs, op, rhs } => {
            let _ = out.push('(');
            expr(lhs, out);
            let _ = write!(out, " {} ", binop(*op));
            expr(rhs, out);
            let _ = out.push(')');
        }
        AstNode::Deref { target } => {
            let _ = out.push_str("(*");
            expr(target, out);
            let _ = out.push(')');
        }
        AstNode::AddressOf { target } => {
            let _ = out.push_str("(&");
            expr(target, out);
            let _ = out.push(')');
        }
        AstNode::Call { callee, args } => {
            expr(callee, out);
            let _ = out.push('(');
            for (i, a) in args.iter().enumerate() {
                expr(a, out);
                if i + 1 != args.len() {
                    let _ = out.push_str(", ");
                }
            }
            let _ = out.push(')');
        }
        AstNode::Intrinsic { name, args } => {
            let _ = write!(out, "{name}(");
            for (i, a) in args.iter().enumerate() {
                expr(a, out);
                if i + 1 != args.len() {
                    let _ = out.push_str(", ");
                }
            }
            let _ = out.push(')');
        }
        AstNode::FunctionName { name, address } => {
            let _ = write!(out, "{name} /* {address:#x} */");
        }
        AstNode::ConditionTrue => {
            let _ = out.push_str("true");
        }
        AstNode::ConditionFalse => {
            let _ = out.push_str("false");
        }
        AstNode::Label { name, address } => {
            let _ = write!(out, "label {name} /* {address:#x} */");
        }
        AstNode::Goto { label, .. } => {
            let _ = write!(out, "goto {label}");
        }
        AstNode::If { cond, .. } => {
            let _ = out.push_str("if (");
            expr(cond, out);
            let _ = out.push(')');
        }
        AstNode::IfGoto { cond, label, negated } => {
            let _ = out.push_str(if *negated { "if (!(" } else { "if (" });
            expr(cond, out);
            let _ = write!(out, ") goto {label}");
        }
        AstNode::Loop { cond, body, kind } => {
            let _ = write!(out, "{:?}(", kind);
            if let Some(c) = cond {
                expr(c, out);
            }
            let _ = out.push_str(") { ... }");
            let _ = body;
        }
    }
}

fn binop(op: BinaryOp) -> &'static str {
    match op {
        BinaryOp::Add => "+",
        BinaryOp::Sub => "-",
        BinaryOp::Mul => "*",
        BinaryOp::Div => "/",
        BinaryOp::Mod => "%",
        BinaryOp::And => "&",
        BinaryOp::Or => "|",
        BinaryOp::Xor => "^",
        BinaryOp::Shl => "<<",
        BinaryOp::Shr => ">>",
        BinaryOp::Equal => "==",
        BinaryOp::NotEqual => "!=",
        BinaryOp::Less => "<",
        BinaryOp::LessEqual => "<=",
        BinaryOp::Greater => ">",
        BinaryOp::GreaterEqual => ">=",
        BinaryOp::LogicalAnd => "&&",
        BinaryOp::LogicalOr => "||",
    }
}

fn size_suffix(bits: u32) -> &'static str {
    match bits {
        8 => ".b",
        16 => ".w",
        32 => ".d",
        64 => ".q",
        _ => "",
    }
}
