// Shared test-only helpers for interpolating filesystem paths into KDL v2 string literals.

use std::fmt::Write as _;
use std::path::Path;

/// Escapes `raw` for placement inside a double-quoted KDL v2 string literal (`"..."`),
/// handling backslashes, double quotes, and control / Unicode line & bidi characters.
#[allow(dead_code)]
pub(crate) fn kdl_escape_str(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control()
                || matches!(
                    c,
                    '\u{0085}'
                        | '\u{2028}'
                        | '\u{2029}'
                        | '\u{200E}'..='\u{200F}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{FEFF}'
                ) =>
            {
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            }
            other => out.push(other),
        }
    }
    out
}

/// Escapes `path` for placement inside a double-quoted KDL v2 string literal (`"..."`).
#[allow(dead_code)]
pub(crate) fn kdl_escape_path(path: &Path) -> String {
    kdl_escape_str(&path.to_string_lossy())
}
