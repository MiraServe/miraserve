//! `llms.txt` and `Accept: text/markdown` content negotiation for AI agents.

use http::HeaderMap;
use http::header::ACCEPT;

/// Returns `true` if the client explicitly requests `text/markdown` via `Accept` header
/// or if RFC 9421 Web Bot Auth matched a `serve-markdown=true` rule.
#[must_use]
pub fn prefers_markdown(headers: &HeaderMap, verified_agent_serve_markdown: bool) -> bool {
    if verified_agent_serve_markdown {
        return true;
    }
    let Some(accept) = headers.get(ACCEPT).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    for part in accept.split(',') {
        let mut segs = part.trim().split(';');
        let Some(media) = segs.next() else {
            continue;
        };
        if media.trim().eq_ignore_ascii_case("text/markdown") {
            let mut rejected = false;
            for p in segs {
                if let Some(q_raw) = p
                    .trim()
                    .strip_prefix("q=")
                    .or_else(|| p.trim().strip_prefix("Q="))
                    && let Ok(q) = q_raw.trim().parse::<f32>()
                    && q <= 0.0
                {
                    rejected = true;
                }
            }
            if !rejected {
                return true;
            }
        }
    }
    false
}

/// Computes the sibling `.md` candidate path for a given URL path (e.g., `"/"` -> `"/index.md"`,
/// `"/docs/guide.html"` -> `"/docs/guide.md"`, `"/about"` -> `"/about.md"`).
#[must_use]
pub fn markdown_sibling_path(uri_path: &str) -> Option<String> {
    let trimmed = uri_path.trim();
    if std::path::Path::new(trimmed)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("md"))
        || trimmed == "/llms.txt"
        || trimmed == "/llms-full.txt"
    {
        return None;
    }
    if trimmed.is_empty() || trimmed == "/" {
        return Some("/index.md".to_owned());
    }
    if let Some(prefix) = trimmed.strip_suffix('/') {
        return Some(format!("{prefix}/index.md"));
    }
    if let Some(stem) = trimmed
        .strip_suffix(".html")
        .or_else(|| trimmed.strip_suffix(".htm"))
    {
        return Some(format!("{stem}.md"));
    }
    // Skip non-HTML binary/asset extensions (.png, .css, .js, .woff2, etc.)
    if let Some(last_seg) = trimmed.rsplit('/').next()
        && last_seg.contains('.')
    {
        return None;
    }
    Some(format!("{trimmed}.md"))
}

/// Deterministic, zero-dependency HTML-to-Markdown fallback converter for serving clean
/// Markdown to verified AI agents when no pre-authored `.md` sibling file exists.
#[must_use]
pub fn html_to_markdown(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    let mut skip_tag: Option<&'static str> = None;
    let mut tag_buf = String::new();

    for ch in html.chars() {
        if in_tag {
            if ch == '>' {
                in_tag = false;
                let tag_lower = tag_buf.trim().to_ascii_lowercase();
                let tag_name = tag_lower.split_whitespace().next().unwrap_or("");
                handle_tag(tag_name, &mut skip_tag, &mut out);
                tag_buf.clear();
            } else if tag_buf.len() < 128 {
                tag_buf.push(ch);
            }
            continue;
        }

        if ch == '<' {
            in_tag = true;
            tag_buf.clear();
            continue;
        }

        if skip_tag.is_some() {
            continue;
        }

        out.push(ch);
    }

    collapse_whitespace_lines(&decode_basic_entities(&out))
}

fn handle_tag(tag_name: &str, skip_tag: &mut Option<&'static str>, out: &mut String) {
    if let Some(active_skip) = *skip_tag {
        if tag_name == active_skip {
            *skip_tag = None;
        }
        return;
    }

    match tag_name {
        "script" => *skip_tag = Some("/script"),
        "style" => *skip_tag = Some("/style"),
        "h1" => out.push_str("\n\n# "),
        "h2" => out.push_str("\n\n## "),
        "h3" => out.push_str("\n\n### "),
        "h4" => out.push_str("\n\n#### "),
        "p" | "div" | "section" | "article" | "br" | "/h1" | "/h2" | "/h3" | "/h4" | "/p" => {
            out.push('\n');
        }
        "li" => out.push_str("\n- "),
        "code" | "/code" => out.push('`'),
        "pre" | "/pre" => out.push_str("\n```\n"),
        _ => {}
    }
}

/// Single-pass HTML entity decoder (eliminates repeated full-string reallocations).
fn decode_basic_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('&') {
        out.push_str(rest.get(..pos).unwrap_or(""));
        let tail = rest.get(pos..).unwrap_or("");
        if let Some(after) = tail.strip_prefix("&amp;") {
            out.push('&');
            rest = after;
        } else if let Some(after) = tail.strip_prefix("&lt;") {
            out.push('<');
            rest = after;
        } else if let Some(after) = tail.strip_prefix("&gt;") {
            out.push('>');
            rest = after;
        } else if let Some(after) = tail.strip_prefix("&quot;") {
            out.push('"');
            rest = after;
        } else if let Some(after) = tail.strip_prefix("&#39;") {
            out.push('\'');
            rest = after;
        } else if let Some(after) = tail.strip_prefix("&nbsp;") {
            out.push(' ');
            rest = after;
        } else {
            out.push('&');
            rest = tail.get(1..).unwrap_or("");
        }
    }
    out.push_str(rest);
    out
}

fn collapse_whitespace_lines(input: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut prev_blank = true;

    for raw in input.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            if !prev_blank {
                lines.push(String::new());
                prev_blank = true;
            }
        } else {
            lines.push(trimmed.to_owned());
            prev_blank = false;
        }
    }

    let mut joined = lines.join("\n");
    if !joined.ends_with('\n') {
        joined.push('\n');
    }
    joined
}
