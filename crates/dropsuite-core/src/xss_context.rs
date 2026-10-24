//! Where a reflected marker landed, and whether its metacharacters survived.
//!
//! A marker that comes back is not automatically XSS. `&lt;` in an attribute is not executable,
//! and a marker inside `<script>` needs different syntax than one in the body. This module answers
//! two questions about a reflection — which context it is in, and how much of it was encoded — so
//! the scanner can pick a payload that would actually execute and set a defensible confidence.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReflectionContext {
    /// Between tags: `<p>HERE</p>`.
    HtmlBody,
    /// Inside a quoted attribute value, carrying the quote character.
    Attribute(char),
    /// Inside `<script>` but outside a string literal.
    Script,
    /// Inside a string literal within `<script>`.
    ScriptString(char),
    /// Inside `href`/`src`/`action`/`formaction`/`poster`.
    Url,
    /// Inside `<style>`.
    Style,
    /// Not inside a tag, attribute or script: treated as body.
    Text,
}

impl ReflectionContext {
    pub fn label(self) -> &'static str {
        match self {
            ReflectionContext::HtmlBody | ReflectionContext::Text => "html body",
            ReflectionContext::Attribute('"') => "double-quoted attribute",
            ReflectionContext::Attribute('\'') => "single-quoted attribute",
            ReflectionContext::Attribute(_) => "attribute",
            ReflectionContext::Script => "script block",
            ReflectionContext::ScriptString(_) => "script string",
            ReflectionContext::Url => "url attribute",
            ReflectionContext::Style => "style block",
        }
    }

    /// A payload that breaks out of this context, or `None` when nothing would execute.
    pub fn breakout_payload(self) -> Option<&'static str> {
        match self {
            ReflectionContext::HtmlBody | ReflectionContext::Text => {
                Some("<script>alert(1)</script>")
            }
            ReflectionContext::Attribute('"') => Some("\"><script>alert(1)</script>"),
            ReflectionContext::Attribute('\'') => Some("'><script>alert(1)</script>"),
            ReflectionContext::Attribute(_) => Some("\"><script>alert(1)</script>"),
            ReflectionContext::Script | ReflectionContext::ScriptString(_) => Some("'-alert(1)-'"),
            ReflectionContext::Url => Some("javascript:alert(1)"),
            ReflectionContext::Style => Some("</style><script>alert(1)</script>"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    /// `<marker>` came back byte for byte.
    Verbatim,
    /// The marker came back but its angle brackets did not survive as `<`.
    Partial,
    /// The angle bracket came back as an entity (`&lt;`, `&#60;`, `&#x3c;`).
    Full,
}

/// Classify the context at `offset` by walking the prefix with a small tag/quote state machine.
///
/// Walking the whole prefix is more reliable than a fixed look-back window: a `<script>` opened
/// 3 KB earlier still governs the reflection.
pub fn classify(body: &str, offset: usize) -> ReflectionContext {
    #[derive(PartialEq)]
    enum Phase {
        Text,
        TagName,
        InTag,
        AttrName,
        AttrValue(char),
        Script,
        ScriptString(char),
        Style,
    }

    let bytes = body.as_bytes();
    let end = offset.min(bytes.len());
    let lower = body.to_ascii_lowercase();
    let mut phase = Phase::Text;
    let mut name = String::new();
    let mut attr = String::new();
    let mut i = 0usize;

    while i < end {
        let b = bytes[i] as char;
        match phase {
            Phase::Text => {
                if b == '<' {
                    phase = Phase::TagName;
                    name.clear();
                }
            }
            Phase::TagName => {
                if b.is_ascii_alphanumeric() || b == '-' || b == ':' {
                    name.push(b.to_ascii_lowercase());
                } else if b == '>' {
                    phase = if name == "script" {
                        Phase::Script
                    } else if name == "style" {
                        Phase::Style
                    } else {
                        Phase::Text
                    };
                } else if b.is_whitespace() {
                    phase = Phase::InTag;
                }
            }
            Phase::InTag => {
                if b == '>' {
                    phase = if name == "script" {
                        Phase::Script
                    } else if name == "style" {
                        Phase::Style
                    } else {
                        Phase::Text
                    };
                } else if b == '"' || b == '\'' {
                    attr.clear();
                    phase = Phase::AttrValue(b);
                } else if !b.is_whitespace() && b != '/' {
                    attr.clear();
                    attr.push(b.to_ascii_lowercase());
                    phase = Phase::AttrName;
                }
            }
            Phase::AttrName => {
                if b == '=' {
                    // value follows
                } else if b == '"' || b == '\'' {
                    phase = Phase::AttrValue(b);
                } else if b == '>' {
                    phase = Phase::Text;
                } else if b.is_whitespace() {
                    phase = Phase::InTag;
                } else {
                    attr.push(b.to_ascii_lowercase());
                }
            }
            Phase::AttrValue(q) => {
                if b == q {
                    phase = Phase::InTag;
                } else if b == '>' {
                    phase = Phase::Text;
                }
            }
            Phase::Script => {
                if b == '\'' || b == '"' {
                    phase = Phase::ScriptString(b);
                } else if b == '<' && lower[i..].starts_with("</script") {
                    phase = Phase::Text;
                }
            }
            Phase::ScriptString(q) => {
                if b == q {
                    phase = Phase::Script;
                }
            }
            Phase::Style => {
                if b == '<' && lower[i..].starts_with("</style") {
                    phase = Phase::Text;
                }
            }
        }
        i += 1;
    }

    match phase {
        Phase::Script => ReflectionContext::Script,
        Phase::ScriptString(q) => ReflectionContext::ScriptString(q),
        Phase::Style => ReflectionContext::Style,
        Phase::AttrValue(q) => {
            if matches!(
                attr.as_str(),
                "href" | "src" | "action" | "formaction" | "poster" | "data"
            ) {
                ReflectionContext::Url
            } else {
                ReflectionContext::Attribute(q)
            }
        }
        _ => ReflectionContext::HtmlBody,
    }
}

/// How the marker's angle brackets survived, judged from the reflected text.
///
/// `marker` is the unique token; `body` is the response body.
pub fn encoding_of(body: &str, marker: &str) -> Option<Encoding> {
    if body.contains(&format!("<{marker}>")) {
        return Some(Encoding::Verbatim);
    }
    let lower = body.to_ascii_lowercase();
    for entity in ["&lt;", "&#60;", "&#x3c;", "&#x3C;"] {
        if lower.contains(&format!("{entity}{}", marker.to_ascii_lowercase())) {
            return Some(Encoding::Full);
        }
    }
    body.contains(marker).then_some(Encoding::Partial)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(body: &str, needle: &str) -> usize {
        body.find(needle).unwrap()
    }

    #[test]
    fn plain_text_is_body_context() {
        let body = "<p>hello HERE</p>";
        assert_eq!(
            classify(body, at(body, "HERE")),
            ReflectionContext::HtmlBody
        );
    }

    #[test]
    fn double_and_single_quoted_attributes_are_distinguished() {
        let body = "<input value=\"HERE\">";
        assert_eq!(
            classify(body, at(body, "HERE")),
            ReflectionContext::Attribute('"')
        );
        let body = "<input value='HERE'>";
        assert_eq!(
            classify(body, at(body, "HERE")),
            ReflectionContext::Attribute('\'')
        );
    }

    #[test]
    fn href_is_a_url_context() {
        let body = "<a href=\"HERE\">x</a>";
        assert_eq!(classify(body, at(body, "HERE")), ReflectionContext::Url);
    }

    #[test]
    fn script_block_and_string_are_distinguished() {
        let body = "<script>var a = 1; HERE</script>";
        assert_eq!(classify(body, at(body, "HERE")), ReflectionContext::Script);
        let body = "<script>var a = 'HERE';</script>";
        assert_eq!(
            classify(body, at(body, "HERE")),
            ReflectionContext::ScriptString('\'')
        );
    }

    #[test]
    fn style_block_is_recognised() {
        let body = "<style>.a { color: HERE }</style>";
        assert_eq!(classify(body, at(body, "HERE")), ReflectionContext::Style);
    }

    #[test]
    fn a_closed_script_returns_to_body() {
        let body = "<script>x</script><p>HERE</p>";
        assert_eq!(
            classify(body, at(body, "HERE")),
            ReflectionContext::HtmlBody
        );
    }

    #[test]
    fn encoding_is_classified() {
        assert_eq!(encoding_of("<p><m1></p>", "m1"), Some(Encoding::Verbatim));
        assert_eq!(encoding_of("<p>&lt;m1&gt;</p>", "m1"), Some(Encoding::Full));
        assert_eq!(
            encoding_of("<p>&#x3c;m1&gt;</p>", "m1"),
            Some(Encoding::Full)
        );
        assert_eq!(encoding_of("<p>m1</p>", "m1"), Some(Encoding::Partial));
        assert_eq!(encoding_of("<p>nope</p>", "m1"), None);
    }

    #[test]
    fn every_context_has_a_breakout_payload() {
        for ctx in [
            ReflectionContext::HtmlBody,
            ReflectionContext::Attribute('"'),
            ReflectionContext::Attribute('\''),
            ReflectionContext::Script,
            ReflectionContext::ScriptString('\''),
            ReflectionContext::Url,
            ReflectionContext::Style,
        ] {
            assert!(ctx.breakout_payload().is_some(), "{ctx:?}");
        }
    }
}
