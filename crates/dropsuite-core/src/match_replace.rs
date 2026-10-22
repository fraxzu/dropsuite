use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchReplaceTarget {
    RequestHeader,
    RequestBody,
    ResponseHeader,
    ResponseBody,
    RequestFirstLine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchReplaceRule {
    pub id: String,
    pub enabled: bool,
    pub comment: String,
    pub target: MatchReplaceTarget,
    pub is_regex: bool,
    pub pattern: String,
    pub replacement: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MatchReplaceConfig {
    pub enabled: bool,
    pub rules: Vec<MatchReplaceRule>,
}

#[derive(Default)]
pub struct MatchReplaceEngine {
    config: RwLock<MatchReplaceConfig>,
}

impl MatchReplaceEngine {
    pub fn new() -> Self {
        Self {
            config: RwLock::new(MatchReplaceConfig::default()),
        }
    }

    pub fn with_config(config: MatchReplaceConfig) -> Self {
        Self {
            config: RwLock::new(config),
        }
    }

    pub fn get_config(&self) -> MatchReplaceConfig {
        self.config.read().unwrap().clone()
    }

    pub fn set_config(&self, config: MatchReplaceConfig) {
        *self.config.write().unwrap() = config;
    }

    /// Apply matching rules to request head wire bytes (request line + headers).
    pub fn apply_request_head(&self, wire: &[u8]) -> Vec<u8> {
        let cfg = self.config.read().unwrap();
        if !cfg.enabled || cfg.rules.is_empty() {
            return wire.to_vec();
        }

        let text = match std::str::from_utf8(wire) {
            Ok(s) => s,
            Err(_) => return wire.to_vec(),
        };

        let mut lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
        if lines.is_empty() {
            return wire.to_vec();
        }

        let enabled_rules: Vec<&MatchReplaceRule> = cfg.rules.iter().filter(|r| r.enabled).collect();

        // 1. Process RequestFirstLine on line 0
        for r in enabled_rules.iter().filter(|r| r.target == MatchReplaceTarget::RequestFirstLine) {
            lines[0] = apply_string_rule(r, &lines[0]);
        }

        // 2. Process RequestHeader rules on lines 1..
        for r in enabled_rules.iter().filter(|r| r.target == MatchReplaceTarget::RequestHeader) {
            if r.pattern.trim().is_empty() && !r.replacement.trim().is_empty() {
                // Header Addition rule (empty pattern)
                // Insert the new header before the blank line that terminates the head, so it stays
                // a header instead of spilling past the CRLFCRLF into the body (which malforms the
                // message and makes upstreams/proxies reject it).
                let insert_at = lines.iter().position(|l| l.is_empty()).unwrap_or(lines.len());
                lines.insert(insert_at, r.replacement.trim().to_string());
            } else {
                let mut i = 1;
                while i < lines.len() {
                    let line = &lines[i];
                    if line.is_empty() {
                        i += 1;
                        continue;
                    }
                    if is_match(r, line) {
                        if r.replacement.trim().is_empty() {
                            // Header removal rule
                            lines.remove(i);
                            continue;
                        } else {
                            lines[i] = apply_string_rule(r, line);
                        }
                    }
                    i += 1;
                }
            }
        }

        // Drop any blank separator line(s) left at the tail, then append exactly one CRLFCRLF so the
        // head is always well-formed — an added header can't leave a stray blank line in the middle.
        while matches!(lines.last(), Some(l) if l.is_empty()) {
            lines.pop();
        }
        let out = lines.join("\r\n") + "\r\n\r\n";
        out.into_bytes()
    }

    /// Apply matching rules to request body bytes.
    pub fn apply_request_body(&self, body: &[u8]) -> Vec<u8> {
        self.apply_body_rules(body, MatchReplaceTarget::RequestBody)
    }

    /// Apply matching rules to response head wire bytes.
    pub fn apply_response_head(&self, wire: &[u8]) -> Vec<u8> {
        let cfg = self.config.read().unwrap();
        if !cfg.enabled || cfg.rules.is_empty() {
            return wire.to_vec();
        }

        let text = match std::str::from_utf8(wire) {
            Ok(s) => s,
            Err(_) => return wire.to_vec(),
        };

        let mut lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
        if lines.is_empty() {
            return wire.to_vec();
        }

        let enabled_rules: Vec<&MatchReplaceRule> = cfg
            .rules
            .iter()
            .filter(|r| r.enabled && r.target == MatchReplaceTarget::ResponseHeader)
            .collect();

        for r in enabled_rules {
            if r.pattern.trim().is_empty() && !r.replacement.trim().is_empty() {
                // Insert the new header before the blank line that terminates the head, so it stays
                // a header instead of spilling past the CRLFCRLF into the body (which malforms the
                // message and makes upstreams/proxies reject it).
                let insert_at = lines.iter().position(|l| l.is_empty()).unwrap_or(lines.len());
                lines.insert(insert_at, r.replacement.trim().to_string());
            } else {
                let mut i = 1;
                while i < lines.len() {
                    let line = &lines[i];
                    if line.is_empty() {
                        i += 1;
                        continue;
                    }
                    if is_match(r, line) {
                        if r.replacement.trim().is_empty() {
                            lines.remove(i);
                            continue;
                        } else {
                            lines[i] = apply_string_rule(r, line);
                        }
                    }
                    i += 1;
                }
            }
        }

        // Drop any blank separator line(s) left at the tail, then append exactly one CRLFCRLF so the
        // head is always well-formed — an added header can't leave a stray blank line in the middle.
        while matches!(lines.last(), Some(l) if l.is_empty()) {
            lines.pop();
        }
        let out = lines.join("\r\n") + "\r\n\r\n";
        out.into_bytes()
    }

    /// Apply matching rules to response body bytes.
    pub fn apply_response_body(&self, body: &[u8]) -> Vec<u8> {
        self.apply_body_rules(body, MatchReplaceTarget::ResponseBody)
    }

    fn apply_body_rules(&self, body: &[u8], target: MatchReplaceTarget) -> Vec<u8> {
        let cfg = self.config.read().unwrap();
        if !cfg.enabled || cfg.rules.is_empty() || body.is_empty() {
            return body.to_vec();
        }

        let text = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(_) => return body.to_vec(),
        };

        let enabled_rules: Vec<&MatchReplaceRule> = cfg
            .rules
            .iter()
            .filter(|r| r.enabled && r.target == target)
            .collect();

        if enabled_rules.is_empty() {
            return body.to_vec();
        }

        let mut cur = text.to_string();
        for r in enabled_rules {
            cur = apply_string_rule(r, &cur);
        }

        cur.into_bytes()
    }
}

fn is_match(rule: &MatchReplaceRule, text: &str) -> bool {
    if rule.is_regex {
        if let Ok(re) = Regex::new(&format!("(?i){}", rule.pattern)) {
            re.is_match(text)
        } else {
            false
        }
    } else {
        text.to_ascii_lowercase().contains(&rule.pattern.to_ascii_lowercase())
    }
}

fn apply_string_rule(rule: &MatchReplaceRule, input: &str) -> String {
    if rule.is_regex {
        if let Ok(re) = Regex::new(&rule.pattern) {
            re.replace_all(input, rule.replacement.as_str()).to_string()
        } else {
            input.to_string()
        }
    } else {
        input.replace(&rule.pattern, &rule.replacement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_replace_request_headers_and_body() {
        let config = MatchReplaceConfig {
            enabled: true,
            rules: vec![
                MatchReplaceRule {
                    id: "1".into(),
                    enabled: true,
                    comment: "Emulate Mobile UA".into(),
                    target: MatchReplaceTarget::RequestHeader,
                    is_regex: true,
                    pattern: r"^User-Agent: .*".into(),
                    replacement: "User-Agent: MobileTester/1.0".into(),
                },
                MatchReplaceRule {
                    id: "2".into(),
                    enabled: true,
                    comment: "Add security token".into(),
                    target: MatchReplaceTarget::RequestHeader,
                    is_regex: false,
                    pattern: "".into(),
                    replacement: "X-Security-Audit: true".into(),
                },
                MatchReplaceRule {
                    id: "3".into(),
                    enabled: true,
                    comment: "Tamper role in JSON body".into(),
                    target: MatchReplaceTarget::RequestBody,
                    is_regex: false,
                    pattern: r#""role":"user""#.into(),
                    replacement: r#""role":"admin""#.into(),
                },
            ],
        };

        let engine = MatchReplaceEngine::with_config(config);

        let req_head = b"POST /api/login HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nContent-Length: 15\r\n\r\n";
        let modified_head = String::from_utf8(engine.apply_request_head(req_head)).unwrap();

        assert!(modified_head.contains("User-Agent: MobileTester/1.0"));
        assert!(modified_head.contains("X-Security-Audit: true"));

        let req_body = br#"{"username":"test","role":"user"}"#;
        let modified_body = String::from_utf8(engine.apply_request_body(req_body)).unwrap();
        assert_eq!(modified_body, r#"{"username":"test","role":"admin"}"#);
    }

    #[test]
    fn test_match_replace_strip_response_security_headers() {
        let config = MatchReplaceConfig {
            enabled: true,
            rules: vec![MatchReplaceRule {
                id: "csp_strip".into(),
                enabled: true,
                comment: "Strip Content-Security-Policy".into(),
                target: MatchReplaceTarget::ResponseHeader,
                is_regex: true,
                pattern: r"^Content-Security-Policy: .*".into(),
                replacement: "".into(),
            }],
        };

        let engine = MatchReplaceEngine::with_config(config);

        let resp_head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Security-Policy: default-src 'self'\r\nX-Frame-Options: DENY\r\n\r\n";
        let modified_resp = String::from_utf8(engine.apply_response_head(resp_head)).unwrap();

        assert!(!modified_resp.contains("Content-Security-Policy"));
        assert!(modified_resp.contains("X-Frame-Options: DENY"));
    }

    #[test]
    fn test_added_request_header_lands_inside_the_head_not_the_body() {
        // Regression: an "add header" rule used to push the new line AFTER the CRLFCRLF terminator,
        // so the header spilled into the body and malformed the request — upstreams/proxies then
        // rejected it (seen live as "502 Bad Gateway" when the Inject-Audit-Header preset was on).
        let config = MatchReplaceConfig {
            enabled: true,
            rules: vec![MatchReplaceRule {
                id: "add_audit".into(),
                enabled: true,
                comment: "Inject audit header".into(),
                target: MatchReplaceTarget::RequestHeader,
                is_regex: false,
                pattern: "".into(),
                replacement: "X-DropSuite-Audit: true".into(),
            }],
        };
        let engine = MatchReplaceEngine::with_config(config);
        // Absolute-form request line, exactly as a client sends it through a proxy.
        let head = b"GET http://127.0.0.1:9000/cek HTTP/1.1\r\nHost: 127.0.0.1:9000\r\nUser-Agent: curl/8.21.0\r\nAccept: */*\r\n\r\n";
        let out = String::from_utf8(engine.apply_request_head(head)).unwrap();

        // Exactly one head/body separator and nothing after it.
        assert!(out.ends_with("\r\n\r\n"), "head must end with the terminator: {out:?}");
        let (head_part, body_part) = out.split_once("\r\n\r\n").unwrap();
        assert_eq!(body_part, "", "nothing may follow the header terminator: {body_part:?}");
        // The injected header is a real header line within the head, and the request line stays first.
        assert!(
            head_part.split("\r\n").any(|l| l == "X-DropSuite-Audit: true"),
            "injected header must be a header line: {head_part:?}"
        );
        assert!(head_part.starts_with("GET http://127.0.0.1:9000/cek HTTP/1.1\r\n"));
    }
}
