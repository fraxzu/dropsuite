use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeRuleType {
    Include,
    Exclude,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeRule {
    pub id: String,
    pub enabled: bool,
    pub rule_type: ScopeRuleType,
    pub protocol: Option<String>, // "http", "https", or None (any)
    pub host: String,             // e.g. "api.target.com", "*.target.com", or regex
    pub port: Option<u16>,
    pub path_prefix: Option<String>, // e.g. "/api"
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScopeConfig {
    pub enabled: bool,
    pub drop_out_of_scope: bool,
    pub rules: Vec<ScopeRule>,
}

#[derive(Default)]
pub struct ScopeEngine {
    config: RwLock<ScopeConfig>,
}

impl ScopeEngine {
    pub fn new() -> Self {
        Self {
            config: RwLock::new(ScopeConfig::default()),
        }
    }

    pub fn with_config(config: ScopeConfig) -> Self {
        Self {
            config: RwLock::new(config),
        }
    }

    pub fn get_config(&self) -> ScopeConfig {
        self.config.read().unwrap().clone()
    }

    pub fn set_config(&self, config: ScopeConfig) {
        *self.config.write().unwrap() = config;
    }

    /// Check if target URL is within the configured scope.
    pub fn is_in_scope(&self, url_str: &str) -> bool {
        let cfg = self.config.read().unwrap();
        if !cfg.enabled || cfg.rules.is_empty() {
            return true;
        }

        let parsed = parse_url_components(url_str);
        let enabled_rules: Vec<&ScopeRule> = cfg.rules.iter().filter(|r| r.enabled).collect();
        if enabled_rules.is_empty() {
            return true;
        }

        // 1. Check if matches any Exclude rule -> immediately out of scope
        for r in enabled_rules
            .iter()
            .filter(|r| r.rule_type == ScopeRuleType::Exclude)
        {
            if matches_rule(r, &parsed) {
                return false;
            }
        }

        // 2. Check Include rules
        let include_rules: Vec<&&ScopeRule> = enabled_rules
            .iter()
            .filter(|r| r.rule_type == ScopeRuleType::Include)
            .collect();

        if include_rules.is_empty() {
            // Only Exclude rules were specified, and none matched -> in scope
            return true;
        }

        for r in include_rules {
            if matches_rule(r, &parsed) {
                return true;
            }
        }

        false
    }

    /// Whether out-of-scope requests should be dropped at proxy boundary.
    pub fn should_drop_out_of_scope(&self, url_str: &str) -> bool {
        let cfg = self.config.read().unwrap();
        cfg.enabled && cfg.drop_out_of_scope && !self.is_in_scope(url_str)
    }
}

struct UrlComponents<'a> {
    scheme: Option<&'a str>,
    host: &'a str,
    port: u16,
    path: &'a str,
}

fn parse_url_components(url_str: &str) -> UrlComponents<'_> {
    let lower = url_str.to_ascii_lowercase();
    let (scheme, rest) = if lower.starts_with("https://") {
        (Some("https"), &url_str[8..])
    } else if lower.starts_with("http://") {
        (Some("http"), &url_str[7..])
    } else {
        (None, url_str)
    };

    let authority = rest.find(['/', '?', '#']).map_or(rest, |i| &rest[..i]);
    let path = rest.find(['/', '?', '#']).map_or("/", |i| &rest[i..]);

    let (host, port) = if let Some(idx) = authority.rfind(':') {
        let h = &authority[..idx];
        let p = authority[idx + 1..].parse::<u16>().unwrap_or_else(|_| {
            if scheme == Some("https") {
                443
            } else {
                80
            }
        });
        (h, p)
    } else {
        let default_port = if scheme == Some("https") { 443 } else { 80 };
        (authority, default_port)
    };

    UrlComponents {
        scheme,
        host,
        port,
        path,
    }
}

fn matches_rule(rule: &ScopeRule, target: &UrlComponents<'_>) -> bool {
    // Protocol match
    if let Some(ref proto) = rule.protocol {
        if let Some(target_proto) = target.scheme {
            if !proto.eq_ignore_ascii_case(target_proto) {
                return false;
            }
        }
    }

    // Port match
    if let Some(port) = rule.port {
        if port != target.port {
            return false;
        }
    }

    // Path prefix match
    if let Some(ref prefix) = rule.path_prefix {
        if !target.path.starts_with(prefix) {
            return false;
        }
    }

    // Host match: supports exact match, wildcard prefix (*.domain.com), or regex
    matches_host(&rule.host, target.host)
}

fn matches_host(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() || pattern == "*" {
        return true;
    }

    let p_lower = pattern.to_ascii_lowercase();
    let h_lower = host.to_ascii_lowercase();

    if p_lower == h_lower {
        return true;
    }

    // Wildcard prefix like *.target.com
    if let Some(domain) = p_lower.strip_prefix("*.") {
        if h_lower == domain || h_lower.ends_with(&format!(".{domain}")) {
            return true;
        }
    }

    // Regex match if special regex characters present
    if pattern.starts_with('^') || pattern.contains(['(', '[', '|', '+', '\\']) {
        if let Ok(re) = Regex::new(&format!("(?i){}", pattern)) {
            return re.is_match(host);
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_default_allows_all() {
        let scope = ScopeEngine::new();
        assert!(scope.is_in_scope("https://example.com/api/v1"));
        assert!(scope.is_in_scope("http://test.local/health"));
    }

    #[test]
    fn test_scope_include_and_exclude_rules() {
        let config = ScopeConfig {
            enabled: true,
            drop_out_of_scope: false,
            rules: vec![
                ScopeRule {
                    id: "1".into(),
                    enabled: true,
                    rule_type: ScopeRuleType::Include,
                    protocol: Some("https".into()),
                    host: "*.target.com".into(),
                    port: Some(443),
                    path_prefix: Some("/api".into()),
                },
                ScopeRule {
                    id: "2".into(),
                    enabled: true,
                    rule_type: ScopeRuleType::Exclude,
                    protocol: None,
                    host: "admin.target.com".into(),
                    port: None,
                    path_prefix: None,
                },
            ],
        };

        let scope = ScopeEngine::with_config(config);

        // Within include rule
        assert!(scope.is_in_scope("https://api.target.com/api/users"));
        assert!(scope.is_in_scope("https://target.com/api/v1/login"));

        // Wrong path -> out of scope
        assert!(!scope.is_in_scope("https://api.target.com/static/logo.png"));

        // Wrong scheme (http instead of https) -> out of scope
        assert!(!scope.is_in_scope("http://api.target.com/api/users"));

        // Excluded host -> out of scope even with matching path
        assert!(!scope.is_in_scope("https://admin.target.com/api/dashboard"));

        // Unrelated host -> out of scope
        assert!(!scope.is_in_scope("https://google.com/search"));
    }
}
