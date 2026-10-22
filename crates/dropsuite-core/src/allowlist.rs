use serde::{Deserialize, Serialize};

/// A single allowlist entry: an exact hostname and optional port restriction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowEntry {
    pub host: String,
    /// `None` means any port; `Some(ports)` restricts to the listed ports.
    pub ports: Option<Vec<u16>>,
}

/// User-configurable list of hostnames (with optional port restrictions) for which
/// HTTPS interception is permitted. Non-allowlisted CONNECT targets receive a blind
/// tunnel (no decryption).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterceptAllowlist {
    entries: Vec<AllowEntry>,
}

impl Default for InterceptAllowlist {
    fn default() -> Self {
        Self::loopback_default()
    }
}

impl InterceptAllowlist {
    /// Default: loopback hosts only, any port.
    pub fn loopback_default() -> Self {
        InterceptAllowlist {
            entries: vec![
                AllowEntry { host: "localhost".into(), ports: None },
                AllowEntry { host: "127.0.0.1".into(), ports: None },
                AllowEntry { host: "::1".into(), ports: None },
            ],
        }
    }

    /// Parse a list of user-supplied strings like `"lumens.my.id"`, `"example.com:443"`,
    /// `"[::1]:8443"`. Rejects malformed entries.
    pub fn from_user_entries(raw: &[String]) -> Result<Self, String> {
        let mut entries = Vec::new();
        for s in raw {
            entries.push(parse_entry(s)?);
        }
        Ok(InterceptAllowlist { entries })
    }

    /// Serialize back to the user-facing string form.
    pub fn to_user_entries(&self) -> Vec<String> {
        self.entries.iter().map(|e| match &e.ports {
            None => e.host.clone(),
            Some(ports) if ports.is_empty() => e.host.clone(),
            Some(ports) => {
                let p: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
                format!("{}:{}", format_host(&e.host), p.join(","))
            }
        }).collect()
    }

    /// True when the given host and port are on the allowlist.
    pub fn allows(&self, host: &str, port: u16) -> bool {
        let norm = match normalize_host(host) {
            Some(h) => h,
            None => return false,
        };
        self.entries.iter().any(|e| {
            e.host == norm
                && match &e.ports {
                    None => true,
                    Some(ports) => ports.contains(&port),
                }
        })
    }

    pub fn entries(&self) -> &[AllowEntry] {
        &self.entries
    }
}

fn format_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// Normalize a hostname: lowercase, strip trailing dot, strip IPv6 brackets.
/// Returns `None` for empty or obviously malformed input.
pub fn normalize_host(host: &str) -> Option<String> {
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    // Reject wildcards, control characters, userinfo, and path delimiters
    if host.contains(['*', '?', '/', '@', ' ', '\t', '\r', '\n', '\0']) {
        return None;
    }
    // Strip IPv6 brackets
    let inner = if let Some(rest) = host.strip_prefix('[') {
        rest.strip_suffix(']').unwrap_or(rest)
    } else {
        host
    };
    // Strip trailing dot (DNS root)
    let inner = inner.strip_suffix('.').unwrap_or(inner);
    if inner.is_empty() || inner.len() > 253 {
        return None;
    }
    // If it is a valid IP address (IPv4 or IPv6):
    if let Ok(ip) = inner.parse::<std::net::IpAddr>() {
        return Some(ip.to_string());
    }
    if inner.contains(':') {
        return None;
    }
    // Validate DNS name format: labels 1..=63 chars, alphanumeric and hyphens, no leading/trailing hyphen
    let lower = inner.to_ascii_lowercase();
    for label in lower.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return None;
        }
    }
    Some(lower)
}

/// Parse a single user entry string.
fn parse_entry(s: &str) -> Result<AllowEntry, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("Empty entry.".into());
    }

    // Check for IPv6 with optional port: [::1] or [::1]:443
    if let Some(rest) = s.strip_prefix('[') {
        let (host_part, port_part) = if let Some(bracket_end) = rest.find(']') {
            let h = &rest[..bracket_end];
            let after = &rest[bracket_end + 1..];
            if let Some(ports) = after.strip_prefix(':') {
                (h, Some(ports))
            } else if after.is_empty() {
                (h, None)
            } else {
                return Err(format!("Invalid entry: {s}"));
            }
        } else {
            return Err(format!("Missing closing bracket in: {s}"));
        };
        let host = normalize_host(&format!("[{host_part}]"))
            .ok_or_else(|| format!("Invalid host in: {s}"))?;
        let ports = parse_ports(port_part, s)?;
        return Ok(AllowEntry { host, ports });
    }

    // A bare IPv6 literal (`::1`, as `to_user_entries` writes it) is a host with no port;
    // ports on IPv6 need the bracket form above.
    if let Ok(ip) = s.parse::<std::net::Ipv6Addr>() {
        return Ok(AllowEntry { host: ip.to_string(), ports: None });
    }

    // host or host:port(s)
    let (host_part, port_part) = if let Some(colon) = s.rfind(':') {
        // Check if this looks like host:port (digits after colon)
        let after = &s[colon + 1..];
        if after.chars().all(|c| c.is_ascii_digit() || c == ',') && !after.is_empty() {
            (&s[..colon], Some(after))
        } else {
            (s, None)
        }
    } else {
        (s, None)
    };

    let host = normalize_host(host_part)
        .ok_or_else(|| format!("Invalid host in: {s}"))?;
    let ports = parse_ports(port_part, s)?;
    Ok(AllowEntry { host, ports })
}

fn parse_ports(part: Option<&str>, ctx: &str) -> Result<Option<Vec<u16>>, String> {
    let Some(part) = part else { return Ok(None) };
    let mut ports = Vec::new();
    for piece in part.split(',') {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        let port: u16 = piece
            .parse()
            .map_err(|_| format!("Invalid port '{piece}' in: {ctx}"))?;
        if port == 0 {
            return Err(format!("Port 0 is not allowed in: {ctx}"));
        }
        ports.push(port);
    }
    if ports.is_empty() {
        Ok(None)
    } else {
        ports.sort_unstable();
        ports.dedup();
        Ok(Some(ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_hosts() {
        assert_eq!(normalize_host("Example.COM."), Some("example.com".into()));
        assert_eq!(normalize_host("[::1]"), Some("::1".into()));
        assert_eq!(normalize_host("localhost"), Some("localhost".into()));
        assert_eq!(normalize_host(""), None);
        assert_eq!(normalize_host("a@b.com"), None);
        assert_eq!(normalize_host("*.example.com"), None);
        assert_eq!(normalize_host("example..com"), None);
        assert_eq!(normalize_host("-bad.com"), None);
        assert_eq!(normalize_host("bad-.com"), None);
    }

    #[test]
    fn parse_entries() {
        let e = parse_entry("lumens.my.id").unwrap();
        assert_eq!(e.host, "lumens.my.id");
        assert_eq!(e.ports, None);

        let e = parse_entry("example.com:443").unwrap();
        assert_eq!(e.host, "example.com");
        assert_eq!(e.ports, Some(vec![443]));

        let e = parse_entry("[::1]:8443").unwrap();
        assert_eq!(e.host, "::1");
        assert_eq!(e.ports, Some(vec![8443]));

        let e = parse_entry("localhost:443,8443").unwrap();
        assert_eq!(e.ports, Some(vec![443, 8443]));

        assert!(parse_entry("").is_err());
        assert!(parse_entry("[::1").is_err());
        assert!(parse_entry("host:0").is_err());
    }

    #[test]
    fn allowlist_matching() {
        let al = InterceptAllowlist::from_user_entries(&[
            "localhost".into(),
            "lumens.my.id:443".into(),
            "[::1]:8443".into(),
        ]).unwrap();
        assert!(al.allows("localhost", 80));
        assert!(al.allows("localhost", 443));
        assert!(al.allows("lumens.my.id", 443));
        assert!(!al.allows("lumens.my.id", 80));
        assert!(al.allows("::1", 8443));
        assert!(!al.allows("::1", 443));
        assert!(!al.allows("google.com", 443));
    }

    #[test]
    fn loopback_default_allows_local() {
        let al = InterceptAllowlist::loopback_default();
        assert!(al.allows("localhost", 443));
        assert!(al.allows("127.0.0.1", 8443));
        assert!(al.allows("::1", 443));
        assert!(!al.allows("example.com", 443));
    }

    #[test]
    fn bare_ipv6_entries_round_trip() {
        // The default list renders `::1` without brackets (as the settings panel shows it);
        // saving that text back must give the same list, not an error.
        let al = InterceptAllowlist::loopback_default();
        assert_eq!(al.to_user_entries(), vec!["localhost", "127.0.0.1", "::1"]);
        assert_eq!(InterceptAllowlist::from_user_entries(&al.to_user_entries()).unwrap(), al);
        let e = parse_entry("fe80::1").unwrap();
        assert_eq!((e.host.as_str(), e.ports), ("fe80::1", None));
        // Ports on IPv6 still need brackets; host:port for names is unchanged.
        assert_eq!(parse_entry("[::1]:8443").unwrap().ports, Some(vec![8443]));
        assert_eq!(parse_entry("example.com:443").unwrap().ports, Some(vec![443]));
    }

    #[test]
    fn round_trip() {
        let al = InterceptAllowlist::from_user_entries(&[
            "localhost".into(),
            "example.com:443".into(),
        ]).unwrap();
        let entries = al.to_user_entries();
        let al2 = InterceptAllowlist::from_user_entries(&entries).unwrap();
        assert_eq!(al, al2);
    }
}
