//! Browser header presets for Replay and Intruder.
//!
//! Bot protection scores a request partly on whether its headers look like a real browser.
//! A preset supplies one complete, internally consistent header set (User-Agent, client hints
//! and fetch metadata all agreeing on the same browser and platform), so a request does not
//! arrive as a half-filled imitation.
//!
//! A preset only fills headers the user has not set. Anything typed explicitly always wins, and
//! the caller-owned fields (`Host`, `Cookie`, `Content-Length`, `Content-Type`) are never touched.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserPreset {
    /// Send exactly what the editor holds.
    #[default]
    Off,
    /// Chromium's client hints and fetch metadata with a Chrome User-Agent.
    Chrome,
    /// The same Chromium profile with an Edge User-Agent and brand list.
    Edge,
    /// Firefox sends no client hints, so only the Firefox-specific fields are supplied.
    Firefox,
    /// Safari sends only fetch metadata and a Safari User-Agent.
    Safari,
}

impl BrowserPreset {
    pub fn label(self) -> &'static str {
        match self {
            BrowserPreset::Off => "Off",
            BrowserPreset::Chrome => "Chrome",
            BrowserPreset::Edge => "Edge",
            BrowserPreset::Firefox => "Firefox",
            BrowserPreset::Safari => "Safari",
        }
    }

    fn user_agent(self) -> &'static str {
        match self {
            BrowserPreset::Off => "",
            BrowserPreset::Chrome => {
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            }
            BrowserPreset::Edge => {
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
            }
            BrowserPreset::Firefox => {
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
            }
            BrowserPreset::Safari => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15"
            }
        }
    }

    fn client_hints(self) -> Option<&'static [(&'static str, &'static str)]> {
        match self {
            BrowserPreset::Chrome => Some(&[
                (
                    "sec-ch-ua",
                    "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
                ),
                ("sec-ch-ua-mobile", "?0"),
                ("sec-ch-ua-platform", "\"Windows\""),
            ]),
            BrowserPreset::Edge => Some(&[
                (
                    "sec-ch-ua",
                    "\"Microsoft Edge\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
                ),
                ("sec-ch-ua-mobile", "?0"),
                ("sec-ch-ua-platform", "\"Windows\""),
            ]),
            _ => None,
        }
    }

    fn accept_encoding(self) -> &'static str {
        match self {
            BrowserPreset::Firefox => "gzip, deflate, br, zstd",
            BrowserPreset::Safari => "gzip, deflate, br",
            _ => "gzip, deflate, br, zstd",
        }
    }

    fn language(self) -> &'static str {
        match self {
            BrowserPreset::Firefox => "en-US,en;q=0.5",
            _ => "en-US,en;q=0.9",
        }
    }

    fn accept(self) -> &'static str {
        match self {
            BrowserPreset::Chrome | BrowserPreset::Edge => concat!(
                "text/html,application/xhtml+xml,application/xml;q=0.9,",
                "image/avif,image/webp,image/apng,*/*;q=0.8,",
                "application/signed-exchange;v=b3;q=0.7"
            ),
            _ => "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
    }
}

/// Names the preset never supplies, because the caller owns them.
const CALLER_OWNED: &[&str] = &["host", "cookie", "content-length", "content-type"];

/// The preset's fields, in the order a browser emits them.
fn fields(preset: BrowserPreset) -> Vec<(&'static str, &'static str)> {
    if preset == BrowserPreset::Off {
        return Vec::new();
    }
    let mut out: Vec<(&'static str, &'static str)> = Vec::new();
    if let Some(hints) = preset.client_hints() {
        out.extend_from_slice(hints);
    }
    out.push(("sec-fetch-site", "none"));
    out.push(("sec-fetch-mode", "navigate"));
    out.push(("sec-fetch-user", "?1"));
    out.push(("sec-fetch-dest", "document"));
    out.push(("upgrade-insecure-requests", "1"));
    out.push(("user-agent", preset.user_agent()));
    out.push(("accept", preset.accept()));
    out.push(("accept-language", preset.language()));
    out.push(("accept-encoding", preset.accept_encoding()));
    out
}

/// Preset headers to insert, skipping names the request already carries. The returned names are
/// lowercased and in emission order; values are already correct for the preset.
pub fn fill(preset: BrowserPreset, present: &[(String, String)]) -> Vec<(&'static str, &'static str)> {
    fields(preset)
        .into_iter()
        .filter(|(name, _)| {
            !CALLER_OWNED.contains(name) && !present.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(list: &[(String, String)], name: &str) -> bool {
        list.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
    }

    fn present(names: &[&str]) -> Vec<(String, String)> {
        names
            .iter()
            .map(|n| (n.to_string(), "given".to_string()))
            .collect()
    }

    #[test]
    fn off_supplies_nothing() {
        assert!(fill(BrowserPreset::Off, &[]).is_empty());
    }

    #[test]
    fn chrome_is_complete_and_self_consistent() {
        let filled = fill(BrowserPreset::Chrome, &[]);
        let names: Vec<&str> = filled.iter().map(|(n, _)| *n).collect();
        for expected in [
            "user-agent",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "sec-fetch-site",
            "sec-fetch-dest",
            "accept",
            "accept-language",
            "accept-encoding",
        ] {
            assert!(names.contains(&expected), "missing {expected}: {names:?}");
        }
        let ua = filled.iter().find(|(n, _)| *n == "user-agent").unwrap().1;
        assert!(ua.contains("Chrome/131"));
        assert!(!ua.contains("Edg/"));
        assert!(names.iter().position(|n| *n == "user-agent") < names.iter().position(|n| *n == "accept"));
    }

    #[test]
    fn edge_does_not_impersonate_chrome() {
        let filled = fill(BrowserPreset::Edge, &[]);
        let ua = filled.iter().find(|(n, _)| *n == "user-agent").unwrap().1;
        let hints = filled.iter().find(|(n, _)| *n == "sec-ch-ua").unwrap().1;
        assert!(ua.contains("Edg/131"));
        assert!(ua.contains("Chrome/131"), "Edge UA still names its Chromium base");
        assert!(hints.contains("Microsoft Edge"));
    }

    #[test]
    fn firefox_and_safari_send_no_client_hints() {
        for preset in [BrowserPreset::Firefox, BrowserPreset::Safari] {
            let names: Vec<&str> = fill(preset, &[]).iter().map(|(n, _)| *n).collect();
            assert!(!names.contains(&"sec-ch-ua"), "{preset:?}");
            assert!(names.contains(&"sec-fetch-site"), "{preset:?}");
        }
        let ff = fill(BrowserPreset::Firefox, &[]);
        assert!(ff.iter().any(|(n, v)| *n == "user-agent" && v.contains("Firefox/133")));
        let sf = fill(BrowserPreset::Safari, &[]);
        assert!(sf.iter().any(|(n, v)| *n == "user-agent" && v.contains("Version/18.1")));
    }

    #[test]
    fn explicit_headers_win_and_caller_fields_are_skipped() {
        let given = present(&["User-Agent", "Accept", "Host", "Cookie", "Content-Length", "Content-Type"]);
        let names: Vec<&str> = fill(BrowserPreset::Chrome, &given).iter().map(|(n, _)| *n).collect();
        for absent in ["user-agent", "accept", "host", "cookie", "content-length", "content-type"] {
            assert!(!names.contains(&absent), "{absent} must not be filled");
        }
        assert!(names.contains(&"accept-language"), "unset fields still filled");
    }

    #[test]
    fn values_are_header_safe() {
        for preset in [BrowserPreset::Chrome, BrowserPreset::Edge, BrowserPreset::Firefox, BrowserPreset::Safari] {
            for (_, value) in fill(preset, &[]) {
                assert!(!value.bytes().any(|b| (b < b' ' && b != b'\t') || b == 0x7f), "{preset:?}");
            }
        }
        assert!(has(&present(&["User-Agent"]), "user-agent"));
    }
}
