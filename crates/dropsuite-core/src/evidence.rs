//! Detailed byte-level evidence and reproducibility tracking for active scan findings.

use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InsertionKind {
    Query,
    Body,
    Header,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Insertion {
    pub kind: InsertionKind,
    pub name: String,
    pub original_value: String,
    pub payload: String,
    pub offset: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HttpPair {
    /// Full HTTP request bytes, suitable for pasting into Repeater.
    pub raw_request: Vec<u8>,
    /// Full HTTP response bytes.
    pub raw_response: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    pub timing_ms: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BodyDiff {
    pub baseline_len: usize,
    pub exploit_len: usize,
    pub common_prefix: usize,
    pub common_suffix: usize,
    /// Base64-encoded bytes of the differing region.
    pub diff_region_b64: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Repro {
    pub attempts: u8,
    pub confirmed: u8,
}

impl Repro {
    pub fn is_confirmed(&self) -> bool {
        self.confirmed >= 2
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub baseline: HttpPair,
    pub exploit: HttpPair,
    pub diff: BodyDiff,
    pub insertions: Vec<Insertion>,
    pub reproducibility: Repro,
}

/// Compute byte-level diff between baseline response body and exploit response body.
pub fn compute_body_diff(baseline: &[u8], exploit: &[u8]) -> BodyDiff {
    let mut common_prefix = 0;
    while common_prefix < baseline.len()
        && common_prefix < exploit.len()
        && baseline[common_prefix] == exploit[common_prefix]
    {
        common_prefix += 1;
    }

    let mut common_suffix = 0;
    while common_suffix < (baseline.len() - common_prefix)
        && common_suffix < (exploit.len() - common_prefix)
        && baseline[baseline.len() - 1 - common_suffix]
            == exploit[exploit.len() - 1 - common_suffix]
    {
        common_suffix += 1;
    }

    let diff_slice = if common_prefix + common_suffix <= exploit.len() {
        &exploit[common_prefix..exploit.len() - common_suffix]
    } else {
        &[]
    };

    let diff_region_b64 = base64::engine::general_purpose::STANDARD.encode(diff_slice);

    BodyDiff {
        baseline_len: baseline.len(),
        exploit_len: exploit.len(),
        common_prefix,
        common_suffix,
        diff_region_b64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_diff_detects_common_boundaries() {
        let base = b"<html>hello user world</html>";
        let exploit = b"<html>hello <script>alert(1)</script> world</html>";
        let diff = compute_body_diff(base, exploit);

        assert_eq!(diff.baseline_len, base.len());
        assert_eq!(diff.exploit_len, exploit.len());
        assert_eq!(diff.common_prefix, 12); // "<html>hello "
        assert_eq!(diff.common_suffix, 13); // " world</html>"

        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&diff.diff_region_b64)
            .unwrap();
        assert_eq!(decoded, b"<script>alert(1)</script>");
    }

    #[test]
    fn compute_diff_identical_bodies() {
        let base = b"unchanged body";
        let diff = compute_body_diff(base, base);
        assert_eq!(diff.common_prefix, base.len());
        assert_eq!(diff.common_suffix, 0);
        assert_eq!(diff.diff_region_b64, "");
    }
}
