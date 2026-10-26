//! ClientHello shaping.
//!
//! Bot protection scores the TLS handshake, not just the HTTP request: the cipher list and the
//! key-exchange group order are the cheapest part of a JA3/JA4 signature to imitate. rustls fixes
//! the extension order, so this is shaping rather than full mimicry, but it removes the obvious
//! "this is not a browser" tells (rustls' own suite order, no browser-like curve preference).
//!
//! A profile is chosen together with the header preset so the User-Agent, client hints and
//! handshake agree on one browser.

use std::sync::Arc;

use rustls::crypto::ring;
use rustls::crypto::CryptoProvider;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsProfile {
    /// rustls defaults.
    #[default]
    Off,
    /// Chromium ordering; also used for Edge, which is Chromium.
    Chromium,
    Firefox,
    Safari,
}

impl TlsProfile {
    pub fn label(self) -> &'static str {
        match self {
            TlsProfile::Off => "rustls default",
            TlsProfile::Chromium => "Chromium",
            TlsProfile::Firefox => "Firefox",
            TlsProfile::Safari => "Safari",
        }
    }

    /// The profile that matches a header preset, so both legs stay consistent.
    pub fn for_preset(preset: crate::header_preset::BrowserPreset) -> Self {
        use crate::header_preset::BrowserPreset;
        match preset {
            BrowserPreset::Off => TlsProfile::Off,
            BrowserPreset::Chrome | BrowserPreset::Edge => TlsProfile::Chromium,
            BrowserPreset::Firefox => TlsProfile::Firefox,
            BrowserPreset::Safari => TlsProfile::Safari,
        }
    }
}

pub fn provider(profile: TlsProfile) -> Arc<CryptoProvider> {
    if profile == TlsProfile::Off {
        return Arc::new(ring::default_provider());
    }
    let mut base = ring::default_provider();

    // Browsers put AES-128 first; rustls prefers AES-256. Only reorder what rustls already
    // supports, so nothing new ever needs to be trusted.
    let tls13 = &rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
    let tls13_256 = &rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384;
    let tls13_chacha = &rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256;
    let wanted: Vec<rustls::SupportedCipherSuite> = match profile {
        TlsProfile::Chromium | TlsProfile::Safari => vec![*tls13, *tls13_256, *tls13_chacha],
        TlsProfile::Firefox => vec![*tls13, *tls13_chacha, *tls13_256],
        TlsProfile::Off => Vec::new(),
    };
    // Keep every TLS 1.2 suite the default provider had, after the reordered TLS 1.3 ones.
    let mut suites = wanted;
    suites.extend(
        base.cipher_suites
            .iter()
            .copied()
            .filter(|s| !matches!(s, rustls::SupportedCipherSuite::Tls13(_))),
    );
    if !suites.is_empty() {
        base.cipher_suites = suites;
    }

    // Curve preference: X25519 first, then the NIST curves in browser order.
    let groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup> = match profile {
        TlsProfile::Chromium | TlsProfile::Safari => vec![
            rustls::crypto::ring::kx_group::X25519,
            rustls::crypto::ring::kx_group::SECP256R1,
            rustls::crypto::ring::kx_group::SECP384R1,
        ],
        TlsProfile::Firefox => vec![
            rustls::crypto::ring::kx_group::X25519,
            rustls::crypto::ring::kx_group::SECP256R1,
            rustls::crypto::ring::kx_group::SECP384R1,
        ],
        TlsProfile::Off => Vec::new(),
    };
    if !groups.is_empty() {
        base.kx_groups = groups;
    }

    Arc::new(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header_preset::BrowserPreset;

    #[test]
    fn off_is_the_rustls_default() {
        let a = provider(TlsProfile::Off);
        let b = ring::default_provider();
        assert_eq!(a.cipher_suites.len(), b.cipher_suites.len());
        assert_eq!(a.cipher_suites[0].suite(), b.cipher_suites[0].suite());
    }

    #[test]
    fn chromium_starts_with_aes_128() {
        let p = provider(TlsProfile::Chromium);
        assert_eq!(
            p.cipher_suites[0].suite(),
            rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256.suite()
        );
        assert!(
            p.cipher_suites.len() > 3,
            "TLS 1.2 suites are kept for compatibility"
        );
    }

    #[test]
    fn firefox_prefers_chacha_before_aes_256() {
        let p = provider(TlsProfile::Firefox);
        assert_eq!(
            p.cipher_suites[1].suite(),
            rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256.suite()
        );
    }

    #[test]
    fn groups_are_browser_ordered_and_non_empty() {
        for profile in [
            TlsProfile::Chromium,
            TlsProfile::Firefox,
            TlsProfile::Safari,
        ] {
            let p = provider(profile);
            assert_eq!(p.kx_groups.len(), 3);
            assert_eq!(p.kx_groups[0].name(), rustls::NamedGroup::X25519);
        }
    }

    #[test]
    fn presets_map_to_matching_profiles() {
        assert_eq!(TlsProfile::for_preset(BrowserPreset::Off), TlsProfile::Off);
        assert_eq!(
            TlsProfile::for_preset(BrowserPreset::Chrome),
            TlsProfile::Chromium
        );
        assert_eq!(
            TlsProfile::for_preset(BrowserPreset::Edge),
            TlsProfile::Chromium
        );
        assert_eq!(
            TlsProfile::for_preset(BrowserPreset::Firefox),
            TlsProfile::Firefox
        );
        assert_eq!(
            TlsProfile::for_preset(BrowserPreset::Safari),
            TlsProfile::Safari
        );
    }
}
