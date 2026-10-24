//! Destination policy on every proxy entry point: ordinary HTTP (absolute-form, origin-form
//! with Host, absolute https:// over the plain listener) and CONNECT (blind tunnel and
//! interception). A restricted destination must be refused before any outbound connection is
//! attempted, whether it is a literal or a hostname that resolves to one, and the interception
//! allowlist must not override that. Names resolve through an injected resolver, and a connect
//! gate refuses every non-loopback socket, so no test needs DNS and none can reach the network
//! even if the policy regresses.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dropsuite_core::allowlist::InterceptAllowlist;
use dropsuite_core::https::HttpsInterceptConfig;
use dropsuite_core::models::HistoryFilter;
use dropsuite_core::proxy::{canonical_ip, is_own_listener, is_restricted_destination};
use dropsuite_core::{ProxyEngine, StorageManager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const METADATA: IpAddr = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const ALIBABA_METADATA: IpAddr = IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200));
const AWS_METADATA_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254));
// RFC 6052 well-known NAT64 prefix 64:ff9b::/96 with the IPv4 address in the low 32 bits.
const NAT64_METADATA: IpAddr = IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0xa9fe, 0xa9fe));
const NAT64_ALIBABA: IpAddr = IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x6464, 0x64c8));
const NAT64_PUBLIC: IpAddr = IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x0808, 0x0808));

/// Restricted literals as they appear in a URL authority, one per documented class.
const RESTRICTED_LITERALS: &[&str] = &[
    "169.254.169.254",          // cloud metadata (IPv4 link-local)
    "169.254.0.1",              // rest of 169.254.0.0/16
    "[::ffff:169.254.169.254]", // IPv4-mapped IPv6 form of the metadata address
    "[fe80::1]",                // IPv6 link-local
    "[febf::1]",                // top of fe80::/10
    "0.0.0.0",                  // unspecified
    "[::]",                     // unspecified (IPv6)
    "224.0.0.1",                // multicast
    "[ff02::1]",                // multicast (IPv6)
    "100.100.100.200",          // Alibaba Cloud metadata
    "[::ffff:100.100.100.200]", // IPv4-mapped form of it
    "[fd00:ec2::254]",          // AWS EC2 metadata over IPv6
    "[64:ff9b::a9fe:a9fe]",     // NAT64 well-known prefix + 169.254.169.254
    "[64:ff9b::6464:64c8]",     // NAT64 well-known prefix + 100.100.100.200
];

/// Hostnames the injected resolver maps onto restricted addresses.
const RESTRICTED_NAMES: &[&str] = &[
    "metadata.test",
    "ll6.test",
    "mapped.test",
    "mixed.test",
    "alibaba-meta.test",
    "aws-meta6.test",
    "mixed-alibaba.test",
    "mixed-aws6.test",
    "nat64-meta.test",
    "nat64-alibaba.test",
];

fn resolver_table() -> HashMap<&'static str, Vec<IpAddr>> {
    HashMap::from([
        ("metadata.test", vec![METADATA]),
        (
            "ll6.test",
            vec![IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))],
        ),
        (
            "mapped.test",
            vec![IpAddr::V6(
                Ipv4Addr::new(169, 254, 169, 254).to_ipv6_mapped(),
            )],
        ),
        // A reachable, permitted address first must not let the restricted one slip through.
        ("mixed.test", vec![LOCAL, METADATA]),
        ("alibaba-meta.test", vec![ALIBABA_METADATA]),
        ("aws-meta6.test", vec![AWS_METADATA_V6]),
        // Loopback first, on a port with no listener: its connect would fail and fall through
        // to the next address, so every answer must be checked before the first connect.
        ("mixed-alibaba.test", vec![LOCAL, ALIBABA_METADATA]),
        (
            "mixed-aws6.test",
            vec![IpAddr::V6(Ipv6Addr::LOCALHOST), AWS_METADATA_V6],
        ),
        ("allowed.test", vec![LOCAL]),
        ("nat64-meta.test", vec![NAT64_METADATA]),
        ("nat64-alibaba.test", vec![NAT64_ALIBABA]),
        ("nat64-public.test", vec![NAT64_PUBLIC]),
    ])
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "dropsuite-dest-{tag}-{:x}{t:x}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A proxy with the injected resolver. `intercept` = None runs without HTTPS interception;
/// Some(list) enables it with that allowlist.
async fn start_proxy(tag: &str, intercept: Option<&[&str]>) -> (ProxyEngine, StorageManager, u16) {
    start_proxy_on("127.0.0.1", tag, intercept).await
}

async fn start_proxy_on(
    bind: &str,
    tag: &str,
    intercept: Option<&[&str]>,
) -> (ProxyEngine, StorageManager, u16) {
    let dir = temp_dir(tag);
    let storage = StorageManager::new(dir.join("test.db")).unwrap();
    let mut proxy = ProxyEngine::new(bind, 0, storage.clone());
    if let Some(entries) = intercept {
        let allowlist = InterceptAllowlist::from_user_entries(
            &entries.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        proxy.set_https_interception(HttpsInterceptConfig {
            ca_dir: dir.join("ca"),
            allowlist,
            upstream_roots: vec![],
        });
    }
    let table = resolver_table();
    proxy.set_resolver_override(Arc::new(move |host: &str| table.get(host).cloned()));
    // Mock connector: any attempt is still counted, but only loopback sockets are ever opened.
    proxy.set_connect_gate(Arc::new(|targets: &[SocketAddr]| {
        targets.iter().all(|t| t.ip().is_loopback())
    }));
    proxy.start().await.unwrap();
    let port = proxy.port();
    (proxy, storage, port)
}

/// Allowlist naming every restricted literal and name, to prove it cannot override the policy.
fn allowlist_with_restricted() -> Vec<&'static str> {
    let mut list = vec!["localhost", "allowed.test"];
    list.extend(RESTRICTED_NAMES);
    // Allowlist entries take IPv6 in brackets, the same form as the literals.
    list.extend(RESTRICTED_LITERALS);
    list
}

async fn send(proxy_port: u16, raw: &str) -> String {
    send_to(SocketAddr::from((LOCAL, proxy_port)), raw).await
}

async fn send_to(proxy: SocketAddr, raw: &str) -> String {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(raw.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out))
        .await
        .expect("proxy answered and closed within 5 s")
        .unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

fn stored(storage: &StorageManager) -> usize {
    storage
        .list_summaries(&HistoryFilter::default())
        .unwrap()
        .len()
}

/// The refusal must be a 403 with no tunnel, nothing captured, and no outbound connect.
fn assert_refused(resp: &str, proxy: &ProxyEngine, storage: &StorageManager, what: &str) {
    assert!(
        resp.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "{what}: expected 403, got: {resp}"
    );
    assert!(
        resp.contains("prohibited"),
        "{what}: expected the policy reason, got: {resp}"
    );
    assert!(
        !resp.contains("200 Connection Established"),
        "{what}: no tunnel may be established, got: {resp}"
    );
    assert_eq!(
        proxy.outbound_connect_attempts(),
        0,
        "{what}: the outbound connector must never be invoked"
    );
    assert_eq!(stored(storage), 0, "{what}: refusals are not captured");
}

/// Minimal origin: one fixed 200 response per connection.
async fn start_origin() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\norigin",
                    )
                    .await;
                let _ = sock.shutdown().await;
            });
        }
    });
    port
}

#[tokio::test]
async fn http_absolute_form_to_metadata_ip_is_refused_before_connect() {
    // With and without HTTPS interception configured: the plain-HTTP path must not depend on it.
    for (tag, intercept) in [
        ("abs-plain", None),
        ("abs-intercept", Some(&["localhost"][..])),
    ] {
        let (proxy, storage, port) = start_proxy(tag, intercept).await;
        let resp = send(
            port,
            "GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n",
        )
        .await;
        assert_refused(&resp, &proxy, &storage, tag);
        assert!(resp.contains("link-local and cloud metadata addresses are strictly prohibited"));
    }
}

#[tokio::test]
async fn http_restricted_address_classes_are_refused_before_connect() {
    let (proxy, storage, port) = start_proxy("http-classes", None).await;
    for lit in RESTRICTED_LITERALS {
        let absolute =
            format!("GET http://{lit}/latest/meta-data/ HTTP/1.1\r\nHost: {lit}\r\n\r\n");
        assert_refused(
            &send(port, &absolute).await,
            &proxy,
            &storage,
            &format!("absolute {lit}"),
        );

        let origin = format!("GET /latest/meta-data/ HTTP/1.1\r\nHost: {lit}\r\n\r\n");
        assert_refused(
            &send(port, &origin).await,
            &proxy,
            &storage,
            &format!("origin-form {lit}"),
        );
    }
}

#[tokio::test]
async fn connect_restricted_address_classes_are_refused_before_tunnel() {
    let allow_all = allowlist_with_restricted();
    // Not allowlisted -> would be a blind tunnel; allowlisted -> would be intercepted.
    for (tag, allow) in [
        ("connect-blind", &["localhost"][..]),
        ("connect-allow", &allow_all[..]),
    ] {
        let (proxy, storage, port) = start_proxy(tag, Some(allow)).await;
        for lit in RESTRICTED_LITERALS {
            let req = format!("CONNECT {lit}:443 HTTP/1.1\r\nHost: {lit}:443\r\n\r\n");
            assert_refused(
                &send(port, &req).await,
                &proxy,
                &storage,
                &format!("{tag} {lit}"),
            );
        }
    }
}

#[tokio::test]
async fn hostname_resolving_to_restricted_address_is_refused_on_every_path() {
    let allow_all = allowlist_with_restricted();
    for (tag, allow) in [
        ("name-blind", &["localhost"][..]),
        ("name-allow", &allow_all[..]),
    ] {
        let (proxy, storage, port) = start_proxy(tag, Some(allow)).await;
        for name in RESTRICTED_NAMES {
            let cases = [
                format!("GET http://{name}/latest/meta-data/ HTTP/1.1\r\nHost: {name}\r\n\r\n"),
                format!("GET /latest/meta-data/ HTTP/1.1\r\nHost: {name}\r\n\r\n"),
                format!("CONNECT {name}:443 HTTP/1.1\r\nHost: {name}:443\r\n\r\n"),
            ];
            for req in &cases {
                let what = format!("{tag} {}", req.lines().next().unwrap());
                assert_refused(&send(port, req).await, &proxy, &storage, &what);
            }
        }
    }
}

#[tokio::test]
async fn interception_allowlist_does_not_override_policy_for_absolute_https_form() {
    // `GET https://...` sent to the plain listener is checked against the allowlist first;
    // being allowlisted must still not reach a restricted address.
    let allow_all = allowlist_with_restricted();
    let (proxy, storage, port) = start_proxy("abs-https", Some(&allow_all)).await;
    let targets = RESTRICTED_LITERALS.iter().chain(RESTRICTED_NAMES);
    for host in targets {
        let req = format!("GET https://{host}/latest/meta-data/ HTTP/1.1\r\nHost: {host}\r\n\r\n");
        assert_refused(
            &send(port, &req).await,
            &proxy,
            &storage,
            &format!("https:// {host}"),
        );
    }
}

#[tokio::test]
async fn http_to_smtp_port_is_refused_like_connect() {
    // CONNECT refuses port 25; the plain-HTTP path must apply the same rule. Local targets only.
    let (proxy, storage, port) = start_proxy("smtp", None).await;
    for req in [
        "GET http://127.0.0.1:25/ HTTP/1.1\r\nHost: 127.0.0.1:25\r\n\r\n",
        "POST http://allowed.test:25/ HTTP/1.1\r\nHost: allowed.test:25\r\nContent-Length: 0\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: allowed.test:25\r\n\r\n",
    ] {
        let resp = send(port, req).await;
        let what = req.lines().next().unwrap();
        assert!(resp.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{what}: got: {resp}");
        assert!(resp.contains("port 25 (SMTP) is prohibited"), "{what}: got: {resp}");
        assert_eq!(proxy.outbound_connect_attempts(), 0, "{what}: connector never invoked");
        assert_eq!(stored(&storage), 0, "{what}: refusals are not captured");
    }
}

#[tokio::test]
async fn permitted_http_forwarding_still_connects_once_per_request() {
    // Positive control: proves the connector counter is live, so the zero-count assertions above
    // are meaningful, and that permitted forwarding (literal and resolved name) still works.
    let origin = start_origin().await;
    let (proxy, storage, port) = start_proxy("permitted", Some(&["localhost"][..])).await;

    let cases = [
        format!("GET http://127.0.0.1:{origin}/ok HTTP/1.1\r\nHost: 127.0.0.1:{origin}\r\nConnection: close\r\n\r\n"),
        format!("GET http://allowed.test:{origin}/ok HTTP/1.1\r\nHost: allowed.test:{origin}\r\nConnection: close\r\n\r\n"),
        format!("GET /ok HTTP/1.1\r\nHost: allowed.test:{origin}\r\nConnection: close\r\n\r\n"),
    ];
    for (i, req) in cases.iter().enumerate() {
        let resp = send(port, req).await;
        assert!(
            resp.starts_with("HTTP/1.1 200 OK\r\n"),
            "case {i}: got: {resp}"
        );
        assert!(resp.ends_with("origin"), "case {i}: got: {resp}");
        assert_eq!(
            proxy.outbound_connect_attempts(),
            i + 1,
            "case {i}: one connect per request"
        );
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(stored(&storage), cases.len());
}

#[tokio::test]
async fn additional_cloud_metadata_endpoints_are_refused_on_every_path() {
    // The matrix tests above already include these addresses; this one pins the reason, so the
    // refusal is known to come from the metadata rule and not from some other check.
    let allow_all = allowlist_with_restricted();
    for (tag, allow) in [
        ("meta-blind", &["localhost"][..]),
        ("meta-allow", &allow_all[..]),
    ] {
        let (proxy, storage, port) = start_proxy(tag, Some(allow)).await;
        for host in [
            "100.100.100.200",
            "[fd00:ec2::254]",
            "alibaba-meta.test",
            "aws-meta6.test",
            "mixed-alibaba.test",
            "mixed-aws6.test",
            "[64:ff9b::a9fe:a9fe]",
            "[64:ff9b::6464:64c8]",
            "nat64-meta.test",
            "nat64-alibaba.test",
        ] {
            let cases = [
                format!("GET http://{host}/latest/meta-data/ HTTP/1.1\r\nHost: {host}\r\n\r\n"),
                format!("GET /latest/meta-data/ HTTP/1.1\r\nHost: {host}\r\n\r\n"),
                format!("GET https://{host}/latest/meta-data/ HTTP/1.1\r\nHost: {host}\r\n\r\n"),
                format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n"),
            ];
            for req in &cases {
                let line = req.lines().next().unwrap();
                // Absolute https:// to a host that is not allowlisted stops at the allowlist
                // (501) before resolution; that path is covered by the allowlisted run.
                if tag == "meta-blind" && line.starts_with("GET https://") {
                    continue;
                }
                let what = format!("{tag} {line}");
                let resp = send(port, req).await;
                assert_refused(&resp, &proxy, &storage, &what);
                assert!(
                    resp.contains("cloud metadata addresses are strictly prohibited"),
                    "{what}: expected the metadata reason, got: {resp}"
                );
            }
        }
    }
}

#[test]
fn metadata_rule_is_exact_and_keeps_existing_classes() {
    let at = |ip: IpAddr| SocketAddr::new(ip, 80);
    let blocked: [IpAddr; 10] = [
        ALIBABA_METADATA,
        AWS_METADATA_V6,
        IpAddr::V6(Ipv4Addr::new(100, 100, 100, 200).to_ipv6_mapped()),
        METADATA,
        "169.254.1.1".parse().unwrap(),
        "fe80::1".parse().unwrap(),
        "::".parse().unwrap(),
        "0.0.0.0".parse().unwrap(),
        "224.0.0.1".parse().unwrap(),
        "ff02::1".parse().unwrap(),
    ];
    for ip in blocked {
        assert!(
            is_restricted_destination(at(ip)).is_some(),
            "{ip} must be blocked"
        );
    }
    // Exact addresses only: neighbours, the rest of 100.64.0.0/10, other ULAs and loopback stay
    // permitted.
    for allowed in [
        "100.100.100.199",
        "100.100.100.201",
        "100.64.0.1",
        "fd00:ec2::253",
        "fd00::1",
        "127.0.0.1",
        "::1",
        "10.0.0.1",
    ] {
        let ip: IpAddr = allowed.parse().unwrap();
        assert!(
            is_restricted_destination(at(ip)).is_none(),
            "{allowed} must stay permitted"
        );
    }
}

#[test]
fn canonical_ip_keeps_ipv6_loopback_and_unspecified() {
    let v4_loop: IpAddr = "127.0.0.1".parse().unwrap();
    let v6_loop: IpAddr = "::1".parse().unwrap();
    let v6_any: IpAddr = "::".parse().unwrap();

    assert_eq!(canonical_ip(v4_loop), v4_loop);
    assert!(canonical_ip(v4_loop).is_loopback());

    assert_eq!(
        canonical_ip(v6_loop),
        v6_loop,
        "::1 must not become 0.0.0.1"
    );
    assert!(canonical_ip(v6_loop).is_loopback());

    assert_eq!(canonical_ip(v6_any), v6_any);
    assert!(canonical_ip(v6_any).is_unspecified());

    // IPv4-mapped forms fold to IPv4.
    assert_eq!(canonical_ip("::ffff:127.0.0.1".parse().unwrap()), v4_loop);
    assert_eq!(
        canonical_ip("::ffff:169.254.169.254".parse().unwrap()),
        METADATA
    );
    // The deprecated IPv4-compatible form still folds, so it cannot slip past the IPv4 rules.
    assert_eq!(canonical_ip("::169.254.169.254".parse().unwrap()), METADATA);
    // Ordinary IPv6 is left alone.
    assert_eq!(canonical_ip(AWS_METADATA_V6), AWS_METADATA_V6);
}

#[test]
fn own_listener_comparison_is_consistent_across_families() {
    let port = 18080;
    let listeners: [SocketAddr; 2] = [
        "127.0.0.1:18080".parse().unwrap(),
        "[::1]:18080".parse().unwrap(),
    ];
    for listen in listeners {
        for own in ["127.0.0.1", "::ffff:127.0.0.1", "::1", "0.0.0.0", "::"] {
            let target = SocketAddr::new(own.parse().unwrap(), port);
            assert!(
                is_own_listener(target, listen),
                "{target} is the proxy at {listen}"
            );
        }
        for other in ["10.0.0.1", "::ffff:10.0.0.1", "::2", "fd00:ec2::254"] {
            let target = SocketAddr::new(other.parse().unwrap(), port);
            assert!(
                !is_own_listener(target, listen),
                "{target} is not the proxy at {listen}"
            );
        }
        let elsewhere = SocketAddr::new("::1".parse().unwrap(), port + 1);
        assert!(
            !is_own_listener(elsewhere, listen),
            "a different port is not the proxy"
        );
    }
}

#[tokio::test]
async fn own_loopback_listener_is_refused_in_both_families() {
    // IPv4 listener: IPv6 spellings of loopback must still be recognised as the proxy itself.
    let (proxy, storage, port) = start_proxy("loop-v4", Some(&["localhost"][..])).await;
    for host in [
        format!("127.0.0.1:{port}"),
        format!("[::1]:{port}"),
        format!("[::ffff:127.0.0.1]:{port}"),
    ] {
        for req in [
            format!("GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\n\r\n"),
            format!("CONNECT {host} HTTP/1.1\r\nHost: {host}\r\n\r\n"),
        ] {
            let resp = send(port, &req).await;
            assert!(
                resp.starts_with("HTTP/1.1 508 Loop Detected\r\n"),
                "v4 {req:?}: got: {resp}"
            );
        }
    }
    assert_eq!(
        proxy.outbound_connect_attempts(),
        0,
        "no forwarding loop is started"
    );
    assert_eq!(stored(&storage), 0);

    // IPv6 listener on ::1, where the host supports it.
    if std::net::TcpListener::bind("[::1]:0").is_err() {
        eprintln!("SKIPPED: IPv6 loopback is not available on this host");
        return;
    }
    let (proxy6, storage6, port6) =
        start_proxy_on("::1", "loop-v6", Some(&["localhost"][..])).await;
    assert_ne!(port6, 0, "::1 is accepted as a loopback bind address");
    let listener6 = SocketAddr::new("::1".parse().unwrap(), port6);
    for host in [
        format!("[::1]:{port6}"),
        format!("127.0.0.1:{port6}"),
        format!("localhost:{port6}"),
    ] {
        for req in [
            format!("GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\n\r\n"),
            format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"),
            format!("CONNECT {host} HTTP/1.1\r\nHost: {host}\r\n\r\n"),
        ] {
            let resp = send_to(listener6, &req).await;
            assert!(
                resp.starts_with("HTTP/1.1 508 Loop Detected\r\n"),
                "v6 {req:?}: got: {resp}"
            );
        }
    }
    assert_eq!(
        proxy6.outbound_connect_attempts(),
        0,
        "no forwarding loop is started"
    );
    assert_eq!(stored(&storage6), 0);
}

#[tokio::test]
async fn non_loopback_ipv6_bind_addresses_are_still_rejected() {
    let dir = temp_dir("bind6");
    let storage = StorageManager::new(dir.join("test.db")).unwrap();
    // `::` used to canonicalize to 0.0.0.0; it must still be refused now that it stays IPv6.
    for bind in ["::", "::ffff:192.168.1.1", "fd00::1", "fe80::1"] {
        let mut proxy = ProxyEngine::new(bind, 0, storage.clone());
        let err = proxy.start().await.unwrap_err().to_string();
        assert!(
            err.contains(&format!("Non-loopback bind address '{bind}' is prohibited")),
            "{bind}: got: {err}"
        );
    }
}

#[test]
fn nat64_well_known_prefix_gets_the_ipv4_rules() {
    let at = |ip: &str| SocketAddr::new(ip.parse().unwrap(), 80);
    // Each NAT64 form is refused with the same reason as the IPv4 address it embeds.
    for (nat64, v4) in [
        ("64:ff9b::a9fe:a9fe", "169.254.169.254"),
        ("64:ff9b::6464:64c8", "100.100.100.200"),
        ("64:ff9b::a9fe:1", "169.254.0.1"),
        ("64:ff9b::e000:1", "224.0.0.1"),
        ("64:ff9b::", "0.0.0.0"),
    ] {
        let reason = is_restricted_destination(at(nat64));
        assert!(reason.is_some(), "{nat64} must be refused like {v4}");
        assert_eq!(
            reason,
            is_restricted_destination(at(v4)),
            "{nat64} reason matches {v4}"
        );
    }
    // The prefix alone is not a reason: permitted embedded addresses stay permitted.
    for allowed in ["64:ff9b::808:808", "64:ff9b::6464:64c7", "64:ff9b::a00:1"] {
        assert!(
            is_restricted_destination(at(allowed)).is_none(),
            "{allowed} stays permitted"
        );
    }
    // Only the well-known /96 is decoded; network-specific prefixes (here the RFC 8215 local-use
    // 64:ff9b:1::/48) are not guessed at.
    assert!(is_restricted_destination(at("64:ff9b:1::a9fe:a9fe")).is_none());
    // Decoding is policy-only; canonical_ip (listener and loop checks) is unchanged.
    assert_eq!(canonical_ip(NAT64_METADATA), NAT64_METADATA);
}

#[tokio::test]
async fn permitted_nat64_destination_reaches_the_connector() {
    // A NAT64 address embedding a public IPv4 passes the policy. The test gate then refuses the
    // non-loopback socket (502) without opening it, so the counter proves the policy said yes.
    let (proxy, storage, port) = start_proxy("nat64-ok", Some(&["localhost"][..])).await;
    let cases = [
        "GET http://[64:ff9b::808:808]/ HTTP/1.1\r\nHost: [64:ff9b::808:808]\r\n\r\n",
        "GET http://nat64-public.test/ HTTP/1.1\r\nHost: nat64-public.test\r\n\r\n",
        "CONNECT [64:ff9b::808:808]:443 HTTP/1.1\r\nHost: [64:ff9b::808:808]:443\r\n\r\n",
    ];
    for (i, req) in cases.iter().enumerate() {
        let resp = send(port, req).await;
        let what = req.lines().next().unwrap();
        assert!(
            resp.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
            "{what}: got: {resp}"
        );
        assert!(
            !resp.contains("prohibited"),
            "{what}: not refused by policy, got: {resp}"
        );
        assert_eq!(
            proxy.outbound_connect_attempts(),
            i + 1,
            "{what}: reached the connector"
        );
    }
    assert_eq!(stored(&storage), 0);
}
