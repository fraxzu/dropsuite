use dropsuite_core::{
    build_sitemap, MatchReplaceConfig, MatchReplaceEngine, MatchReplaceRule,
    MatchReplaceTarget, ScopeConfig, ScopeEngine, ScopeRule, ScopeRuleType, TransactionSummary,
};

#[test]
fn test_scope_wildcard_and_prefix_evaluation() {
    let mut config = ScopeConfig::default();
    config.enabled = true;
    config.drop_out_of_scope = true;
    config.rules = vec![
        ScopeRule {
            id: "rule_include_wildcard".into(),
            enabled: true,
            rule_type: ScopeRuleType::Include,
            protocol: Some("https".into()),
            host: "*.example.com".into(),
            port: Some(443),
            path_prefix: Some("/api/v1".into()),
        },
        ScopeRule {
            id: "rule_exclude_telemetry".into(),
            enabled: true,
            rule_type: ScopeRuleType::Exclude,
            protocol: None,
            host: "telemetry.example.com".into(),
            port: None,
            path_prefix: None,
        },
    ];

    let engine = ScopeEngine::with_config(config);

    // In-scope: matches *.example.com, https:443, /api/v1
    assert!(engine.is_in_scope("https://api.example.com/api/v1/auth"));
    assert!(engine.is_in_scope("https://example.com/api/v1/users"));
    assert!(!engine.should_drop_out_of_scope("https://api.example.com/api/v1/auth"));

    // Out-of-scope: path mismatch
    assert!(!engine.is_in_scope("https://api.example.com/static/style.css"));
    assert!(engine.should_drop_out_of_scope("https://api.example.com/static/style.css"));

    // Out-of-scope: scheme mismatch (http)
    assert!(!engine.is_in_scope("http://api.example.com/api/v1/auth"));
    assert!(engine.should_drop_out_of_scope("http://api.example.com/api/v1/auth"));

    // Out-of-scope: explicitly excluded host
    assert!(!engine.is_in_scope("https://telemetry.example.com/api/v1/track"));
    assert!(engine.should_drop_out_of_scope("https://telemetry.example.com/api/v1/track"));

    // Out-of-scope: completely foreign host
    assert!(!engine.is_in_scope("https://malicious.org/api/v1/payload"));
    assert!(engine.should_drop_out_of_scope("https://malicious.org/api/v1/payload"));
}

#[test]
fn test_match_replace_comprehensive_rules() {
    let config = MatchReplaceConfig {
        enabled: true,
        rules: vec![
            // 1. Rewrite First Line (Method/Path)
            MatchReplaceRule {
                id: "first_line".into(),
                enabled: true,
                comment: "Rewrite path".into(),
                target: MatchReplaceTarget::RequestFirstLine,
                is_regex: false,
                pattern: "/old-endpoint".into(),
                replacement: "/new-v2-endpoint".into(),
            },
            // 2. Replace Request Header
            MatchReplaceRule {
                id: "user_agent".into(),
                enabled: true,
                comment: "Spoof User-Agent".into(),
                target: MatchReplaceTarget::RequestHeader,
                is_regex: true,
                pattern: r"^User-Agent: .*".into(),
                replacement: "User-Agent: DropSuite-Security-Auditor/1.0".into(),
            },
            // 3. Add Custom Request Header
            MatchReplaceRule {
                id: "add_header".into(),
                enabled: true,
                comment: "Inject Bearer Token".into(),
                target: MatchReplaceTarget::RequestHeader,
                is_regex: false,
                pattern: "".into(),
                replacement: "Authorization: Bearer test_token_xyz".into(),
            },
            // 4. Request Body Tampering
            MatchReplaceRule {
                id: "body_tamper".into(),
                enabled: true,
                comment: "Escalate privilege in JSON".into(),
                target: MatchReplaceTarget::RequestBody,
                is_regex: false,
                pattern: "\"is_admin\": false".into(),
                replacement: "\"is_admin\": true".into(),
            },
            // 5. Response Header Removal (Remove CSP)
            MatchReplaceRule {
                id: "strip_csp".into(),
                enabled: true,
                comment: "Remove CSP".into(),
                target: MatchReplaceTarget::ResponseHeader,
                is_regex: true,
                pattern: r"^Content-Security-Policy: .*".into(),
                replacement: "".into(),
            },
            // 6. Response Body Rewrite
            MatchReplaceRule {
                id: "resp_body".into(),
                enabled: true,
                comment: "Un-minify or modify response".into(),
                target: MatchReplaceTarget::ResponseBody,
                is_regex: false,
                pattern: "var debug = false;".into(),
                replacement: "var debug = true;".into(),
            },
        ],
    };

    let engine = MatchReplaceEngine::with_config(config);

    // Test Request Head Wire Modification
    let raw_req_head = b"GET /old-endpoint HTTP/1.1\r\nHost: target.local\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n";
    let modified_req = engine.apply_request_head(raw_req_head);
    let modified_req_str = String::from_utf8(modified_req).unwrap();

    assert!(modified_req_str.starts_with("GET /new-v2-endpoint HTTP/1.1\r\n"));
    assert!(modified_req_str.contains("User-Agent: DropSuite-Security-Auditor/1.0"));
    assert!(modified_req_str.contains("Authorization: Bearer test_token_xyz"));
    assert!(modified_req_str.ends_with("\r\n\r\n"));

    // Test Request Body Modification
    let raw_body = br#"{"username": "auditor", "is_admin": false, "active": true}"#;
    let modified_body = engine.apply_request_body(raw_body);
    let modified_body_str = String::from_utf8(modified_body).unwrap();
    assert_eq!(
        modified_body_str,
        r#"{"username": "auditor", "is_admin": true, "active": true}"#
    );

    // Test Response Head Strip
    let raw_resp_head = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Security-Policy: default-src 'self'\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n";
    let modified_resp = engine.apply_response_head(raw_resp_head);
    let modified_resp_str = String::from_utf8(modified_resp).unwrap();
    assert!(!modified_resp_str.contains("Content-Security-Policy"));
    assert!(modified_resp_str.contains("X-Frame-Options: SAMEORIGIN"));
    assert!(modified_resp_str.contains("Server: nginx"));

    // Test Response Body Replacement
    let raw_resp_body = b"function init() { var debug = false; console.log('ready'); }";
    let modified_resp_body = engine.apply_response_body(raw_resp_body);
    let modified_resp_body_str = String::from_utf8(modified_resp_body).unwrap();
    assert_eq!(
        modified_resp_body_str,
        "function init() { var debug = true; console.log('ready'); }"
    );
}

#[test]
fn test_sitemap_building_and_scope_tagging() {
    let mut scope_cfg = ScopeConfig::default();
    scope_cfg.enabled = true;
    scope_cfg.rules = vec![ScopeRule {
        id: "target_scope".into(),
        enabled: true,
        rule_type: ScopeRuleType::Include,
        protocol: None,
        host: "app.securetarget.com".into(),
        port: None,
        path_prefix: None,
    }];
    let scope_engine = ScopeEngine::with_config(scope_cfg);

    let records = vec![
        TransactionSummary {
            id: 1,
            timestamp: 1000,
            duration_ms: 15,
            method: "GET".into(),
            host: "app.securetarget.com".into(),
            path: "/api/v2/items?sort=desc&limit=10".into(),
            status_code: 200,
            content_type: Some("application/json".into()),
            content_length: 120,
        },
        TransactionSummary {
            id: 2,
            timestamp: 1050,
            duration_ms: 22,
            method: "POST".into(),
            host: "app.securetarget.com".into(),
            path: "/api/v2/items?token=secret".into(),
            status_code: 201,
            content_type: Some("application/json".into()),
            content_length: 64,
        },
        TransactionSummary {
            id: 3,
            timestamp: 1100,
            duration_ms: 5,
            method: "GET".into(),
            host: "cdn.out-of-scope.net".into(),
            path: "/assets/app.js".into(),
            status_code: 200,
            content_type: Some("application/javascript".into()),
            content_length: 5000,
        },
    ];

    let sitemap = build_sitemap(&records, &scope_engine);

    assert_eq!(sitemap.len(), 2);

    let secure_root = sitemap.iter().find(|n| n.host == "app.securetarget.com").expect("Found secure target");
    assert!(secure_root.in_scope);
    assert_eq!(secure_root.total, 2);
    assert_eq!(secure_root.methods, vec!["GET", "POST"]);

    // Hierarchy navigation: api -> v2 -> items
    assert_eq!(secure_root.children.len(), 1);
    let api_node = &secure_root.children[0];
    assert_eq!(api_node.name, "api");

    let v2_node = &api_node.children[0];
    assert_eq!(v2_node.name, "v2");

    let items_node = &v2_node.children[0];
    assert_eq!(items_node.name, "items");
    assert_eq!(items_node.total, 2);
    assert!(items_node.parameters.contains(&"sort".to_string()));
    assert!(items_node.parameters.contains(&"limit".to_string()));
    assert!(items_node.parameters.contains(&"token".to_string()));

    let out_node = sitemap.iter().find(|n| n.host == "cdn.out-of-scope.net").expect("Found out-of-scope root");
    assert!(!out_node.in_scope);
}
