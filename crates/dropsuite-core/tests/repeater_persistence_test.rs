use dropsuite_core::models::{
    HistoryFilter, RepeaterAttemptRecord, RepeaterTabRecord, TransactionRecord,
};
use dropsuite_core::StorageManager;

#[test]
fn test_repeater_tab_crud_and_persistence() {
    let db_path = "test_repeater_tabs.db";
    let _ = std::fs::remove_file(db_path);

    {
        let storage = StorageManager::new(db_path).expect("Init storage");
        assert_eq!(storage.list_repeater_tabs().unwrap().len(), 0);

        let t1 = RepeaterTabRecord {
            id: 0,
            name: "Login Probe".to_string(),
            color: Some("blue".to_string()),
            group_name: Some("Auth".to_string()),
            method: "POST".to_string(),
            url: "http://127.0.0.1:8080/api/auth/login".to_string(),
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: "{\"user\":\"admin\",\"pass\":\"test\"}".to_string(),
            created_at: 1000,
            updated_at: 1000,
        };

        let t2 = RepeaterTabRecord {
            id: 0,
            name: "User Info".to_string(),
            color: Some("green".to_string()),
            group_name: Some("Users".to_string()),
            method: "GET".to_string(),
            url: "http://127.0.0.1:8080/api/users/me".to_string(),
            headers: vec![("Accept".to_string(), "application/json".to_string())],
            body: "".to_string(),
            created_at: 2000,
            updated_at: 2000,
        };

        let t3 = RepeaterTabRecord {
            id: 0,
            name: "Health Check".to_string(),
            color: None,
            group_name: None,
            method: "GET".to_string(),
            url: "http://127.0.0.1:8080/health".to_string(),
            headers: vec![],
            body: "".to_string(),
            created_at: 3000,
            updated_at: 3000,
        };

        let id1 = storage.save_repeater_tab(&t1).unwrap();
        let id2 = storage.save_repeater_tab(&t2).unwrap();
        let id3 = storage.save_repeater_tab(&t3).unwrap();

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);

        let tabs = storage.list_repeater_tabs().unwrap();
        assert_eq!(tabs.len(), 3);
        assert_eq!(tabs[0].name, "Login Probe");
        assert_eq!(tabs[0].color, Some("blue".to_string()));
        assert_eq!(tabs[0].group_name, Some("Auth".to_string()));
        assert_eq!(tabs[1].name, "User Info");

        // Update tab 2
        let mut t2_updated = storage
            .get_repeater_tab(id2)
            .unwrap()
            .expect("Tab 2 exists");
        t2_updated.name = "User Info (Updated)".to_string();
        t2_updated.color = Some("purple".to_string());
        t2_updated.body = "{\"include_roles\":true}".to_string();
        let saved_id2 = storage.save_repeater_tab(&t2_updated).unwrap();
        assert_eq!(saved_id2, id2);

        let t2_fetched = storage
            .get_repeater_tab(id2)
            .unwrap()
            .expect("Tab 2 exists");
        assert_eq!(t2_fetched.name, "User Info (Updated)");
        assert_eq!(t2_fetched.color, Some("purple".to_string()));
        assert_eq!(t2_fetched.body, "{\"include_roles\":true}");

        // Delete tab 1
        storage.delete_repeater_tab(id1).unwrap();
        let tabs_after = storage.list_repeater_tabs().unwrap();
        assert_eq!(tabs_after.len(), 2);
        assert_eq!(tabs_after[0].id, 2);
        assert_eq!(tabs_after[1].id, 3);
    }

    // Reopen and check persistence across restarts
    {
        let reopened = StorageManager::new(db_path).expect("Reopen storage");
        let tabs = reopened.list_repeater_tabs().unwrap();
        assert_eq!(tabs.len(), 2);
        assert_eq!(tabs[0].name, "User Info (Updated)");
        assert_eq!(tabs[1].name, "Health Check");
    }

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn test_repeater_attempts_recording_pruning_and_sanitization() {
    let db_path = "test_repeater_attempts.db";
    let _ = std::fs::remove_file(db_path);

    {
        let storage = StorageManager::new(db_path).expect("Init storage");

        let tab = RepeaterTabRecord {
            id: 0,
            name: "Security Probe".to_string(),
            color: Some("red".to_string()),
            group_name: None,
            method: "POST".to_string(),
            url: "http://127.0.0.1:8080/api/session".to_string(),
            headers: vec![],
            body: "".to_string(),
            created_at: 1000,
            updated_at: 1000,
        };
        let tab_id = storage.save_repeater_tab(&tab).unwrap();

        // 1. Add 25 attempts to test automatic retention capping (max 20)
        for i in 1..=25 {
            let attempt = RepeaterAttemptRecord {
                id: 0,
                tab_id,
                seq: i,
                created_at: 1000 + i as i64 * 10,
                method: "POST".to_string(),
                destination: "127.0.0.1:8080".to_string(),
                status_code: Some(200),
                duration_ms: 10 + i as u64,
                total_bytes: 500,
                sent_bytes: 120,
                response_headers: vec![(
                    "Content-Type".to_string(),
                    "application/json".to_string(),
                )],
                response_body: format!("{{\"seq\":{}}}", i).into_bytes(),
                content_type: Some("application/json".to_string()),
                failure_kind: None,
                failure_message: None,
            };
            storage.save_repeater_attempt(&attempt).unwrap();
        }

        let attempts = storage.list_repeater_attempts(tab_id, Some(50)).unwrap();
        // Capped at 20
        assert_eq!(attempts.len(), 20);
        // The oldest kept should be seq 6, newest seq 25
        assert_eq!(attempts.first().unwrap().seq, 6);
        assert_eq!(attempts.last().unwrap().seq, 25);

        // 2. Test sanitization of sensitive values at persistence boundary
        let secret_attempt = RepeaterAttemptRecord {
            id: 0,
            tab_id,
            seq: 26,
            created_at: 2000,
            method: "POST".to_string(),
            destination: "127.0.0.1:8080".to_string(),
            status_code: Some(200),
            duration_ms: 25,
            total_bytes: 600,
            sent_bytes: 150,
            response_headers: vec![
                (
                    "Set-Cookie".to_string(),
                    "session=secret_token_12345; Path=/".to_string(),
                ),
                ("X-Api-Key".to_string(), "sk-live-secret-999".to_string()),
            ],
            response_body: b"{\"token\":\"sk-live-secret-999\",\"public\":\"visible\"}".to_vec(),
            content_type: Some("application/json".to_string()),
            failure_kind: None,
            failure_message: None,
        };
        storage.save_repeater_attempt(&secret_attempt).unwrap();

        let attempts_after = storage.list_repeater_attempts(tab_id, Some(50)).unwrap();
        let last = attempts_after.last().unwrap();
        assert_eq!(last.seq, 26);

        // Verify Set-Cookie and X-Api-Key are redacted
        for (k, v) in &last.response_headers {
            if k.eq_ignore_ascii_case("set-cookie") {
                assert!(
                    v.contains("[REDACTED"),
                    "Cookie value should be redacted: {}",
                    v
                );
            }
            if k.eq_ignore_ascii_case("x-api-key") {
                assert!(v.contains("[REDACTED"), "API key should be redacted: {}", v);
            }
        }

        // 3. Clear attempts
        storage.clear_repeater_attempts(tab_id).unwrap();
        assert_eq!(
            storage.list_repeater_attempts(tab_id, None).unwrap().len(),
            0
        );
    }

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn test_advanced_history_filters_sorting_and_har_export() {
    let db_path = "test_history_advanced.db";
    let _ = std::fs::remove_file(db_path);

    {
        let storage = StorageManager::new(db_path).expect("Init storage");

        let make_tx = |id: i64, status: u16, ct: &str, dur: u64, len: usize| TransactionRecord {
            id,
            timestamp: 1729000000000 + id * 1000,
            duration_ms: dur,
            method: if status == 404 { "GET" } else { "POST" }.to_string(),
            url: format!("http://127.0.0.1:8080/item/{}", id),
            host: "127.0.0.1:8080".to_string(),
            path: format!("/item/{}", id),
            request_headers: vec![("User-Agent".to_string(), "DropSuite/0.1".to_string())],
            request_body: b"{\"req\":1}".to_vec(),
            status_code: status,
            response_headers: vec![("Content-Type".to_string(), ct.to_string())],
            response_body: b"{\"resp\":true}".to_vec(),
            content_type: Some(ct.to_string()),
            content_length: len,
        };

        storage
            .insert_transaction(&make_tx(1, 200, "application/json", 50, 200))
            .unwrap();
        storage
            .insert_transaction(&make_tx(2, 302, "text/html", 10, 50))
            .unwrap();
        storage
            .insert_transaction(&make_tx(3, 404, "text/plain", 120, 15))
            .unwrap();
        storage
            .insert_transaction(&make_tx(4, 500, "application/json", 300, 500))
            .unwrap();

        // Filter status range 400-599
        let err_filter = HistoryFilter {
            status_min: Some(400),
            status_max: Some(599),
            ..Default::default()
        };
        let err_summaries = storage.list_summaries(&err_filter).unwrap();
        assert_eq!(err_summaries.len(), 2);

        // Filter content_type "json"
        let json_filter = HistoryFilter {
            content_type: Some("json".to_string()),
            ..Default::default()
        };
        let json_summaries = storage.list_summaries(&json_filter).unwrap();
        assert_eq!(json_summaries.len(), 2);

        // Sort by duration_ms ASC
        let sort_filter = HistoryFilter {
            sort_by: Some("duration_ms".to_string()),
            sort_order: Some("ASC".to_string()),
            ..Default::default()
        };
        let sorted = storage.list_summaries(&sort_filter).unwrap();
        assert_eq!(sorted.len(), 4);
        assert_eq!(sorted[0].duration_ms, 10);
        assert_eq!(sorted[3].duration_ms, 300);

        // HAR 1.2 Export
        let har_json = storage.export_har(&[1, 4]).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&har_json).expect("Valid JSON");
        assert_eq!(parsed["log"]["version"], "1.2");
        assert_eq!(parsed["log"]["creator"]["name"], "DropSuite");
        let entries = parsed["log"]["entries"].as_array().expect("Entries array");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["response"]["status"], 200);
        assert_eq!(entries[1]["response"]["status"], 500);
        assert_eq!(entries[0]["request"]["url"], "http://127.0.0.1:8080/item/1");
    }

    let _ = std::fs::remove_file(db_path);
}
