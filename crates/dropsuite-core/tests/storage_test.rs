use dropsuite_core::models::{HistoryFilter, TransactionRecord};
use dropsuite_core::StorageManager;

#[test]
fn test_sqlite_crud_and_persistence() {
    let test_db_path = "test_persistence.db";
    let _ = std::fs::remove_file(test_db_path);

    // 1. Creation and schema initialization
    {
        let storage = StorageManager::new(test_db_path).expect("Failed to initialize storage");
        assert_eq!(storage.count_transactions().unwrap(), 0);

        // 2. INSERT 3 distinct transactions
        let t1 = TransactionRecord {
            id: 0,
            timestamp: 1729000000000,
            duration_ms: 45,
            method: "GET".to_string(),
            url: "http://127.0.0.1:9090/api/users".to_string(),
            host: "127.0.0.1:9090".to_string(),
            path: "/api/users".to_string(),
            request_headers: vec![("User-Agent".to_string(), "DropSuite/1.0".to_string())],
            request_body: vec![],
            status_code: 200,
            response_headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            response_body: b"{\"users\":[\"alice\",\"bob\"]}".to_vec(),
            content_type: Some("application/json".to_string()),
            content_length: 27,
        };

        let t2 = TransactionRecord {
            id: 0,
            timestamp: 1729000001000,
            duration_ms: 120,
            method: "POST".to_string(),
            url: "http://127.0.0.1:9090/api/login".to_string(),
            host: "127.0.0.1:9090".to_string(),
            path: "/api/login".to_string(),
            request_headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            request_body: b"{\"username\":\"admin\"}".to_vec(),
            status_code: 401,
            response_headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            response_body: b"{\"error\":\"Unauthorized\"}".to_vec(),
            content_type: Some("application/json".to_string()),
            content_length: 24,
        };

        let t3 = TransactionRecord {
            id: 0,
            timestamp: 1729000002000,
            duration_ms: 15,
            method: "GET".to_string(),
            url: "http://127.0.0.1:9090/health".to_string(),
            host: "127.0.0.1:9090".to_string(),
            path: "/health".to_string(),
            request_headers: vec![],
            request_body: vec![],
            status_code: 200,
            response_headers: vec![],
            response_body: b"OK".to_vec(),
            content_type: Some("text/plain".to_string()),
            content_length: 2,
        };

        let id1 = storage.insert_transaction(&t1).unwrap();
        let id2 = storage.insert_transaction(&t2).unwrap();
        let id3 = storage.insert_transaction(&t3).unwrap();

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
        assert_eq!(storage.count_transactions().unwrap(), 3);

        // 3. SELECT and Filter tests
        // Filter by method POST
        let post_filter = HistoryFilter {
            method: Some("POST".to_string()),
            ..Default::default()
        };
        let post_summaries = storage.list_summaries(&post_filter).unwrap();
        assert_eq!(post_summaries.len(), 1);
        assert_eq!(post_summaries[0].path, "/api/login");
        assert_eq!(post_summaries[0].status_code, 401);

        // Filter by status 200
        let status_filter = HistoryFilter {
            status_code: Some(200),
            ..Default::default()
        };
        let ok_summaries = storage.list_summaries(&status_filter).unwrap();
        assert_eq!(ok_summaries.len(), 2);

        // Search query
        let q_filter = HistoryFilter {
            query: Some("users".to_string()),
            ..Default::default()
        };
        let q_summaries = storage.list_summaries(&q_filter).unwrap();
        assert_eq!(q_summaries.len(), 1);
        assert_eq!(q_summaries[0].path, "/api/users");

        // Verify full record retrieval by ID
        let rec2 = storage
            .get_transaction_by_id(2)
            .unwrap()
            .expect("Transaction 2 exists");
        assert_eq!(rec2.method, "POST");
        assert_eq!(rec2.request_body, b"{\"username\":\"admin\"}");
        assert_eq!(rec2.response_body, b"{\"error\":\"Unauthorized\"}");
    } // Storage connection closed here

    // 4. Persistence Test across re-opens (simulating app restart)
    {
        let reopened_storage = StorageManager::new(test_db_path).expect("Failed to reopen storage");
        assert_eq!(reopened_storage.count_transactions().unwrap(), 3);

        let rec1 = reopened_storage
            .get_transaction_by_id(1)
            .unwrap()
            .expect("Transaction 1 persisted");
        assert_eq!(rec1.url, "http://127.0.0.1:9090/api/users");
        assert_eq!(rec1.status_code, 200);
    }

    // Cleanup test database
    let _ = std::fs::remove_file(test_db_path);
}

#[test]
fn test_clear_transactions_empties_history() {
    let test_db_path = "test_clear_history.db";
    let _ = std::fs::remove_file(test_db_path);

    let rec = |path: &str| TransactionRecord {
        id: 0,
        timestamp: 1729000000000,
        duration_ms: 10,
        method: "GET".to_string(),
        url: format!("http://127.0.0.1:9090{path}"),
        host: "127.0.0.1:9090".to_string(),
        path: path.to_string(),
        request_headers: vec![],
        request_body: vec![],
        status_code: 200,
        response_headers: vec![],
        response_body: b"OK".to_vec(),
        content_type: Some("text/plain".to_string()),
        content_length: 2,
    };

    {
        let storage = StorageManager::new(test_db_path).expect("init storage");
        storage.insert_transaction(&rec("/a")).unwrap();
        storage.insert_transaction(&rec("/b")).unwrap();
        storage.insert_transaction(&rec("/c")).unwrap();
        assert_eq!(storage.count_transactions().unwrap(), 3);

        // Clear reports how many rows it removed and leaves the table empty.
        let removed = storage.clear_transactions().unwrap();
        assert_eq!(removed, 3);
        assert_eq!(storage.count_transactions().unwrap(), 0);
        assert!(storage
            .list_summaries(&HistoryFilter::default())
            .unwrap()
            .is_empty());

        // Clearing an already-empty table removes nothing and does not error.
        assert_eq!(storage.clear_transactions().unwrap(), 0);

        // New captures still insert after a clear; ids keep climbing (AUTOINCREMENT).
        let new_id = storage.insert_transaction(&rec("/d")).unwrap();
        assert!(
            new_id > 3,
            "id should not be reused after clear, got {new_id}"
        );
        assert_eq!(storage.count_transactions().unwrap(), 1);
    }

    // The empty state survives a reopen (the delete reached the main db file, not just the WAL).
    {
        let reopened = StorageManager::new(test_db_path).expect("reopen storage");
        assert_eq!(reopened.count_transactions().unwrap(), 1);
        reopened.clear_transactions().unwrap();
        assert_eq!(reopened.count_transactions().unwrap(), 0);
    }

    let _ = std::fs::remove_file(test_db_path);
}

fn cookie(
    host: &str,
    name: &str,
    path: &str,
    expires_at: Option<i64>,
) -> dropsuite_core::StoredCookie {
    dropsuite_core::StoredCookie {
        domain: None,
        host: host.to_string(),
        name: name.to_string(),
        value: "v1".to_string(),
        path: path.to_string(),
        secure: false,
        http_only: true,
        expires_at,
        created_at: 1_700_000_000,
    }
}

#[test]
fn cookies_persist_upsert_and_filter_by_host() {
    let db = "test_cookies.db";
    let _ = std::fs::remove_file(db);

    {
        let storage = StorageManager::new(db).expect("init storage");
        storage
            .upsert_cookie(&cookie("api.example.com", "cf_clearance", "/", None))
            .unwrap();
        storage
            .upsert_cookie(&cookie("other.test", "sid", "/", None))
            .unwrap();

        let for_host = storage.cookies_for_host("api.example.com").unwrap();
        assert_eq!(for_host.len(), 1);
        assert_eq!(for_host[0].name, "cf_clearance");
        assert!(for_host[0].http_only);

        // Same host, name and path replaces the value in place.
        let mut updated = cookie("api.example.com", "cf_clearance", "/", None);
        updated.value = "v2".to_string();
        storage.upsert_cookie(&updated).unwrap();
        let for_host = storage.cookies_for_host("api.example.com").unwrap();
        assert_eq!(for_host.len(), 1);
        assert_eq!(for_host[0].value, "v2");
    }

    {
        let reopened = StorageManager::new(db).expect("reopen storage");
        let for_host = reopened.cookies_for_host("api.example.com").unwrap();
        assert_eq!(for_host.len(), 1);
        assert_eq!(for_host[0].value, "v2", "cookies outlive a restart");

        // A parent-domain cookie also comes back for a child host.
        let mut parent = cookie("example.com", "wide", "/", None);
        parent.domain = Some("example.com".to_string());
        reopened.upsert_cookie(&parent).unwrap();
        assert_eq!(
            reopened.cookies_for_host("api.example.com").unwrap().len(),
            2
        );
        assert_eq!(
            reopened.cookies_for_host("unrelated.test").unwrap().len(),
            0
        );

        assert_eq!(
            reopened
                .delete_cookie("api.example.com", "cf_clearance", "/")
                .unwrap(),
            1
        );
        // `sid` on other.test and the wide parent cookie remain.
        assert_eq!(reopened.list_cookies().unwrap().len(), 2);
        assert_eq!(reopened.clear_cookies().unwrap(), 2);
        assert!(reopened.list_cookies().unwrap().is_empty());
    }

    let _ = std::fs::remove_file(db);
}

#[test]
fn expired_cookies_are_purged_only() {
    let storage = StorageManager::new_in_memory().unwrap();
    storage
        .upsert_cookie(&cookie("a.test", "old", "/", Some(1_600_000_000)))
        .unwrap();
    storage
        .upsert_cookie(&cookie("a.test", "fresh", "/", Some(1_800_000_000)))
        .unwrap();
    storage
        .upsert_cookie(&cookie("a.test", "session", "/", None))
        .unwrap();

    assert_eq!(storage.purge_expired_cookies(1_700_000_000).unwrap(), 1);
    let names: Vec<String> = storage
        .list_cookies()
        .unwrap()
        .into_iter()
        .map(|c| c.name)
        .collect();
    assert_eq!(names, vec!["fresh".to_string(), "session".to_string()]);
}

#[test]
fn challenge_pin_round_trips_and_expires() {
    let storage = StorageManager::new_in_memory().unwrap();
    let pin = dropsuite_core::storage::ChallengePin {
        host: "a.test".into(),
        user_agent: "UA/1".into(),
        preset: "edge".into(),
        expires_at: 2_000,
    };
    storage.upsert_challenge_pin(&pin).unwrap();
    assert_eq!(
        storage.challenge_pin("a.test", 1_000).unwrap(),
        Some(pin.clone())
    );
    assert_eq!(
        storage.challenge_pin("a.test", 2_000).unwrap(),
        None,
        "expired pins are dropped"
    );

    storage.upsert_challenge_pin(&pin).unwrap();
    storage.clear_challenge_pin("a.test").unwrap();
    assert_eq!(storage.challenge_pin("a.test", 1_000).unwrap(), None);
}
