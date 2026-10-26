//! P1.6 regression: rows written before the persistence boundary existed are not exposed
//! through reads, are counted by the audit, and are purged by the opt-in remediation.
//! Uses a temporary database only.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use dropsuite_core::models::HistoryFilter;
use dropsuite_core::StorageManager;
use rusqlite::{params, Connection};

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

fn files(db: &Path) -> Vec<u8> {
    ["", "-wal", "-shm"]
        .iter()
        .filter_map(|s| std::fs::read(format!("{}{}", db.display(), s)).ok())
        .collect::<Vec<_>>()
        .concat()
}

#[test]
fn legacy_plaintext_is_hidden_counted_and_purged() {
    let n = format!(
        "{:x}{:x}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let markers: Vec<String> = ["LAUTH", "LCOOKIE", "LSETCOOKIE", "LQUERY"]
        .iter()
        .map(|l| format!("DSMARK{l}{n}"))
        .collect();
    let found = |bytes: &[u8]| markers.iter().filter(|m| contains(bytes, m)).count();
    let db = std::env::temp_dir().join(format!("dropsuite-p16-legacy-{n}.db"));

    // Create the schema, then write rows the way pre-P1.6 code did: parsed headers redacted,
    // raw messages and URLs in clear text.
    drop(StorageManager::new(&db).unwrap());
    {
        let conn = Connection::open(&db).unwrap();
        let insert = |url: &str, req_raw: &str, resp_raw: &str| {
            conn.execute(
                "INSERT INTO transactions (timestamp, duration_ms, method, url, host, path, request_headers,
                    request_body, status_code, response_headers, response_body, content_type, content_length)
                 VALUES (1, 1, 'GET', ?1, 'legacy.test', ?1, ?2, ?3, 200, ?4, ?5, 'text/plain', 2)",
                params![
                    url,
                    r#"[["Authorization","Bearer [REDACTED]"],["Cookie","[REDACTED_COOKIE]"]]"#,
                    req_raw.as_bytes(),
                    r#"[["Set-Cookie","[REDACTED_COOKIE]"]]"#,
                    resp_raw.as_bytes()
                ],
            )
            .unwrap();
        };
        insert(
            "http://legacy.test/a",
            &format!("GET http://legacy.test/a HTTP/1.1\r\nAuthorization: Bearer {}\r\nCookie: s={}\r\n\r\n", markers[0], markers[1]),
            &format!("HTTP/1.1 200 OK\r\nSet-Cookie: s={}; Path=/\r\n\r\nOK", markers[2]),
        );
        insert(
            &format!("http://legacy.test/b?token={}", markers[3]),
            "GET /b HTTP/1.1\r\nAccept: */*\r\n\r\n",
            "HTTP/1.1 200 OK\r\n\r\nOK",
        );
        insert(
            "http://legacy.test/c",
            "GET /c HTTP/1.1\r\nAccept: */*\r\n\r\n",
            "HTTP/1.1 200 OK\r\n\r\nOK",
        );
    }
    assert_eq!(
        found(&files(&db)),
        4,
        "fixture: legacy plaintext is on disk before remediation"
    );

    // Reads never expose it, even before remediation.
    let storage = StorageManager::new(&db).unwrap();
    let summaries = storage.list_summaries(&HistoryFilter::default()).unwrap();
    assert_eq!(
        found(serde_json::to_string(&summaries).unwrap().as_bytes()),
        0
    );
    for s in &summaries {
        let rec = storage.get_transaction_by_id(s.id).unwrap().unwrap();
        // Bodies are serialized as number arrays, so scan the decoded bytes as well.
        let mut view = serde_json::to_vec(&rec).unwrap();
        view.extend_from_slice(&rec.request_body);
        view.extend_from_slice(&rec.response_body);
        assert_eq!(found(&view), 0, "record {} API payload and bodies", rec.id);
    }
    drop(storage);

    // The read-only audit counts affected rows without returning any value.
    let audit = StorageManager::open_read_only(&db)
        .unwrap()
        .audit_legacy_records()
        .unwrap();
    assert_eq!(audit.total_records, 3);
    assert_eq!(audit.affected_records, 2);
    assert_eq!(audit.request_raw_affected, 1);
    assert_eq!(audit.response_raw_affected, 1);
    assert_eq!(audit.url_or_path_affected, 1);

    // Opt-in remediation rewrites the rows and purges the old pages.
    let storage = StorageManager::new(&db).unwrap();
    assert_eq!(
        storage.redact_legacy_records().unwrap(),
        2,
        "only the two leaking rows are rewritten"
    );
    assert_eq!(storage.audit_legacy_records().unwrap().affected_records, 0);
    assert_eq!(
        storage.count_transactions().unwrap(),
        3,
        "history is kept, not deleted"
    );
    drop(storage);
    assert_eq!(
        found(&files(&db)),
        0,
        "no marker left in db, -wal or -shm after remediation"
    );

    for s in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{}", db.display(), s));
    }
}
