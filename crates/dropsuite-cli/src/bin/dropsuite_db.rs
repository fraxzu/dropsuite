//! Legacy history audit and remediation.
//!
//!   dropsuite_db audit  <db-path>              read-only; prints counts, never values
//!   dropsuite_db redact <db-path> --i-understand   rewrites rows in place and purges old pages
//!
//! `redact` is destructive and irreversible. Stop the daemon first and make sure you do not
//! need the unredacted history. It cannot clean copies outside the database file.

use dropsuite_core::StorageManager;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let usage =
        "usage: dropsuite_db audit <db-path> | dropsuite_db redact <db-path> --i-understand";
    let (cmd, path) = match (args.get(1), args.get(2)) {
        (Some(c), Some(p)) => (c.as_str(), p.as_str()),
        _ => {
            eprintln!("{usage}");
            std::process::exit(2);
        }
    };
    if !std::path::Path::new(path).exists() {
        eprintln!("No database at {path}");
        std::process::exit(2);
    }

    match cmd {
        "audit" => {
            let storage = StorageManager::open_read_only(path).unwrap_or_else(|e| fail(&e));
            let a = storage.audit_legacy_records().unwrap_or_else(|e| fail(&e));
            println!("records total:                       {}", a.total_records);
            println!(
                "records the current policy changes:  {}",
                a.affected_records
            );
            println!(
                "  raw request holds redactable data:  {}",
                a.request_raw_affected
            );
            println!(
                "  raw response holds redactable data: {}",
                a.response_raw_affected
            );
            println!(
                "  url/path/host holds redactable data:{:>3}",
                a.url_or_path_affected
            );
            println!(
                "  parsed headers differ:              {}",
                a.parsed_headers_affected
            );
        }
        "redact" if args.get(3).map(String::as_str) == Some("--i-understand") => {
            let storage = StorageManager::new(path).unwrap_or_else(|e| fail(&e));
            let n = storage.redact_legacy_records().unwrap_or_else(|e| fail(&e));
            println!("rewrote {n} record(s); WAL checkpointed and database vacuumed");
        }
        "redact" => {
            eprintln!("redact rewrites history permanently. Re-run with --i-understand after stopping the daemon.");
            std::process::exit(2);
        }
        _ => {
            eprintln!("{usage}");
            std::process::exit(2);
        }
    }
}

fn fail(e: &dyn std::fmt::Display) -> ! {
    eprintln!("error: {e}");
    std::process::exit(1);
}
