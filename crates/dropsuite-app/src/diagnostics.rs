//! Local diagnostics: the app's log lines go to stderr and, once the data folder is known, to
//! `logs/dropsuite.log` there. The file rotates at 1 MiB and three files are kept, so the
//! logs never use more than about 3 MiB. Nothing is sent anywhere.
//!
//! What is logged: startup and shutdown, listener start and stop, port conflicts, settings
//! changes, upstream connection failures (host and port only) and internal errors. Captured
//! traffic, header values, bodies and URLs are never logged.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const MAX_BYTES: u64 = 1024 * 1024;
/// The current file plus this many rotated ones.
const ROTATED: usize = 2;
const FILE_NAME: &str = "dropsuite.log";

struct LogFile {
    dir: PathBuf,
    file: Option<File>,
    size: u64,
}

static LOG: OnceLock<Mutex<LogFile>> = OnceLock::new();

fn rotated(dir: &Path, n: usize) -> PathBuf {
    dir.join(format!("dropsuite.{n}.log"))
}

impl LogFile {
    fn open(dir: &Path) -> std::io::Result<LogFile> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(FILE_NAME))?;
        let size = file.metadata()?.len();
        Ok(LogFile {
            dir: dir.to_path_buf(),
            file: Some(file),
            size,
        })
    }

    fn rotate(&mut self) {
        self.file = None; // close before renaming (Windows cannot rename an open file)
        let _ = std::fs::remove_file(rotated(&self.dir, ROTATED));
        for n in (1..ROTATED).rev() {
            let _ = std::fs::rename(rotated(&self.dir, n), rotated(&self.dir, n + 1));
        }
        let _ = std::fs::rename(self.dir.join(FILE_NAME), rotated(&self.dir, 1));
        if let Ok(fresh) = LogFile::open(&self.dir) {
            *self = fresh;
        }
    }

    fn write(&mut self, buf: &[u8]) {
        if self.size + buf.len() as u64 > MAX_BYTES {
            self.rotate();
        }
        if let Some(file) = &mut self.file {
            if file.write_all(buf).is_ok() {
                self.size += buf.len() as u64;
            }
        }
    }
}

/// Start writing the log file in `dir` (created if needed). Returns the folder for display.
pub fn start_file_log(data_dir: &Path) -> Option<PathBuf> {
    let dir = data_dir.join("logs");
    std::fs::create_dir_all(&dir).ok()?;
    let mut log = LogFile::open(&dir).ok()?;
    if log.size > MAX_BYTES {
        log.rotate();
    }
    let _ = LOG.set(Mutex::new(log));
    Some(dir)
}

/// The writer handed to `tracing_subscriber`: stderr always, the file once started.
pub struct LogWriter;

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let _ = std::io::stderr().write_all(buf);
        if let Some(log) = LOG.get() {
            log.lock().unwrap_or_else(|e| e.into_inner()).write(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_writer(|| LogWriter)
        .init();
    // Internal errors that would otherwise vanish with a GUI-subsystem process. Only the
    // location and a bounded message are kept.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_default();
        let message: String = message.chars().take(200).collect();
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        tracing::error!("Internal error at {location}: {message}");
        default_hook(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_rotates_and_stays_bounded() {
        let dir = std::env::temp_dir().join(format!("dropsuite-logs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut log = LogFile::open(&dir).unwrap();
        let line = vec![b'x'; 1000];
        for _ in 0..5000 {
            log.write(&line);
        }
        let files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap())
            .collect();
        assert_eq!(
            files.len(),
            1 + ROTATED,
            "current file plus {ROTATED} rotated"
        );
        let total: u64 = files.iter().map(|f| f.metadata().unwrap().len()).sum();
        assert!(
            total <= (1 + ROTATED as u64) * MAX_BYTES,
            "total {total} bytes"
        );
        drop(log);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
