use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

static LOCK_MANAGER: OnceLock<(Mutex<HashSet<PathBuf>>, Condvar)> = OnceLock::new();

fn normalize_path(path: &Path) -> PathBuf {
    if let Ok(canon) = path.canonicalize() {
        canon
    } else if let Some(parent) = path.parent() {
        if let Ok(canon_parent) = parent.canonicalize() {
            if let Some(file_name) = path.file_name() {
                return canon_parent.join(file_name);
            }
        }
        path.to_path_buf()
    } else {
        path.to_path_buf()
    }
}

pub struct FileLock {
    file: File,
    lock_path: PathBuf,
}

impl FileLock {
    /// Acquires both an in-process exclusive lock and an OS-level file lock on `lock_path`.
    /// Retries for up to 5 seconds with exponential backoff.
    pub fn acquire(lock_path: &Path) -> Result<Self, String> {
        let norm_path = normalize_path(lock_path);
        let (lock, cvar) =
            LOCK_MANAGER.get_or_init(|| (Mutex::new(HashSet::new()), Condvar::new()));

        let start = Instant::now();
        let timeout = Duration::from_secs(5);

        // 1. Acquire in-process lock
        {
            let mut set = lock
                .lock()
                .map_err(|e| format!("Lock manager mutex poisoned: {}", e))?;
            loop {
                if !set.contains(&norm_path) {
                    set.insert(norm_path.clone());
                    break;
                }
                let elapsed = start.elapsed();
                if elapsed >= timeout {
                    return Err(format!(
                        "Timeout waiting for in-process lock on {}",
                        lock_path.display()
                    ));
                }
                let remaining = timeout - elapsed;
                let (new_set, wait_res) = cvar
                    .wait_timeout(set, remaining)
                    .map_err(|e| format!("Lock manager condvar poisoned: {}", e))?;
                set = new_set;
                if wait_res.timed_out() && set.contains(&norm_path) {
                    return Err(format!(
                        "Timeout waiting for in-process lock on {}",
                        lock_path.display()
                    ));
                }
            }
        }

        // Helper to release in-process lock if subsequent OS lock fails
        let release_in_process = || {
            if let Ok(mut set) = lock.lock() {
                set.remove(&norm_path);
                cvar.notify_all();
            }
        };

        // 2. Open or create the lock file
        if let Some(parent) = lock_path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                release_in_process();
                return Err(format!(
                    "Failed to create directory for lockfile {}: {}",
                    lock_path.display(),
                    e
                ));
            }
        }

        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
        {
            Ok(f) => f,
            Err(e) => {
                release_in_process();
                return Err(format!(
                    "Failed to open lockfile {}: {}",
                    lock_path.display(),
                    e
                ));
            }
        };

        // 3. Acquire OS-level exclusive advisory lock
        let mut backoff = Duration::from_millis(10);
        let max_backoff = Duration::from_millis(50);

        loop {
            match file.try_lock() {
                Ok(()) => {
                    return Ok(FileLock {
                        file,
                        lock_path: norm_path,
                    });
                }
                Err(e) => {
                    if start.elapsed() >= timeout {
                        release_in_process();
                        return Err(format!(
                            "Timeout acquiring OS file lock on {}: {:?}",
                            lock_path.display(),
                            e
                        ));
                    }
                    std::thread::sleep(backoff);
                    backoff = std::cmp::min(backoff * 2, max_backoff);
                }
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // Unlock OS file lock
        let _ = self.file.unlock();

        // Release in-process lock
        if let Some((lock, cvar)) = LOCK_MANAGER.get() {
            if let Ok(mut set) = lock.lock() {
                set.remove(&self.lock_path);
                cvar.notify_all();
            }
        }
    }
}

/// Atomically writes content to a temporary file in the same directory and renames it to `target_path`.
/// Handles cross-process/cross-thread uniqueness, 0600 permissions on Unix, and Windows rename retries.
pub fn atomic_write_and_rename(target_path: &Path, content: &[u8]) -> Result<(), String> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let parent = target_path.parent().ok_or_else(|| {
        format!(
            "Invalid target path with no parent: {}",
            target_path.display()
        )
    })?;
    fs::create_dir_all(parent).map_err(|e| {
        format!(
            "Failed to create parent directory {}: {}",
            parent.display(),
            e
        )
    })?;

    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let file_name = target_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config");
    let tmp_path = parent.join(format!(".{}.{}_{}.tmp", file_name, pid, counter));

    // Write content to temporary file
    fs::write(&tmp_path, content).map_err(|e| {
        format!(
            "Failed to write temporary file {}: {}",
            tmp_path.display(),
            e
        )
    })?;

    // Layer 1: Restrict permissions to 0600 on Unix (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
    }

    // Atomic rename with retries for Windows file-sharing transient locks
    let mut rename_result = fs::rename(&tmp_path, target_path);
    if rename_result.is_err() {
        for _ in 0..10 {
            std::thread::sleep(Duration::from_millis(10));
            rename_result = fs::rename(&tmp_path, target_path);
            if rename_result.is_ok() {
                break;
            }
        }
    }

    if let Err(e) = rename_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!(
            "Failed to atomically rename {} to {}: {}",
            tmp_path.display(),
            target_path.display(),
            e
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_file_lock_mutual_exclusion() {
        let temp_dir = std::env::temp_dir().join(format!("mcp_lock_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let lock_path = temp_dir.join("test.lock");

        let lock1 = FileLock::acquire(&lock_path).expect("First lock should succeed");

        let shared_val = Arc::new(Mutex::new(0));
        let val_clone = shared_val.clone();
        let path_clone = lock_path.clone();

        let handle = thread::spawn(move || {
            let _lock2 = FileLock::acquire(&path_clone)
                .expect("Second lock should succeed after lock1 drops");
            let mut v = val_clone.lock().unwrap();
            *v = 42;
        });

        // Sleep to ensure child thread attempts to lock and blocks
        thread::sleep(Duration::from_millis(100));
        assert_eq!(*shared_val.lock().unwrap(), 0);

        // Drop lock1 to unblock child thread
        drop(lock1);

        handle.join().unwrap();
        assert_eq!(*shared_val.lock().unwrap(), 42);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_atomic_write_and_rename() {
        let temp_dir = std::env::temp_dir().join(format!("mcp_atomic_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let file_path = temp_dir.join("target.json");

        atomic_write_and_rename(&file_path, b"{\"hello\": \"world\"}").unwrap();
        let read = fs::read_to_string(&file_path).unwrap();
        assert_eq!(read, "{\"hello\": \"world\"}");

        // Overwrite
        atomic_write_and_rename(&file_path, b"{\"hello\": \"updated\"}").unwrap();
        let read2 = fs::read_to_string(&file_path).unwrap();
        assert_eq!(read2, "{\"hello\": \"updated\"}");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
