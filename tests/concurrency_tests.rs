use mcp_sentinel::policy::{compute_fingerprint, load_policy, record_grant};
use mcp_sentinel::tool_policy::{self, ToolProfile};
use mcp_sentinel::vault;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn setup_temp_config_dir(prefix: &str) -> PathBuf {
    let temp_dir =
        std::env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), fastrand()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("Failed to create temp config dir");
    std::env::set_var("MCP_SENTINEL_CONFIG_DIR", &temp_dir);
    std::env::set_var("MCP_SENTINEL_ALLOW_INSECURE_KEYFILE", "1");
    std::env::set_var("MCP_SENTINEL_MOCK_KEYRING_UNAVAILABLE", "1");
    temp_dir
}

fn fastrand() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

#[test]
fn test_concurrent_policy_record_grant() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp_dir = setup_temp_config_dir("mcp_test_policy_concurrent");

    let cmd = vec!["server".to_string(), "--opt".to_string()];
    let fp = compute_fingerprint(&cmd);

    let num_threads = 30;
    let mut handles = Vec::new();
    let errors = Arc::new(Mutex::new(Vec::new()));

    for i in 0..num_threads {
        let fp_clone = fp.clone();
        let cmd_clone = cmd.clone();
        let errs = errors.clone();

        handles.push(thread::spawn(move || {
            let secret = format!("SECRET_{:02}", i);
            if let Err(e) = record_grant(&fp_clone, Some("test".to_string()), &cmd_clone, &[secret])
            {
                errs.lock().unwrap().push(e);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert!(
        errors.lock().unwrap().is_empty(),
        "Some threads failed to record grant: {:?}",
        *errors.lock().unwrap()
    );

    let policy = load_policy();
    let grant = policy.grants.get(&fp).expect("Grant entry must exist");

    assert_eq!(
        grant.granted_secrets.len(),
        num_threads,
        "All 30 secrets must be successfully merged"
    );

    for i in 0..num_threads {
        let expected = format!("SECRET_{:02}", i);
        assert!(
            grant.granted_secrets.contains(&expected),
            "Missing secret: {}",
            expected
        );
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_concurrent_vault_register_keys() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp_dir = setup_temp_config_dir("mcp_test_vault_concurrent");

    let num_threads = 30;
    let mut handles = Vec::new();

    for i in 0..num_threads {
        handles.push(thread::spawn(move || {
            let key = format!("KEY_{:02}", i);
            vault::register_key(&key);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let keys = vault::list_keys();
    assert_eq!(
        keys.len(),
        num_threads,
        "All 30 keys must be present without lost updates"
    );

    for i in 0..num_threads {
        let expected = format!("KEY_{:02}", i);
        assert!(keys.contains(&expected), "Missing key: {}", expected);
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_concurrent_tool_policy_upsert() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp_dir = setup_temp_config_dir("mcp_test_tool_upsert_concurrent");

    // Initialize defaults first
    let initial = tool_policy::load_profiles().expect("Failed to initialize tool policy");
    assert!(initial.profiles.contains_key("read-only"));

    let num_threads = 20;
    let mut handles = Vec::new();
    let errors = Arc::new(Mutex::new(Vec::new()));

    for i in 0..num_threads {
        let errs = errors.clone();
        handles.push(thread::spawn(move || {
            let profile = ToolProfile {
                name: format!("profile_{:02}", i),
                description: Some(format!("Custom profile {}", i)),
                allow: vec![format!("tool_{:02}", i)],
                deny: vec![],
            };
            if let Err(e) = tool_policy::upsert_profile(profile) {
                errs.lock().unwrap().push(e);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert!(
        errors.lock().unwrap().is_empty(),
        "Upsert profile threads had errors: {:?}",
        *errors.lock().unwrap()
    );

    let final_profiles = tool_policy::load_profiles().expect("Must load updated profiles");
    assert!(final_profiles.profiles.contains_key("read-only"));
    assert!(final_profiles.profiles.contains_key("no-destructive"));

    for i in 0..num_threads {
        let name = format!("profile_{:02}", i);
        assert!(
            final_profiles.profiles.contains_key(&name),
            "Missing profile: {}",
            name
        );
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_concurrent_tool_policy_initialization() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp_dir = setup_temp_config_dir("mcp_test_tool_init_concurrent");

    let num_threads = 20;
    let mut handles = Vec::new();
    let errors = Arc::new(Mutex::new(Vec::new()));

    for _ in 0..num_threads {
        let errs = errors.clone();
        handles.push(thread::spawn(move || match tool_policy::load_profiles() {
            Ok(file) => {
                if !file.profiles.contains_key("read-only") {
                    errs.lock()
                        .unwrap()
                        .push("Missing read-only profile".to_string());
                }
            }
            Err(e) => {
                errs.lock().unwrap().push(e);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert!(
        errors.lock().unwrap().is_empty(),
        "Initialization threads failed: {:?}",
        *errors.lock().unwrap()
    );

    let p = tool_policy::get_tool_policies_file_path().unwrap();
    assert!(
        p.exists(),
        "tool_policies.json must exist after initialization"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_concurrent_audit_logging() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp_dir = setup_temp_config_dir("mcp_test_audit_concurrent");

    let num_threads = 30;
    let mut handles = Vec::new();
    let errors = Arc::new(Mutex::new(Vec::new()));

    for i in 0..num_threads {
        let errs = errors.clone();
        handles.push(thread::spawn(move || {
            let entry = mcp_sentinel::audit::AuditEntry {
                timestamp: chrono::Utc::now(),
                event: mcp_sentinel::audit::AuditEventType::ToolCallAllowed,
                server_name: Some(format!("server_{:02}", i)),
                command: Some("test command".to_string()),
                tool_name: Some(format!("tool_{:02}", i)),
                decision: Some("ALLOW".to_string()),
                reason: None,
                secrets: None,
                profile: None,
                exit_code: None,
            };
            if let Err(e) = mcp_sentinel::audit::log_event(&entry) {
                errs.lock().unwrap().push(e);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert!(
        errors.lock().unwrap().is_empty(),
        "Audit log threads failed: {:?}",
        *errors.lock().unwrap()
    );

    let entries =
        mcp_sentinel::audit::read_entries(100, None, false).expect("Must read audit entries");
    assert_eq!(
        entries.len(),
        num_threads,
        "All {} entries must be written without data corruption or lost lines",
        num_threads
    );

    let _ = fs::remove_dir_all(&temp_dir);
}
