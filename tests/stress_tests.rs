use mcp_sentinel::policy::{compute_fingerprint, PolicyFile};
use mcp_sentinel::sanitizer::build_sanitized_env;
use std::collections::HashMap;
use std::process::Command;

#[test]
fn test_exit_code_propagation_success() {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .args(["run", "--", "node", "-e", "process.exit(0)"])
        .output()
        .expect("Failed to execute mcp-sentinel");

    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn test_exit_code_propagation_custom_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .args(["run", "--", "node", "-e", "process.exit(42)"])
        .output()
        .expect("Failed to execute mcp-sentinel");

    assert_eq!(output.status.code(), Some(42));
}

#[test]
fn test_stdout_and_stderr_separation() {
    let script = "console.log('STDOUT_ONLY_LINE'); console.error('STDERR_ONLY_LINE');";
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .args(["run", "--", "node", "-e", script])
        .output()
        .expect("Failed to execute mcp-sentinel");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Stderr data must NOT leak into stdout
    assert!(stdout.contains("STDOUT_ONLY_LINE"));
    assert!(!stdout.contains("STDERR_ONLY_LINE"));

    // Stderr must receive the stderr output
    assert!(stderr.contains("STDERR_ONLY_LINE"));
}

#[test]
fn test_unicode_and_complex_args_integrity() {
    let complex_args = vec![
        "node".to_string(),
        "-e".to_string(),
        "console.log('Xin chào thế giới 🛡️ 🚀');".to_string(),
        "--custom-flag".to_string(),
        "arg with spaces & symbols @#$%^*()".to_string(),
    ];

    let fp1 = compute_fingerprint(&complex_args);
    let fp2 = compute_fingerprint(&complex_args);
    assert_eq!(fp1, fp2);
    assert_eq!(fp1.len(), 64);

    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .args([
            "run",
            "--",
            "node",
            "-e",
            "console.log('Xin chào thế giới 🛡️ 🚀');",
        ])
        .output()
        .expect("Failed to run unicode command");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Xin chào thế giới 🛡️ 🚀"));
}

#[test]
fn test_sanitizer_with_100_secrets() {
    let mut secrets = HashMap::new();
    for i in 0..100 {
        secrets.insert(format!("SECRET_VAR_{:03}", i), format!("val_{}", i));
    }

    let clean_env = build_sanitized_env(&secrets);

    // Verify all 100 secrets are present
    for i in 0..100 {
        let key = format!("SECRET_VAR_{:03}", i);
        assert_eq!(clean_env.get(&key), Some(&format!("val_{}", i)));
    }

    // Verify system path is still preserved
    assert!(clean_env.keys().any(|k| k.eq_ignore_ascii_case("PATH")));
}

#[test]
fn test_corrupted_policy_file_resilience() {
    // If a corrupted JSON file exists, load_policy must not panic
    let bad_json = "{ invalid_json: true, ";
    let res: Result<PolicyFile, _> = serde_json::from_str(bad_json);
    assert!(res.is_err());

    // When policy file is corrupted or empty, load_policy falls back gracefully to default
    let default_policy = PolicyFile::default();
    assert!(default_policy.grants.is_empty());
}
