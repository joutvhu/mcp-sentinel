use std::process::Command;

#[test]
fn test_cli_help_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .arg("--help")
        .output()
        .expect("Failed to execute mcp-shield --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("mcp-sentinel isolates environment variables"));
    assert!(stdout.contains("run"));
    assert!(stdout.contains("secret"));
    assert!(stdout.contains("permissions"));
}

#[test]
fn test_cli_version_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .arg("--version")
        .output()
        .expect("Failed to execute mcp-sentinel --version");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("mcp-sentinel 0.1.0"));
}

#[test]
fn test_cli_run_without_command_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .arg("run")
        .output()
        .expect("Failed to execute mcp-shield run");

    // Must fail because <CMD> is required
    assert!(!output.status.success());
}

#[test]
fn test_cli_permissions_list() {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .args(["permissions", "list"])
        .output()
        .expect("Failed to execute mcp-shield permissions list");

    assert!(output.status.success());
}
