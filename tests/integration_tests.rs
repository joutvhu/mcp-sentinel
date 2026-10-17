use std::process::Command;

#[test]
fn test_cli_help_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .arg("--help")
        .output()
        .expect("Failed to execute mcp-sentinel --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("mcp-sentinel isolates environment variables"));
    assert!(stdout.contains("run"));
    assert!(stdout.contains("secrets"));
    assert!(stdout.contains("permissions"));
    assert!(stdout.contains("ui"));
}

#[test]
fn test_cli_ui_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .args(["ui", "--help"])
        .output()
        .expect("Failed to execute mcp-sentinel ui --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Terminal User Interface"));

    // Also test alias "tui"
    let output_tui = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .args(["tui", "--help"])
        .output()
        .expect("Failed to execute mcp-sentinel tui --help");
    assert!(output_tui.status.success());
}

#[test]
fn test_cli_version_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .arg("--version")
        .output()
        .expect("Failed to execute mcp-sentinel --version");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(concat!("mcp-sentinel ", env!("CARGO_PKG_VERSION"))));
}

#[test]
fn test_cli_run_without_command_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .arg("run")
        .output()
        .expect("Failed to execute mcp-sentinel run");

    // Must fail because <CMD> is required
    assert!(!output.status.success());
}

#[test]
fn test_cli_permissions_list() {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .args(["permissions", "list"])
        .output()
        .expect("Failed to execute mcp-sentinel permissions list");

    assert!(output.status.success());
}

#[test]
fn test_cli_secret_list() {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .args(["secret", "list"])
        .output()
        .expect("Failed to execute mcp-sentinel secret list");

    assert!(output.status.success());

    // Test official plural form 'secrets'
    let output_plural = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .args(["secrets", "list"])
        .output()
        .expect("Failed to execute mcp-sentinel secrets list");

    assert!(output_plural.status.success());
}
