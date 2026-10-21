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
fn test_cli_run_pass_env() {
    let (cmd, args) = if which::which("node").is_ok() {
        (
            "node",
            vec![
                "-e",
                "console.log('PORT:' + process.env.SENTINEL_INTEG_TEST_PORT);",
            ],
        )
    } else {
        (
            "python3",
            vec![
                "-c",
                "import os; print('PORT:' + os.environ.get('SENTINEL_INTEG_TEST_PORT', ''))",
            ],
        )
    };

    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("SENTINEL_INTEG_TEST_PORT", "4000")
        .args(["run", "--pass-env", "SENTINEL_INTEG_TEST_PORT", "--", cmd])
        .args(&args)
        .output()
        .expect("Failed to execute mcp-sentinel run with --pass-env");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PORT:4000"));
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
        .env("MCP_SENTINEL_BYPASS_JOB_CHECK", "1")
        .args(["secret", "list"])
        .output()
        .expect("Failed to execute mcp-sentinel secret list");

    assert!(output.status.success());

    // Test official plural form 'secrets'
    let output_plural = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_BYPASS_JOB_CHECK", "1")
        .args(["secrets", "list"])
        .output()
        .expect("Failed to execute mcp-sentinel secrets list");

    assert!(output_plural.status.success());
}

#[test]
fn test_cli_migrate_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .args(["migrate", "--help"])
        .output()
        .expect("Failed to execute mcp-sentinel migrate --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Migrate existing plaintext MCP configurations"));
    assert!(stdout.contains("--dry-run"));
    assert!(stdout.contains("--file"));
}

#[test]
fn test_cli_migrate_file_end_to_end() {
    use std::fs;
    let temp_dir = std::env::temp_dir().join(format!("mcp_test_migrate_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let config_file = temp_dir.join("test_mcp_config.json");

    let initial_content = r#"{
        "mcpServers": {
            "test_sqlite": {
                "command": "python",
                "args": ["-m", "sqlite_server"],
                "env": {
                    "SQLITE_DB_KEY": "sqlite_secret_token_123"
                }
            }
        }
    }"#;
    fs::write(&config_file, initial_content).unwrap();

    // 1. Dry run
    let output_dry = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_CONFIG_DIR", &temp_dir)
        .env("MCP_SENTINEL_ALLOW_INSECURE_KEYFILE", "1")
        .env("MCP_SENTINEL_MOCK_KEYRING_UNAVAILABLE", "1")
        .env("MCP_SENTINEL_NON_INTERACTIVE", "1")
        .args([
            "migrate",
            "--file",
            config_file.to_str().unwrap(),
            "--dry-run",
        ])
        .output()
        .expect("Failed to run migrate --dry-run");

    assert!(output_dry.status.success());
    let stdout_dry = String::from_utf8_lossy(&output_dry.stdout);
    assert!(stdout_dry.contains("DRY-RUN mode"));
    assert!(stdout_dry.contains("test_sqlite"));

    // File content should remain unchanged after dry-run
    let content_after_dry = fs::read_to_string(&config_file).unwrap();
    assert_eq!(content_after_dry, initial_content);

    // 2. Real migration
    let output_real = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_CONFIG_DIR", &temp_dir)
        .env("MCP_SENTINEL_ALLOW_INSECURE_KEYFILE", "1")
        .env("MCP_SENTINEL_MOCK_KEYRING_UNAVAILABLE", "1")
        .env("MCP_SENTINEL_NON_INTERACTIVE", "1")
        .args(["migrate", "--file", config_file.to_str().unwrap()])
        .output()
        .expect("Failed to run migrate");

    assert!(output_real.status.success());
    let stdout_real = String::from_utf8_lossy(&output_real.stdout);
    assert!(stdout_real.contains("Created backup at"));
    assert!(stdout_real.contains("Migration complete"));

    // Check backup file exists
    let backup_file = temp_dir.join("test_mcp_config.json.bak");
    assert!(backup_file.exists());
    assert_eq!(fs::read_to_string(&backup_file).unwrap(), initial_content);

    // Check migrated content
    let content_migrated = fs::read_to_string(&config_file).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content_migrated).unwrap();
    let server = &parsed["mcpServers"]["test_sqlite"];
    let cmd_str = server["command"].as_str().unwrap();
    assert!(
        cmd_str == "mcp-sentinel"
            || cmd_str.ends_with("/mcp-sentinel")
            || cmd_str.ends_with("\\mcp-sentinel")
            || cmd_str.ends_with("/mcp-sentinel.exe")
            || cmd_str.ends_with("\\mcp-sentinel.exe"),
        "Migrated command must be mcp-sentinel or full binary path! Got: {}",
        cmd_str
    );
    assert!(server.get("env").is_none());

    let args = server["args"].as_array().unwrap();
    assert_eq!(args[0], "run");
    assert_eq!(args[1], "--name");
    assert_eq!(args[2], "test_sqlite MCP Server");
    assert_eq!(args[3], "--secrets");
    assert_eq!(args[4], "SQLITE_DB_KEY");

    // Clean up
    let _ = fs::remove_file(&config_file);
    let _ = fs::remove_file(&backup_file);
    let _ = fs::remove_dir_all(&temp_dir);
}
