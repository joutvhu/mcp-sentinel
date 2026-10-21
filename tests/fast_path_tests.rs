use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn setup_temp_config_dir(prefix: &str) -> PathBuf {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temp_dir =
        std::env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), nanos));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("Failed to create temp config dir");
    temp_dir
}

fn get_test_server_command() -> (&'static str, Vec<String>) {
    if which::which("node").is_ok() {
        (
            "node",
            vec![
                "-e".to_string(),
                r#"
                    const readline = require('readline');
                    const rl = readline.createInterface({ input: process.stdin, terminal: false });
                    rl.on('line', (line) => {
                        console.log("RECEIVED:" + line);
                    });
                    rl.on('close', () => {
                        process.exit(0);
                    });
                "#
                .to_string(),
            ],
        )
    } else {
        (
            "python3",
            vec![
                "-u".to_string(),
                "-c".to_string(),
                r#"
import sys
for line in sys.stdin:
    line = line.rstrip('\r\n')
    print("RECEIVED:" + line, flush=True)
"#
                .to_string(),
            ],
        )
    }
}

#[test]
fn test_fast_path_allowed_request_preserves_raw_formatting_and_large_int() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = setup_temp_config_dir("mcp_test_fp_single");

    let (server_bin, server_args) = get_test_server_command();

    let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_CONFIG_DIR", &temp_dir)
        .env("MCP_SENTINEL_ALLOW_INSECURE_KEYFILE", "1")
        .env("MCP_SENTINEL_MOCK_KEYRING_UNAVAILABLE", "1")
        .env("MCP_SENTINEL_NON_INTERACTIVE", "1")
        .args(["run", "--profile", "read-only", "--", server_bin])
        .args(&server_args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn mcp-sentinel");

    // Deliberately ordered keys: params first, then method, then id, then jsonrpc
    // ID is 9007199254740993 (2^53 + 1, which loses precision if parsed as f64)
    let raw_request = r#"{"params":{"name":"read_data","args":{"z":1,"a":2}},"method":"tools/call","id":9007199254740993,"jsonrpc":"2.0"}"#;

    {
        let mut stdin = child.stdin.take().expect("Failed to open child stdin");
        stdin
            .write_all(format!("{}\n", raw_request).as_bytes())
            .expect("Failed to write to stdin");
        stdin.flush().expect("Failed to flush stdin");
        drop(stdin);
    }

    let output = child.wait_with_output().expect("Failed to wait for child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.contains(&format!("RECEIVED:{}", raw_request)),
        "Fast-path must forward raw slice verbatim without re-serialization!\nExpected: RECEIVED:{}\nActual stdout: {}\nActual stderr: {}\nExit status: {:?}",
        raw_request,
        stdout,
        stderr,
        output.status
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_fast_path_batch_all_allowed_preserves_raw_bytes() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = setup_temp_config_dir("mcp_test_fp_batch");

    let (server_bin, server_args) = get_test_server_command();

    let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_CONFIG_DIR", &temp_dir)
        .env("MCP_SENTINEL_ALLOW_INSECURE_KEYFILE", "1")
        .env("MCP_SENTINEL_MOCK_KEYRING_UNAVAILABLE", "1")
        .env("MCP_SENTINEL_NON_INTERACTIVE", "1")
        .args(["run", "--profile", "read-only", "--", server_bin])
        .args(&server_args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn mcp-sentinel");

    let raw_batch = r#"[{"id":"id-beta","jsonrpc":"2.0","method":"tools/call","params":{"name":"read_records"}},{"id":"id-alpha","jsonrpc":"2.0","method":"tools/call","params":{"name":"query_status"}}]"#;

    {
        let mut stdin = child.stdin.take().expect("Failed to open child stdin");
        stdin
            .write_all(format!("{}\n", raw_batch).as_bytes())
            .expect("Failed to write to stdin");
        stdin.flush().expect("Failed to flush stdin");
        drop(stdin);
    }

    let output = child.wait_with_output().expect("Failed to wait for child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.contains(&format!("RECEIVED:{}", raw_batch)),
        "Fast-path must forward allowed batch verbatim without re-serialization!\nExpected: RECEIVED:{}\nActual stdout: {}\nActual stderr: {}\nExit status: {:?}",
        raw_batch,
        stdout,
        stderr,
        output.status
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_mixed_batch_filters_blocked_and_reserializes_allowed() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = setup_temp_config_dir("mcp_test_fp_mixed");

    let (server_bin, server_args) = get_test_server_command();

    let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_CONFIG_DIR", &temp_dir)
        .env("MCP_SENTINEL_ALLOW_INSECURE_KEYFILE", "1")
        .env("MCP_SENTINEL_MOCK_KEYRING_UNAVAILABLE", "1")
        .env("MCP_SENTINEL_NON_INTERACTIVE", "1")
        .args(["run", "--profile", "read-only", "--", server_bin])
        .args(&server_args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn mcp-sentinel");

    // Item 1 is allowed ('read_ok'), Item 2 is blocked ('drop_table')
    let mixed_batch = r#"[{"id":101,"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_ok"}},{"id":102,"jsonrpc":"2.0","method":"tools/call","params":{"name":"drop_table"}}]"#;

    {
        let mut stdin = child.stdin.take().expect("Failed to open child stdin");
        stdin
            .write_all(format!("{}\n", mixed_batch).as_bytes())
            .expect("Failed to write to stdin");
        stdin.flush().expect("Failed to flush stdin");
        drop(stdin);
    }

    let output = child.wait_with_output().expect("Failed to wait for child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // 1. Host stdout receives the synthetic error for id 102
    assert!(
        stdout.contains("\"code\":-32001") && stdout.contains("drop_table"),
        "Host stdout must receive error for blocked call: {}\nStderr: {}",
        stdout,
        stderr
    );

    // 2. Child process receives only the allowed call id 101
    assert!(
        stdout.contains("RECEIVED:") && stdout.contains("\"read_ok\""),
        "Child process must receive the allowed call: {}\nStderr: {}",
        stdout,
        stderr
    );

    // 3. Child process NEVER receives drop_table
    assert!(
        !stdout.contains("RECEIVED:")
            || !stdout
                .split("RECEIVED:")
                .skip(1)
                .any(|chunk| chunk.contains("drop_table")),
        "Child process must NEVER receive blocked drop_table call: {}\nStderr: {}",
        stdout,
        stderr
    );

    let _ = fs::remove_dir_all(&temp_dir);
}
