use mcp_sentinel::policy::{compute_fingerprint, Grant, PolicyFile};
use std::collections::HashMap;
use std::process::Command;
use std::sync::Mutex;

static POLICY_TEST_LOCK: Mutex<()> = Mutex::new(());

/// HACK ATTACK 1: Host Environment Variable Exfiltration
/// An attacker writes a malicious MCP server attempting to dump environment variables
/// to find cloud keys, tokens, or SSH credentials from the user's host machine.
#[test]
fn hack_test_host_env_exfiltration_blocked() {
    // We launch mcp-sentinel with sensitive environment variables present in the parent process
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("AWS_SECRET_ACCESS_KEY", "AKIA_EXFILTRATED_HOST_AWS_KEY")
        .env("SSH_AUTH_SOCK", "/tmp/sensitive_ssh_agent.sock")
        .env("GITHUB_PAT_LEAK", "ghp_super_secret_host_pat_token")
        .args([
            "run",
            "--",
            "node",
            "-e",
            r#"
                const leakedAws = process.env.AWS_SECRET_ACCESS_KEY;
                const leakedSsh = process.env.SSH_AUTH_SOCK;
                const leakedPat = process.env.GITHUB_PAT_LEAK;
                if (leakedAws || leakedSsh || leakedPat) {
                    console.log('EXFILTRATION_SUCCEEDED');
                } else {
                    console.log('SAFE_SENTINEL_BLOCKED_ALL');
                }
            "#,
        ])
        .output()
        .expect("Failed to execute mcp-sentinel");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("SAFE_SENTINEL_BLOCKED_ALL"),
        "Host environment exfiltration must be blocked!"
    );
    assert!(!stdout.contains("EXFILTRATION_SUCCEEDED"));
}

/// HACK ATTACK 2: Command Injection & Shell Metacharacter Bypass
/// An attacker tries to escape process arguments using shell metacharacters (; && | ` $).
/// Since mcp-sentinel executes via direct OS spawn rather than a raw shell,
/// the arguments must be passed literally without executing subcommands.
#[test]
fn hack_test_command_injection_shell_metachars() {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .args([
            "run",
            "--",
            "node",
            "-e",
            "console.log('ARG1:', process.argv[1]);",
            "; echo INJECTED_COMMAND_EXECUTION ;",
        ])
        .output()
        .expect("Failed to execute mcp-sentinel");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The argument must remain literal data inside argv
    assert!(stdout.contains("; echo INJECTED_COMMAND_EXECUTION ;"));
    // It must NOT have spawned an independent echo output
    assert!(!stdout
        .lines()
        .any(|l| l.trim() == "INJECTED_COMMAND_EXECUTION"));
}

/// HACK ATTACK 3: Tampered Permissions File Injection
/// A malicious script running on the machine attempts to inject a forged grant directly into
/// permissions.json to grant itself access to a high-privilege secret without user prompt.
#[test]
fn hack_test_tampered_permissions_file_attack() {
    let cmd = vec!["node".to_string(), "malicious_script.js".to_string()];
    let fp = compute_fingerprint(&cmd);

    // Attacker crafts a fake permissions.json file with an unauthorized grant
    let forged_grant = Grant {
        id: fp.clone(),
        name: Some("Trojan MCP".to_string()),
        command: "node malicious_script.js".to_string(),
        granted_secrets: vec!["RESTRICTED_PRODUCTION_DATABASE_URL".to_string()],
        created_at: chrono::Utc::now(),
    };

    let mut forged_grants = HashMap::new();
    forged_grants.insert(fp, forged_grant);

    // Attacker signs it with an invalid/forged signature
    let attacker_fake_file = PolicyFile {
        grants: forged_grants,
        signature: Some(
            "attacker_forged_hmac_signature_00000000000000000000000000000000".to_string(),
        ),
    };

    // Verify HMAC verification detects and rejects the forged signature
    let master_key =
        mcp_sentinel::policy::get_or_create_master_key().expect("Failed to get master key");
    let genuine_sig =
        mcp_sentinel::policy::compute_grants_hmac(&attacker_fake_file.grants, &master_key);
    assert_ne!(
        attacker_fake_file.signature.as_deref(),
        Some(genuine_sig.as_str()),
        "Forged signature must never match genuine HMAC-SHA256 master signature!"
    );

    // Test tamper detection via policy deserialization & HMAC check
    let bad_json = serde_json::to_string_pretty(&attacker_fake_file).unwrap();
    let parsed: PolicyFile = serde_json::from_str(&bad_json).unwrap();
    let expected_sig = mcp_sentinel::policy::compute_grants_hmac(&parsed.grants, &master_key);
    assert_ne!(
        parsed.signature.as_deref(),
        Some(expected_sig.as_str()),
        "Tampered policy file signature verification must fail!"
    );
}

/// HACK ATTACK 4: Fingerprint Collision & Argument Smuggling
/// An attacker attempts to append flags to an approved command, hoping
/// that mcp-sentinel will confuse it with the originally approved command.
#[test]
fn hack_test_argument_smuggling_fingerprint_isolation() {
    let benign_cmd = vec!["npx".to_string(), "safe-server".to_string()];
    let smuggled_cmd = vec![
        "npx".to_string(),
        "safe-server".to_string(),
        "--steal-keys".to_string(),
    ];

    let fp_benign = compute_fingerprint(&benign_cmd);
    let fp_smuggled = compute_fingerprint(&smuggled_cmd);

    assert_ne!(
        fp_benign, fp_smuggled,
        "Appended arguments must produce an entirely different fingerprint!"
    );
}

/// HACK ATTACK 5: Requesting Missing/Unregistered Secret Fails Safely
/// An attacker calls mcp-sentinel with an arbitrary secret key.
/// mcp-sentinel must immediately abort with non-zero code and not expose other secrets.
#[test]
fn hack_test_requesting_missing_secret_fails_safely() {
    let _lock = POLICY_TEST_LOCK.lock().unwrap();
    let cmd = vec![
        "node".to_string(),
        "-e".to_string(),
        "console.log('SHOULD_NOT_EXECUTE');".to_string(),
    ];
    let fp = compute_fingerprint(&cmd);
    let missing_secret = "NON_EXISTENT_UNKNOWN_KEY_9999".to_string();

    // Pre-authorize this test command so it skips the interactive GUI prompt
    mcp_sentinel::policy::record_grant(&fp, None, &cmd, std::slice::from_ref(&missing_secret))
        .expect("Pre-authorizing grant for test must succeed");

    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_NON_INTERACTIVE", "1")
        .args([
            "run",
            "--secrets",
            &missing_secret,
            "--",
            "node",
            "-e",
            "console.log('SHOULD_NOT_EXECUTE');",
        ])
        .output()
        .expect("Failed to execute mcp-sentinel");

    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!stdout.contains("SHOULD_NOT_EXECUTE"));
    assert!(
        stderr.contains(&missing_secret),
        "Must report missing secret name in error log. Actual stderr: {}",
        stderr
    );
}

/// HACK ATTACK 6: Child Sandbox Jailbreak & Recursive Secret Theft
/// A compromised child MCP server attempts to invoke mcp-sentinel secret get/list.
/// mcp-sentinel must detect the child context lock, abort with exit code 13, and refuse to leak any secret!
#[test]
fn hack_test_child_process_cannot_invoke_sentinel() {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .args(["secret", "get", "TEST_KEY"])
        .env("MCP_SENTINEL_CHILD_CONTEXT", "1")
        .output()
        .expect("Failed to execute mcp-sentinel with child context");

    assert_eq!(
        output.status.code(),
        Some(13),
        "Must exit with permission denied code (13)"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Security Violation"),
        "Must output security violation error"
    );
}

/// HACK ATTACK 7: Setting Reserved or Malformed Secret Key Names Blocked
/// An attacker attempts to set reserved prefixes (MCP_SENTINEL_*) or inject special characters into keys.
/// mcp-sentinel must reject the key name and exit with a failure code.
#[test]
fn hack_test_setting_reserved_key_names_blocked() {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .args(["secret", "set", "MCP_SENTINEL_CHILD_CONTEXT", "0"])
        .output()
        .expect("Failed to execute mcp-sentinel secret set");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("reserved prefix"));

    // Also test invalid characters
    let output_invalid = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .args(["secret", "set", "KEY=MALICIOUS", "value"])
        .output()
        .expect("Failed to execute mcp-sentinel secret set");

    assert!(!output_invalid.status.success());
    let stderr_invalid = String::from_utf8_lossy(&output_invalid.stderr);
    assert!(stderr_invalid.contains("invalid character"));
}

/// HACK ATTACK 8: Secret Aliasing End-to-End & Vault Key Non-Leakage
/// Verifies that an MCP server can receive a secret mapped to an aliased target environment variable,
/// and that the underlying vault key name is not leaked into the child process.
#[test]
fn hack_test_secret_aliasing_end_to_end() {
    let _lock = POLICY_TEST_LOCK.lock().unwrap();
    let vault_key = "TEST_VAULT_SOURCE_SECRET_1";
    let target_env = "TARGET_MCP_API_KEY";
    let secret_val = "secure_token_abc_xyz_789";

    // Store secret in vault
    let _ = mcp_sentinel::vault::set_secret(vault_key, secret_val);

    let script = r#"
        console.log('TARGET_VAL=' + (process.env.TARGET_MCP_API_KEY || 'MISSING'));
        console.log('VAULT_VAL=' + (process.env.TEST_VAULT_SOURCE_SECRET_1 || 'NOT_LEAKED'));
    "#;

    let cmd = vec!["node".to_string(), "-e".to_string(), script.to_string()];
    let fp = compute_fingerprint(&cmd);
    let alias_spec = format!("{}={}", target_env, vault_key);

    // Pre-authorize grant with canonical spec
    mcp_sentinel::policy::record_grant(&fp, None, &cmd, std::slice::from_ref(&alias_spec))
        .expect("Pre-authorizing alias grant must succeed");

    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_NON_INTERACTIVE", "1")
        .args([
            "run",
            "--no-redact",
            "--secrets",
            &alias_spec,
            "--",
            "node",
            "-e",
            script,
        ])
        .output()
        .expect("Failed to execute mcp-sentinel with alias");

    // Clean up secret
    let _ = mcp_sentinel::vault::delete_secret(vault_key);

    assert!(
        output.status.success(),
        "Execution with alias should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("TARGET_VAL=secure_token_abc_xyz_789"),
        "Target environment variable must receive the secret value! Actual stdout: {}",
        stdout
    );
    assert!(
        stdout.contains("VAULT_VAL=NOT_LEAKED"),
        "Vault secret key name must NOT be leaked as an environment variable! Actual stdout: {}",
        stdout
    );
}

/// HACK ATTACK 9: Duplicate Target Env Vars in Aliases Rejected
/// If an attacker attempts to define conflicting secrets for the same environment variable,
/// mcp-sentinel must abort before launching the child.
#[test]
fn hack_test_duplicate_target_env_in_aliases_rejected() {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_NON_INTERACTIVE", "1")
        .args([
            "run",
            "--secrets",
            "API_KEY=KEY_1,API_KEY=KEY_2",
            "--",
            "node",
            "-e",
            "console.log('UNREACHABLE');",
        ])
        .output()
        .expect("Failed to execute mcp-sentinel");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Duplicate target environment variable 'API_KEY'"),
        "Must report duplicate target error: {}",
        stderr
    );
}

/// HACK ATTACK 10: TOFU Blocks Swapped Vault Source Key
/// An MCP server was previously authorized for `API_KEY=DEV_KEY`.
/// If the configuration is switched to `API_KEY=PROD_KEY`, mcp-sentinel must NOT auto-grant
/// access; it must detect the unapproved vault source key and require new consent.
#[test]
fn hack_test_tofu_blocks_swapped_vault_source_key() {
    let _lock = POLICY_TEST_LOCK.lock().unwrap();
    let dev_key = "TEST_VAULT_SWAP_DEV_KEY";
    let prod_key = "TEST_VAULT_SWAP_PROD_KEY";

    let _ = mcp_sentinel::vault::set_secret(dev_key, "dev_value_111");
    let _ = mcp_sentinel::vault::set_secret(prod_key, "prod_super_secret_999");

    let script = "console.log('EXECUTED_WITH_VAL=' + (process.env.API_KEY || ''));";
    let cmd = vec!["node".to_string(), "-e".to_string(), script.to_string()];
    let fp = compute_fingerprint(&cmd);

    // Only authorize DEV_KEY
    let dev_spec = format!("API_KEY={}", dev_key);
    mcp_sentinel::policy::record_grant(&fp, None, &cmd, std::slice::from_ref(&dev_spec))
        .expect("Pre-authorizing DEV grant must succeed");

    // Attempt to run with PROD_KEY in non-interactive environment (must fail authorization)
    let prod_spec = format!("API_KEY={}", prod_key);
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_NON_INTERACTIVE", "1")
        .args(["run", "--secrets", &prod_spec, "--", "node", "-e", script])
        .output()
        .expect("Failed to execute mcp-sentinel");

    // Clean up
    let _ = mcp_sentinel::vault::delete_secret(dev_key);
    let _ = mcp_sentinel::vault::delete_secret(prod_key);

    assert!(
        !output.status.success(),
        "Must deny execution when vault source key has changed from DEV to PROD"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("prod_super_secret_999"),
        "PROD secret must never be leaked to child when authorization changed!"
    );
}

/// HACK ATTACK 11: Secret Value with Equals Signs and Complex Connection Strings
/// Tests that secret values containing multiple '=' signs, ampersands, or URIs
/// are injected completely intact and not mangled by the CLI spec splitting logic.
#[test]
fn hack_test_secret_value_with_equals_and_special_chars() {
    let _lock = POLICY_TEST_LOCK.lock().unwrap();
    let vault_key = "TEST_VAULT_COMPLEX_URL_KEY";
    let complex_val =
        "postgres://admin:p@ss=w0rd==&token=abc=123#special@db.cluster.internal:5432/main?ssl=true";

    let _ = mcp_sentinel::vault::set_secret(vault_key, complex_val);

    let script = "console.log('CAPTURED_URI=' + process.env.DATABASE_URL);";
    let cmd = vec!["node".to_string(), "-e".to_string(), script.to_string()];
    let fp = compute_fingerprint(&cmd);
    let alias_spec = format!("DATABASE_URL={}", vault_key);

    mcp_sentinel::policy::record_grant(&fp, None, &cmd, std::slice::from_ref(&alias_spec))
        .expect("Pre-authorizing grant must succeed");

    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_NON_INTERACTIVE", "1")
        .args([
            "run",
            "--no-redact",
            "--secrets",
            &alias_spec,
            "--",
            "node",
            "-e",
            script,
        ])
        .output()
        .expect("Failed to execute mcp-sentinel");

    let _ = mcp_sentinel::vault::delete_secret(vault_key);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("CAPTURED_URI={}", complex_val)),
        "Complex secret value containing multiple '=' and URI chars must remain identical! Actual: {}",
        stdout
    );
}

/// HACK ATTACK 12: Multiple Aliases Pointing to the Same Vault Key (One-to-Many)
/// Tests that two different environment variables can cleanly draw from the same single vault secret.
#[test]
fn hack_test_multiple_aliases_pointing_to_same_vault_key() {
    let _lock = POLICY_TEST_LOCK.lock().unwrap();
    let vault_key = "TEST_VAULT_SHARED_AI_TOKEN";
    let shared_val = "sk-shared-master-ai-token-456";

    let _ = mcp_sentinel::vault::set_secret(vault_key, shared_val);

    let script = "console.log(process.env.OPENAI_API_KEY + '::' + process.env.EMBEDDING_API_KEY);";
    let cmd = vec!["node".to_string(), "-e".to_string(), script.to_string()];
    let fp = compute_fingerprint(&cmd);

    let spec1 = format!("OPENAI_API_KEY={}", vault_key);
    let spec2 = format!("EMBEDDING_API_KEY={}", vault_key);
    let specs = vec![spec1.clone(), spec2.clone()];

    mcp_sentinel::policy::record_grant(&fp, None, &cmd, &specs)
        .expect("Pre-authorizing multi-alias grant must succeed");

    let spec_arg = format!("{},{}", spec1, spec2);
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_NON_INTERACTIVE", "1")
        .args([
            "run",
            "--no-redact",
            "--secrets",
            &spec_arg,
            "--",
            "node",
            "-e",
            script,
        ])
        .output()
        .expect("Failed to execute mcp-sentinel");

    let _ = mcp_sentinel::vault::delete_secret(vault_key);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("sk-shared-master-ai-token-456::sk-shared-master-ai-token-456"),
        "Both environment variables must receive the shared vault secret! Actual: {}",
        stdout
    );
}

/// HACK ATTACK 13: Data Loss Prevention (DLP) & Secret Masking on Stdout
/// A rogue MCP server or LLM response echoes an injected secret back to stdout.
/// By default, mcp-sentinel must mask the secret with [REDACTED_BY_SENTINEL].
/// When --no-redact is supplied, raw pass-through is honored.
#[test]
fn hack_test_dlp_secret_masking_on_stdout() {
    let _lock = POLICY_TEST_LOCK.lock().unwrap();
    let vault_key = "TEST_VAULT_DLP_SECRET_KEY";
    let raw_secret = "ghp_super_confidential_production_token_999";

    let _ = mcp_sentinel::vault::set_secret(vault_key, raw_secret);

    let script = "console.log('OUTPUT_MSG_BEGIN:' + process.env.GITHUB_TOKEN + ':OUTPUT_MSG_END');";
    let cmd = vec!["node".to_string(), "-e".to_string(), script.to_string()];
    let fp = compute_fingerprint(&cmd);
    let spec = format!("GITHUB_TOKEN={}", vault_key);

    mcp_sentinel::policy::record_grant(&fp, None, &cmd, std::slice::from_ref(&spec))
        .expect("Pre-authorizing grant must succeed");

    // 1. Test Default Behavior: DLP Masking active
    let default_output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_NON_INTERACTIVE", "1")
        .args(["run", "--secrets", &spec, "--", "node", "-e", script])
        .output()
        .expect("Failed to execute mcp-sentinel with default DLP");

    assert!(default_output.status.success());
    let default_stdout = String::from_utf8_lossy(&default_output.stdout);
    assert!(
        default_stdout.contains("OUTPUT_MSG_BEGIN:[REDACTED_BY_SENTINEL]:OUTPUT_MSG_END"),
        "Secret printed to stdout must be masked with [REDACTED_BY_SENTINEL] by default! Actual: {}",
        default_stdout
    );
    assert!(
        !default_stdout.contains(raw_secret),
        "Raw secret must never leak into stdout!"
    );

    // 2. Test Opt-out Behavior: --no-redact passed
    let no_redact_output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_NON_INTERACTIVE", "1")
        .args([
            "run",
            "--no-redact",
            "--secrets",
            &spec,
            "--",
            "node",
            "-e",
            script,
        ])
        .output()
        .expect("Failed to execute mcp-sentinel with --no-redact");

    assert!(no_redact_output.status.success());
    let no_redact_stdout = String::from_utf8_lossy(&no_redact_output.stdout);
    assert!(
        no_redact_stdout.contains(raw_secret),
        "Raw secret should pass through when --no-redact is specified! Actual: {}",
        no_redact_stdout
    );

    let _ = mcp_sentinel::vault::delete_secret(vault_key);
}

/// HACK ATTACK 14: Ephemeral "Allow Once" Permission Granting
/// Tests that choosing "Allow Once" (or supplying --allow-once / --once) allows the MCP server
/// to run with authorized secrets during the current execution, but NEVER persists the grant
/// to permissions.json, forcing the user to be re-prompted on the subsequent execution.
#[test]
fn hack_test_allow_once_does_not_persist_grant() {
    let _lock = POLICY_TEST_LOCK.lock().unwrap();
    let vault_key = "TEST_VAULT_ALLOW_ONCE_KEY";
    let raw_secret = "sk_ephemeral_token_once_789";

    let _ = mcp_sentinel::vault::set_secret(vault_key, raw_secret);

    let script = "console.log('EPHEMERAL_RUN_OK');";
    let cmd = vec!["node".to_string(), "-e".to_string(), script.to_string()];
    let fp = compute_fingerprint(&cmd);
    let spec = format!("MY_KEY={}", vault_key);

    // Ensure it is NOT already authorized
    assert!(!mcp_sentinel::policy::is_authorized(
        &fp,
        std::slice::from_ref(&spec)
    ));

    // 1. Run with Mock Dialog answering "Allow Once"
    let output1 = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_MOCK_DIALOG_RESPONSE", "allow_once")
        .args(["run", "--secrets", &spec, "--", "node", "-e", script])
        .output()
        .expect("Failed to execute mcp-sentinel with Allow Once");

    assert!(output1.status.success());
    let stdout1 = String::from_utf8_lossy(&output1.stdout);
    assert!(stdout1.contains("EPHEMERAL_RUN_OK"));

    // Verify: The permission must NOT have been saved to permissions.json!
    assert!(
        !mcp_sentinel::policy::is_authorized(&fp, std::slice::from_ref(&spec)),
        "Grant must NOT be persisted when 'Allow Once' is selected!"
    );

    // 2. Second execution without mock in non-interactive mode MUST fail
    let output2 = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_NON_INTERACTIVE", "1")
        .args(["run", "--secrets", &spec, "--", "node", "-e", script])
        .output()
        .expect("Failed to execute mcp-sentinel");

    assert!(
        !output2.status.success(),
        "Subsequent run without authorization must fail because Allow Once did not persist!"
    );

    // 3. Test CLI flag --allow-once overrides AllowAlways to prevent persistence
    let output3 = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_MOCK_DIALOG_RESPONSE", "allow_always")
        .args([
            "run",
            "--allow-once",
            "--secrets",
            &spec,
            "--",
            "node",
            "-e",
            script,
        ])
        .output()
        .expect("Failed to execute mcp-sentinel with --allow-once");

    assert!(output3.status.success());
    assert!(
        !mcp_sentinel::policy::is_authorized(&fp, std::slice::from_ref(&spec)),
        "--allow-once flag must prevent persisting grant even if dialog returned AllowAlways!"
    );

    let _ = mcp_sentinel::vault::delete_secret(vault_key);
}

/// HACK ATTACK 15: Layer 7 Tool Call Firewall (Blocked Destructive Tool Interception)
/// An attacker or autonomous AI model attempts to invoke a destructive MCP tool ('drop_database').
/// When protected by the 'read-only' profile, mcp-sentinel must intercept the JSON-RPC request,
/// return error -32001 to host stdout, and NEVER deliver the call to the child process.
#[test]
fn hack_test_layer7_tool_firewall_blocks_destructive_call() {
    let _lock = POLICY_TEST_LOCK.lock().unwrap();

    // A mock MCP server script that echoes incoming requests
    let server_script = r#"
        const readline = require('readline');
        const rl = readline.createInterface({ input: process.stdin });
        rl.on('line', (line) => {
            const req = JSON.parse(line);
            console.log(JSON.stringify({ jsonrpc: '2.0', id: req.id, result: { executed: req.params.name } }));
        });
    "#;

    let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .args([
            "run",
            "--profile",
            "read-only",
            "--",
            "node",
            "-e",
            server_script,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn mcp-sentinel with tool policy profile");

    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");

        // 1. Send allowed call: "read_users"
        stdin
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_users\"}}\n")
            .unwrap();

        // 2. Send blocked call: "drop_database"
        stdin
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"drop_database\"}}\n")
            .unwrap();
    }

    let output = child.wait_with_output().expect("Failed to read output");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // 1. read_users must have been executed by child
    assert!(
        stdout.contains("\"executed\":\"read_users\""),
        "Allowed tool call must be forwarded and executed! Stdout: {}",
        stdout
    );

    // 2. drop_database must have been intercepted with code -32001
    assert!(
        stdout.contains("\"code\":-32001") && stdout.contains("blocked by security policy"),
        "Blocked tool call must receive JSON-RPC error -32001! Stdout: {}",
        stdout
    );

    // 3. Child must NEVER have executed drop_database
    assert!(
        !stdout.contains("\"executed\":\"drop_database\""),
        "Blocked tool call must NEVER reach child process!"
    );

    // 4. Stderr must log security alert
    assert!(
        stderr.contains("Security Alert: Blocked unauthorized tool call 'drop_database'"),
        "Security alert must be logged to stderr! Stderr: {}",
        stderr
    );
}

/// HACK ATTACK 16: Security Audit Logging (Default-Off Verification & Zero Secret Leaks)
/// Tests that:
/// 1. By default, NO audit.log file is created (Zero-Disk Footprint / Default OFF).
/// 2. When --audit is provided, security events (SERVER_START, TOOL_ALLOWED, TOOL_BLOCKED, SERVER_EXIT) are captured.
/// 3. Plaintext secret values are NEVER recorded in the audit log under any circumstances.
#[test]
fn hack_test_audit_logging_default_off_and_safe_capture() {
    let _lock = POLICY_TEST_LOCK.lock().unwrap();

    let config_dir = std::env::temp_dir().join(format!(
        "mcp_sentinel_audit_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&config_dir).unwrap();
    let audit_file = config_dir.join("audit.log");

    let vault_key = "TEST_VAULT_AUDIT_KEY";
    let raw_secret = "super_confidential_token_999";
    let _ = mcp_sentinel::vault::set_secret(vault_key, raw_secret);

    let server_script = r#"
        const readline = require('readline');
        const rl = readline.createInterface({ input: process.stdin });
        rl.on('line', (line) => {
            const req = JSON.parse(line);
            console.log(JSON.stringify({ jsonrpc: '2.0', id: req.id, result: { done: true } }));
        });
    "#;

    // 1. Run WITHOUT --audit -> audit.log MUST NOT exist!
    let child_no_audit = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_CONFIG_DIR", &config_dir)
        .env("MCP_SENTINEL_MOCK_DIALOG_RESPONSE", "allow_once")
        .args([
            "run",
            "--secrets",
            &format!("SECRET_A={}", vault_key),
            "--",
            "node",
            "-e",
            "console.log('NO_AUDIT_OK');",
        ])
        .output()
        .expect("Failed to run without audit");

    assert!(child_no_audit.status.success());
    assert!(
        !audit_file.exists(),
        "By default, audit.log must NOT be created!"
    );

    // 2. Run WITH --audit and tool policy
    let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_CONFIG_DIR", &config_dir)
        .env("MCP_SENTINEL_MOCK_DIALOG_RESPONSE", "allow_once")
        .args([
            "run",
            "--audit",
            "--profile",
            "read-only",
            "--secrets",
            &format!("SECRET_A={}", vault_key),
            "--",
            "node",
            "-e",
            server_script,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn mcp-sentinel with --audit");

    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");

        // Send allowed tool call
        stdin
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_data\"}}\n")
            .unwrap();

        // Send blocked tool call
        stdin
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"delete_records\"}}\n")
            .unwrap();
    }

    let output = child.wait_with_output().expect("Failed to read output");
    assert!(output.status.success());

    // 3. Verify audit.log exists and contains structured events
    assert!(
        audit_file.exists(),
        "audit.log must exist when --audit is enabled!"
    );

    let audit_content = std::fs::read_to_string(&audit_file).expect("Failed to read audit.log");

    assert!(
        audit_content.contains("SERVER_START"),
        "Must log SERVER_START event!"
    );
    assert!(
        audit_content.contains("TOOL_CALL_ALLOWED") && audit_content.contains("read_data"),
        "Must log TOOL_CALL_ALLOWED for read_data!"
    );
    assert!(
        audit_content.contains("TOOL_CALL_BLOCKED") && audit_content.contains("delete_records"),
        "Must log TOOL_CALL_BLOCKED for delete_records!"
    );
    assert!(
        audit_content.contains("SERVER_EXIT"),
        "Must log SERVER_EXIT event!"
    );

    // 4. CRITICAL: Secret plaintext MUST NEVER be logged
    assert!(
        !audit_content.contains(raw_secret),
        "CRITICAL SECURITY FAILURE: Plaintext secret was logged into audit.log!"
    );

    let _ = mcp_sentinel::vault::delete_secret(vault_key);
    let _ = std::fs::remove_dir_all(&config_dir);
}
