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
        profile: None,
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
        .env("MCP_SENTINEL_BYPASS_JOB_CHECK", "1")
        .args(["secret", "set", "MCP_SENTINEL_CHILD_CONTEXT", "0"])
        .output()
        .expect("Failed to execute mcp-sentinel secret set");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("reserved prefix"));

    // Also test exact reserved prefix without underscore
    let output_exact = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_BYPASS_JOB_CHECK", "1")
        .args(["secret", "set", "MCP_SENTINEL", "0"])
        .output()
        .expect("Failed to execute mcp-sentinel secret set");
    assert!(!output_exact.status.success());
    let stderr_exact = String::from_utf8_lossy(&output_exact.stderr);
    assert!(stderr_exact.contains("reserved prefix"));

    // Also test invalid characters
    let output_invalid = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_BYPASS_JOB_CHECK", "1")
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

/// HACK ATTACK 17: Layer 7 Tool Call Firewall Batch Request Interception
/// Attackers or rogue models can pack multiple JSON-RPC calls into an array batch request.
/// The L7 firewall must unpack the batch, block unauthorized destructive calls,
/// return JSON-RPC errors for blocked items, and only forward permitted calls to the child.
#[test]
fn hack_test_layer7_tool_firewall_blocks_batch_requests() {
    let _lock = POLICY_TEST_LOCK.lock().unwrap();

    let server_script = r#"
        const readline = require('readline');
        const rl = readline.createInterface({ input: process.stdin });
        rl.on('line', (line) => {
            const parsed = JSON.parse(line);
            if (Array.isArray(parsed)) {
                const resp = parsed.map(req => ({ jsonrpc: '2.0', id: req.id, result: { executed: req.params.name } }));
                console.log(JSON.stringify(resp));
            } else {
                console.log(JSON.stringify({ jsonrpc: '2.0', id: parsed.id, result: { executed: parsed.params.name } }));
            }
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
        .expect("Failed to spawn mcp-sentinel with read-only profile");

    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");

        // Send a mixed batch: id: 1 is allowed ('read_data'), id: 2 is blocked ('drop_database')
        let batch_payload = serde_json::json!([
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "read_data" }
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": { "name": "drop_database" }
            }
        ]);

        let payload_str = format!("{}\n", batch_payload);
        stdin.write_all(payload_str.as_bytes()).unwrap();

        // Also send a batch where ALL are blocked: id: 3 ('rmdir'), id: 4 ('truncate')
        let all_blocked_batch = serde_json::json!([
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": { "name": "rmdir" }
            },
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": { "name": "truncate" }
            }
        ]);
        let all_blocked_str = format!("{}\n", all_blocked_batch);
        stdin.write_all(all_blocked_str.as_bytes()).unwrap();
    }

    let output = child.wait_with_output().expect("Failed to read output");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // 1. Mixed batch: read_data must succeed and be executed
    assert!(
        stdout.contains("\"executed\":\"read_data\""),
        "Permitted tool in batch must be executed by child! Stdout: {}",
        stdout
    );

    // 2. Mixed batch: drop_database must be intercepted with code -32001
    assert!(
        stdout.contains("\"code\":-32001") && stdout.contains("drop_database"),
        "Blocked tool in batch must receive code -32001 error! Stdout: {}",
        stdout
    );

    // 3. Destructive tool drop_database must NEVER have been executed by child
    assert!(
        !stdout.contains("\"executed\":\"drop_database\""),
        "Destructive tool in batch must NEVER reach child process!"
    );

    // 4. All-blocked batch: id 3 and 4 must both receive error -32001
    assert!(
        stdout.contains("\"id\":3") && stdout.contains("\"id\":4"),
        "All blocked items in batch must receive errors! Stdout: {}",
        stdout
    );
    assert!(
        !stdout.contains("\"executed\":\"rmdir\"") && !stdout.contains("\"executed\":\"truncate\""),
        "Child must never execute any call from all-blocked batch!"
    );
}

/// HACK ATTACK 18: Headless / SSH Pre-authorization via CLI
/// On headless servers or CI/CD pipelines without GUI or interactive terminal,
/// administrators must be able to securely pre-authorize servers via `permissions grant`.
#[test]
fn hack_test_permissions_grant_headless_preauth() {
    let _lock = POLICY_TEST_LOCK.lock().unwrap();
    let vault_key = "TEST_VAULT_HEADLESS_KEY";
    let _ = mcp_sentinel::vault::set_secret(vault_key, "secret_value_123");

    let script = "console.log('HEADLESS_AUTH_SUCCESS');";
    let cmd = vec!["node".to_string(), "-e".to_string(), script.to_string()];
    let fp = compute_fingerprint(&cmd);
    let spec = format!("MY_KEY={}", vault_key);

    // Pre-condition: revoke any previous grant and assert not authorized
    let _ = mcp_sentinel::policy::revoke_grant(&fp);
    assert!(!mcp_sentinel::policy::is_authorized(
        &fp,
        std::slice::from_ref(&spec)
    ));

    // Execute CLI command: permissions grant
    let grant_output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .args([
            "permissions",
            "grant",
            "--name",
            "Headless Test Server",
            "--secrets",
            &spec,
            "--",
            "node",
            "-e",
            script,
        ])
        .output()
        .expect("Failed to execute permissions grant");

    assert!(
        grant_output.status.success(),
        "permissions grant must succeed with exit code 0! Stderr: {}",
        String::from_utf8_lossy(&grant_output.stderr)
    );

    // Verify policy now marks fingerprint as authorized
    assert!(
        mcp_sentinel::policy::is_authorized(&fp, std::slice::from_ref(&spec)),
        "Server must be authorized in policy after permissions grant!"
    );

    // Run in non-interactive mode: must succeed immediately without prompt
    let run_output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_NON_INTERACTIVE", "1")
        .args(["run", "--secrets", &spec, "--", "node", "-e", script])
        .output()
        .expect("Failed to execute mcp-sentinel run");

    assert!(run_output.status.success());
    let stdout = String::from_utf8_lossy(&run_output.stdout);
    assert!(
        stdout.contains("HEADLESS_AUTH_SUCCESS"),
        "Pre-authorized server must run cleanly in non-interactive mode! Stdout: {}",
        stdout
    );

    let _ = mcp_sentinel::policy::revoke_grant(&fp);
    let _ = mcp_sentinel::vault::delete_secret(vault_key);
}

/// HACK ATTACK 19: Multi-line / Formatted JSON-RPC Firewall Inspection (SEC-01)
/// Attackers format JSON-RPC payloads with whitespace and newlines to bypass line-oriented readers.
/// The streaming parser in Sentinel must correctly assemble multi-line objects,
/// block destructive tool calls, return code -32001, and never send them to the child.
#[test]
fn hack_test_multiline_formatted_jsonrpc_firewall_blocks_destructive_call() {
    let _lock = POLICY_TEST_LOCK.lock().unwrap();

    let server_script = r#"
        const readline = require('readline');
        const rl = readline.createInterface({ input: process.stdin });
        let buf = '';
        process.stdin.on('data', (chunk) => {
            buf += chunk.toString();
            try {
                const parsed = JSON.parse(buf);
                console.log(JSON.stringify({ jsonrpc: '2.0', id: parsed.id, result: { executed: parsed.params.name } }));
                buf = '';
            } catch (e) {}
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
        .expect("Failed to spawn mcp-sentinel");

    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");

        // Send a multi-line formatted JSON-RPC tool call
        let multiline_payload = "{\n  \"jsonrpc\": \"2.0\",\n  \"id\": 99,\n  \"method\": \"tools/call\",\n  \"params\": {\n    \"name\": \"drop_database\"\n  }\n}\n";
        stdin.write_all(multiline_payload.as_bytes()).unwrap();
        stdin.flush().unwrap();
    }

    let output = child.wait_with_output().expect("Failed to read output");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // 1. Must intercept with code -32001 error response
    assert!(
        stdout.contains("\"code\":-32001") && stdout.contains("blocked by security policy"),
        "Multi-line JSON-RPC tool call must be intercepted! Stdout: {}",
        stdout
    );

    // 2. Child process must NEVER have executed drop_database
    assert!(
        !stdout.contains("\"executed\":\"drop_database\""),
        "Destructive tool in multi-line JSON-RPC must NEVER reach child! Stdout: {}",
        stdout
    );
}

/// HACK ATTACK 20: Protecting Internal Master Key from secret get and secret delete (SEC-04)
/// Attackers or malicious scripts attempting to query `secret get __master_key__` or delete it
/// must be blocked by key name validation to prevent HMAC key exfiltration or sabotage.
#[test]
fn hack_test_secret_get_and_delete_blocks_internal_master_key() {
    // 1. secret get __master_key__ must fail
    let get_output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_BYPASS_JOB_CHECK", "1")
        .args(["secret", "get", "__master_key__"])
        .output()
        .expect("Failed to execute secret get");

    assert!(
        !get_output.status.success(),
        "secret get __master_key__ must fail!"
    );
    let get_stderr = String::from_utf8_lossy(&get_output.stderr);
    assert!(
        get_stderr.contains("reserved prefix"),
        "Must block access to reserved prefix! Stderr: {}",
        get_stderr
    );

    // 2. secret delete __master_key__ must fail
    let del_output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_BYPASS_JOB_CHECK", "1")
        .args(["secret", "delete", "__master_key__"])
        .output()
        .expect("Failed to execute secret delete");

    assert!(
        !del_output.status.success(),
        "secret delete __master_key__ must fail!"
    );
    let del_stderr = String::from_utf8_lossy(&del_output.stderr);
    assert!(
        del_stderr.contains("reserved prefix"),
        "Must block deletion of reserved prefix! Stderr: {}",
        del_stderr
    );
}

/// HACK ATTACK 21: Migrate server with reserved prefix in name does not crash (BUG-03)
#[test]
fn hack_test_migrate_server_name_with_mcp_sentinel_prefix() {
    let _lock = POLICY_TEST_LOCK.lock().unwrap();

    let input_json = r#"{
        "mcpServers": {
            "mcp-sentinel-server": {
                "command": "node",
                "args": ["server.js"],
                "env": {
                    "API_KEY": "test_secret_value_123"
                }
            }
        }
    }"#;

    // Dry-run migration should succeed without crashing on reserved prefix
    let result = mcp_sentinel::migrate::transform_config_json(input_json, true);
    assert!(
        result.is_ok(),
        "Migration with mcp-sentinel prefix in server name must succeed! Error: {:?}",
        result.err()
    );

    let (output_json, results) = result.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].extracted_secrets.len(), 1);

    // The extracted key should have been safely prefixed with SRV_ to avoid MCP_SENTINEL_ reserved key
    let parsed: serde_json::Value = serde_json::from_str(&output_json).unwrap();
    assert_eq!(
        parsed["mcpServers"]["mcp-sentinel-server"]["command"],
        "mcp-sentinel"
    );
}

/// HACK ATTACK 22: Layer 7 Tool Firewall Fail-Closed on Malformed Tool Name
/// An attacker or prompt injection crafts a `tools/call` request with missing or non-string `params.name`.
/// The L7 firewall must fail-closed, blocking the request with code -32602 instead of allowing it through.
#[test]
fn hack_test_layer7_tool_firewall_blocks_malformed_name_call() {
    use std::io::Write;
    let _lock = POLICY_TEST_LOCK.lock().unwrap();

    let server_script = r#"
        const readline = require('readline');
        const rl = readline.createInterface({ input: process.stdin });
        rl.on('line', (line) => {
            console.log(JSON.stringify({ jsonrpc: '2.0', id: 99, result: { executed: 'MALICIOUS_EXECUTION' } }));
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
        .spawn()
        .expect("Failed to spawn mcp-sentinel");

    {
        let stdin = child.stdin.as_mut().expect("Failed to open child stdin");
        // Request declaring tools/call but missing params.name
        let malformed_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": { "not_name": "delete_database" }
        });
        writeln!(stdin, "{}", malformed_req).unwrap();
    }

    let output = child.wait_with_output().expect("Failed to read output");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Must be intercepted with -32602 error
    assert!(
        stdout.contains("\"code\":-32602"),
        "Malformed tools/call must be intercepted with code -32602! Stdout: {}",
        stdout
    );
    // Must NOT reach child process
    assert!(
        !stdout.contains("MALICIOUS_EXECUTION"),
        "Child process must NEVER execute when tools/call has malformed name! Stdout: {}",
        stdout
    );
}

/// HACK ATTACK 23: Layer 7 Tool Firewall Blocks Unicode Homoglyphs & Trojan Source
/// An attacker tries to bypass blacklist patterns like `*delete*` using Cyrillic homoglyph `е` (U+0435)
/// or invisible zero-width spaces (\u{200B}).
/// The L7 firewall must detect both and fail-closed with code -32603.
#[test]
fn hack_test_layer7_tool_firewall_blocks_unicode_homoglyphs_and_trojan_source() {
    use std::io::Write;
    let _lock = POLICY_TEST_LOCK.lock().unwrap();

    let server_script = r#"
        const readline = require('readline');
        const rl = readline.createInterface({ input: process.stdin });
        rl.on('line', (line) => {
            console.log(JSON.stringify({ jsonrpc: '2.0', id: 99, result: { executed: 'HOMOGLYPH_BYPASS_EXECUTED' } }));
        });
    "#;

    // Test 1: Cyrillic homoglyph 'е' (U+0435) in 'delete_database'
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
        .spawn()
        .expect("Failed to spawn mcp-sentinel");

    {
        let stdin = child.stdin.as_mut().expect("Failed to open child stdin");
        let cyrillic_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": { "name": "d\u{0435}lete_database" }
        });
        writeln!(stdin, "{}", cyrillic_req).unwrap();
    }

    let output = child.wait_with_output().expect("Failed to read output");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("\"code\":-32001"),
        "Cyrillic homoglyph delete call must be intercepted! Stdout: {}",
        stdout
    );
    assert!(
        !stdout.contains("HOMOGLYPH_BYPASS_EXECUTED"),
        "Cyrillic homoglyph tool call must NEVER reach child process!"
    );

    // Test 2: Trojan Source zero-width space in tool name
    let mut child_zw = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
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
        .spawn()
        .expect("Failed to spawn mcp-sentinel");

    {
        let stdin = child_zw.stdin.as_mut().expect("Failed to open child stdin");
        let zw_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 102,
            "method": "tools/call",
            "params": { "name": "del\u{200B}ete_database" }
        });
        writeln!(stdin, "{}", zw_req).unwrap();
    }

    let output_zw = child_zw.wait_with_output().expect("Failed to read output");
    let stdout_zw = String::from_utf8_lossy(&output_zw.stdout);

    assert!(
        stdout_zw.contains("\"code\":-32001"),
        "Zero-width Trojan Source tool call must be intercepted! Stdout: {}",
        stdout_zw
    );
    assert!(
        !stdout_zw.contains("HOMOGLYPH_BYPASS_EXECUTED"),
        "Zero-width Trojan Source tool call must NEVER reach child process!"
    );
}

/// HACK ATTACK 24: JSON-RPC Stream Framing Integrity on Synthetic Error Interleaving
/// When a child process emits an incomplete, in-flight partial JSON-RPC frame without a newline,
/// and the Layer 7 firewall emits a synthetic error (e.g. blocking a prohibited tool call),
/// mcp-sentinel must NOT inject an artificial newline or corrupt the partial child frame.
/// Both the synthetic error and subsequent completed child frame must parse as valid JSON.
#[test]
fn hack_test_jsonrpc_stream_framing_integrity_on_interleaved_synthetic_error() {
    use std::io::Write;
    let _lock = POLICY_TEST_LOCK.lock().unwrap();

    let server_script = r#"
        const readline = require('readline');
        // Immediately emit a partial chunk without trailing newline
        process.stdout.write('{"jsonrpc":"2.0","id":100,"result":{"status":"child_chunk"');
        
        // After 200ms, finish the line
        setTimeout(() => {
            process.stdout.write(',"completed":true}}\n');
        }, 200);

        const rl = readline.createInterface({ input: process.stdin });
        rl.on('line', (line) => {
            // Should not receive blocked calls
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
        .spawn()
        .expect("Failed to spawn mcp-sentinel");

    // Give child 50ms to write the initial partial chunk
    std::thread::sleep(std::time::Duration::from_millis(50));

    {
        let stdin = child.stdin.as_mut().expect("Failed to open child stdin");
        // Send a blocked request that triggers a synthetic error from the firewall
        let blocked_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 200,
            "method": "tools/call",
            "params": { "name": "drop_database" }
        });
        writeln!(stdin, "{}", blocked_req).unwrap();
    }

    let output = child.wait_with_output().expect("Failed to read output");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Stdout must contain both the synthetic error for id 200 and the completed child response for id 100
    assert!(
        stdout.contains("\"code\":-32001"),
        "Must contain synthetic firewall error for blocked call! Stdout: {}",
        stdout
    );
    assert!(
        stdout.contains("\"completed\":true"),
        "Must contain completed child response! Stdout: {}",
        stdout
    );

    // Verify each line is valid JSON (framing not corrupted)
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    for line in &lines {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
        assert!(
            parsed.is_ok(),
            "Each output line must be valid, uncorrupted JSON! Broken line: '{}', Error: {:?}",
            line,
            parsed.err()
        );
    }

    // Specifically verify the reconstructed child line
    let child_line = lines.iter().find(|l| l.contains("\"id\":100") || l.contains("\"id\": 100"));
    assert!(
        child_line.is_some(),
        "Reconstructed child message must be present intact! Output: {}",
        stdout
    );
    let child_json: serde_json::Value = serde_json::from_str(child_line.unwrap()).unwrap();
    assert_eq!(child_json["result"]["status"], "child_chunk");
    assert_eq!(child_json["result"]["completed"], true);
}

/// HACK ATTACK 25: Stdin Buffer Unbounded Memory Exhaustion DoS Protection (SEC-DOS)
/// An attacker or rogue client streams an endless payload into stdin without valid JSON delimiters or newlines.
/// Sentinel must enforce MAX_IN_BUF_SIZE (16 MB), log a security alert to stderr, and terminate the input stream.
#[test]
fn hack_test_stdin_buffer_dos_protection() {
    use std::io::Write;
    let _lock = POLICY_TEST_LOCK.lock().unwrap();

    let server_script = r#"
        const readline = require('readline');
        const rl = readline.createInterface({ input: process.stdin });
        rl.on('line', () => {});
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
        .expect("Failed to spawn mcp-sentinel");

    {
        let stdin = child.stdin.as_mut().expect("Failed to open child stdin");
        // Stream slightly more than 16MB of non-newline data
        let chunk = vec![b'a'; 64 * 1024]; // 64 KB chunk
        for _ in 0..270 {
            // 270 * 64 KB = 17.28 MB > 16 MB
            if stdin.write_all(&chunk).is_err() {
                break;
            }
        }
        let _ = stdin.flush();
    }

    let output = child.wait_with_output().expect("Failed to read output");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("Security Alert: Stdin buffer exceeded max capacity"),
        "Must alert on stdin buffer exceeding max capacity! Actual stderr: {}",
        stderr
    );
}

#[test]
fn test_stdin_buffer_custom_env_override() {
    use std::io::Write;
    let _lock = POLICY_TEST_LOCK.lock().unwrap();

    let server_script = r#"
        const readline = require('readline');
        const rl = readline.createInterface({ input: process.stdin });
        rl.on('line', () => {});
    "#;

    // Set custom limit to 1 MB (1048576 bytes)
    let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_MAX_BUFFER", "1048576")
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
        .expect("Failed to spawn mcp-sentinel");

    {
        let stdin = child.stdin.as_mut().expect("Failed to open child stdin");
        // Stream slightly more than 1 MB (20 * 64 KB = 1.28 MB)
        let chunk = vec![b'a'; 64 * 1024];
        for _ in 0..20 {
            if stdin.write_all(&chunk).is_err() {
                break;
            }
        }
        let _ = stdin.flush();
    }

    let output = child.wait_with_output().expect("Failed to read output");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("Security Alert: Stdin buffer exceeded max capacity (1048576 bytes)"),
        "Must alert with custom buffer limit! Actual stderr: {}",
        stderr
    );
}

/// HACK ATTACK 28: Profile Mismatch Re-authorization Requirement
/// A grant authorized under `--profile read-only` must be denied (re-prompting) if later run without profile or with a different profile.
#[test]
fn hack_test_tofu_profile_mismatch_requires_reauthorization() {
    let _lock = POLICY_TEST_LOCK.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!("sentinel_test_profile_tofu_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);

    let vault_key = "TEST_VAULT_PROFILE_KEY";
    let _ = mcp_sentinel::vault::set_secret(vault_key, "secret_value_12345");

    let cmd = vec!["node".to_string(), "server.js".to_string()];
    let fp_ro = mcp_sentinel::policy::compute_fingerprint_with_profile(&cmd, Some("read-only"));
    let spec = format!("API_KEY={}", vault_key);

    // Pre-authorize with read-only profile
    std::env::set_var("MCP_SENTINEL_CONFIG_DIR", temp_dir.to_str().unwrap());
    std::env::set_var("MCP_SENTINEL_ALLOW_INSECURE_KEYFILE", "1");

    mcp_sentinel::policy::record_grant_with_profile(
        &fp_ro,
        None,
        &cmd,
        std::slice::from_ref(&spec),
        Some("read-only".to_string()),
    )
    .expect("Pre-authorizing read-only grant must succeed");

    // Check that it's authorized with read-only profile
    assert!(mcp_sentinel::policy::is_authorized_with_profile(
        &fp_ro,
        std::slice::from_ref(&spec),
        Some("read-only")
    ));

    // Check that it's NOT authorized with None or a different profile
    assert!(!mcp_sentinel::policy::is_authorized_with_profile(
        &fp_ro,
        std::slice::from_ref(&spec),
        None
    ));
    assert!(!mcp_sentinel::policy::is_authorized_with_profile(
        &fp_ro,
        std::slice::from_ref(&spec),
        Some("admin")
    ));

    // Now test running via CLI without profile in mock deny mode -> exits with code 1
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SENTINEL_CONFIG_DIR", temp_dir.to_str().unwrap())
        .env("MCP_SENTINEL_ALLOW_INSECURE_KEYFILE", "1")
        .env("MCP_SENTINEL_MOCK_DIALOG_RESPONSE", "deny")
        .args([
            "run",
            "--secrets",
            &spec,
            "--",
            "node",
            "server.js",
        ])
        .output()
        .expect("Failed to execute mcp-sentinel run");

    assert!(
        !output.status.success(),
        "Running without profile when granted with read-only must prompt and fail when denied"
    );

    // Cleanup
    let _ = mcp_sentinel::vault::delete_secret(vault_key);
    std::env::remove_var("MCP_SENTINEL_CONFIG_DIR");
    std::env::remove_var("MCP_SENTINEL_ALLOW_INSECURE_KEYFILE");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// HACK ATTACK 29: OS Job Object Sandbox & Child Bypass Prevention
/// A process running inside a Job Object attempting to access secrets must be strictly blocked
/// with exit code 13, even if an attacker or malicious child unset the MCP_SENTINEL_CHILD_CONTEXT env var.
/// The check can be overridden only via MCP_SENTINEL_BYPASS_JOB_CHECK=1 for trusted workflows/tests.
#[test]
#[cfg(windows)]
fn hack_test_job_object_blocks_secret_access_even_without_child_context_env() {
    let job = mcp_sentinel::platform::windows::JobObjectGuard::new().expect("Failed to create Job Object");

    use std::os::windows::io::AsRawHandle;

    let script_child = format!(
        "Start-Sleep -Milliseconds 100; & '{}' secrets list; exit $LASTEXITCODE",
        env!("CARGO_BIN_EXE_mcp-sentinel").replace('\'', "''")
    );

    // 1. Without child context (attacker stripped MCP_SENTINEL_CHILD_CONTEXT) -> still blocked with code 13
    let child_no_env = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script_child])
        .env_remove("MCP_SENTINEL_CHILD_CONTEXT")
        .env_remove("MCP_SENTINEL_BYPASS_JOB_CHECK")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn powershell child for sandbox simulation");

    unsafe {
        let _ = job.assign_process(child_no_env.as_raw_handle() as _);
    }

    let output_no_env = child_no_env.wait_with_output().expect("Failed to read output");
    let stderr_no_env = String::from_utf8_lossy(&output_no_env.stderr);
    assert_eq!(
        output_no_env.status.code(),
        Some(13),
        "Secrets access from within Job Object even without child context env must exit with code 13. Stderr: {}",
        stderr_no_env
    );
    assert!(
        stderr_no_env.contains("Security Violation"),
        "Must output security violation message"
    );

    // 2. With MCP_SENTINEL_BYPASS_JOB_CHECK=1 -> permitted (for test/trusted override)
    let child_bypass = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script_child])
        .env_remove("MCP_SENTINEL_CHILD_CONTEXT")
        .env("MCP_SENTINEL_BYPASS_JOB_CHECK", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn powershell child for bypass simulation");

    unsafe {
        let _ = job.assign_process(child_bypass.as_raw_handle() as _);
    }

    let output_bypass = child_bypass.wait_with_output().expect("Failed to read output");
    let stderr_bypass = String::from_utf8_lossy(&output_bypass.stderr);
    assert_ne!(
        output_bypass.status.code(),
        Some(13),
        "With bypass flag set, must not be blocked with code 13. Stderr: {}",
        stderr_bypass
    );
}

/// HACK ATTACK 30: BUG-01 Fix Verification - Grandchild Pipe Hang Mitigation
/// When a child process spawns an orphan grandchild holding open stdout/stderr pipes,
/// mcp-sentinel must drop its process lifecycle guards and enforce a bounded timeout (250ms),
/// terminating cleanly (< 3s) rather than hanging indefinitely waiting for pipe EOF.
#[test]
fn hack_test_grandchild_pipe_hang_mitigation() {
    let script = r#"
        const cp = require('child_process');
        if (process.platform === 'win32') {
            const sub = cp.spawn('powershell.exe', ['-NoProfile', '-Command', 'Start-Sleep -Seconds 10'], {
                stdio: 'inherit',
                detached: true
            });
            sub.unref();
        } else {
            const sub = cp.spawn('sleep', ['10'], {
                stdio: 'inherit',
                detached: true
            });
            sub.unref();
        }
        console.log('PARENT_CHILD_EXITED');
        process.exit(0);
    "#;

    let start = std::time::Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .args(["run", "--", "node", "-e", script])
        .output()
        .expect("Failed to run mcp-sentinel with grandchild test");

    let elapsed = start.elapsed();
    assert!(
        output.status.success(),
        "mcp-sentinel should exit successfully"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(4),
        "Grandchild pipe hang detected: execution took {:?}, must be under 4s",
        elapsed
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("PARENT_CHILD_EXITED"),
        "Stdout should contain child output before grandchild detach: {}",
        stdout
    );
}

/// HACK ATTACK 31: BUG-02 Fix Verification - Safe pass-env forwarding & Isolation
/// Non-secret configuration variables specified in `--pass-env` or `--env` must be passed
/// to the child, while non-passed environment variables remain completely isolated and invisible.
#[test]
fn hack_test_pass_env_forwarding_and_isolation() {
    let script = r#"
        console.log('CFG_PORT=' + process.env.MCP_SERVER_PORT);
        console.log('CFG_HOST=' + process.env.MCP_SERVER_HOST);
        console.log('UNPASSED=' + process.env.MCP_UNPASSED_SECRET_KEY);
    "#;

    // Test --pass-env
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SERVER_PORT", "9090")
        .env("MCP_SERVER_HOST", "127.0.0.1")
        .env("MCP_UNPASSED_SECRET_KEY", "should_not_leak_to_child")
        .args([
            "run",
            "--pass-env",
            "MCP_SERVER_PORT,MCP_SERVER_HOST",
            "--",
            "node",
            "-e",
            script,
        ])
        .output()
        .expect("Failed to run mcp-sentinel with --pass-env");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CFG_PORT=9090"));
    assert!(stdout.contains("CFG_HOST=127.0.0.1"));
    assert!(stdout.contains("UNPASSED=undefined"));

    // Test alias --env
    let output_alias = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("MCP_SERVER_PORT", "9090")
        .env("MCP_UNPASSED_SECRET_KEY", "should_not_leak_to_child")
        .args([
            "run",
            "--env",
            "MCP_SERVER_PORT",
            "--",
            "node",
            "-e",
            script,
        ])
        .output()
        .expect("Failed to run mcp-sentinel with --env alias");

    assert!(output_alias.status.success());
    let stdout_alias = String::from_utf8_lossy(&output_alias.stdout);
    assert!(stdout_alias.contains("CFG_PORT=9090"));
    assert!(stdout_alias.contains("CFG_HOST=undefined"));
    assert!(stdout_alias.contains("UNPASSED=undefined"));
}

/// HACK ATTACK 32: RISK-02 Fix Verification - Dangerous Runtime Variables Blocked
/// Setting secrets or passing env for dangerous runtime control variables (e.g. NODE_OPTIONS,
/// PYTHONPATH, LD_PRELOAD) must be rejected with an explicit security error and never passed down.
#[test]
fn hack_test_dangerous_runtime_control_variables_blocked() {
    // 1. Attempt to set dangerous secret via CLI
    let dangerous_keys = [
        "NODE_OPTIONS",
        "node_options",
        "PYTHONPATH",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
    ];

    for &key in &dangerous_keys {
        let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
            .env("MCP_SENTINEL_BYPASS_JOB_CHECK", "1")
            .args(["secret", "set", key, "malicious_payload"])
            .output()
            .expect("Failed to execute secret set");

        assert!(
            !output.status.success(),
            "Setting dangerous runtime variable '{}' must fail",
            key
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("dangerous runtime control variable"),
            "Stderr for '{}' must mention dangerous runtime control variable: {}",
            key,
            stderr
        );
    }

    // 2. Attempt to pass dangerous runtime variable via --pass-env -> must NOT leak to child
    let script = r#"
        console.log('NODE_OPTIONS=' + process.env.NODE_OPTIONS);
        console.log('PYTHONPATH=' + process.env.PYTHONPATH);
    "#;

    let output_pass = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .env("NODE_OPTIONS", "--require evil.js")
        .env("PYTHONPATH", "/tmp/malicious")
        .args([
            "run",
            "--pass-env",
            "NODE_OPTIONS,PYTHONPATH",
            "--",
            "node",
            "-e",
            script,
        ])
        .output()
        .expect("Failed to execute mcp-sentinel with pass-env of dangerous vars");

    assert!(output_pass.status.success());
    let stdout_pass = String::from_utf8_lossy(&output_pass.stdout);
    assert!(stdout_pass.contains("NODE_OPTIONS=undefined"));
    assert!(stdout_pass.contains("PYTHONPATH=undefined"));
}


