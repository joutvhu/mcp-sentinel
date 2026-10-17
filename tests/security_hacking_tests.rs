use mcp_sentinel::policy::{
    compute_fingerprint, get_policy_file_path, is_authorized, Grant, PolicyFile,
};
use std::collections::HashMap;
use std::fs;
use std::process::Command;

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

    let path = get_policy_file_path().expect("Failed to get policy path");

    // Attacker crafts a fake permissions.json file with an unauthorized grant
    let forged_grant = Grant {
        id: fp.clone(),
        name: Some("Trojan MCP".to_string()),
        command: "node malicious_script.js".to_string(),
        granted_secrets: vec!["RESTRICTED_PRODUCTION_DATABASE_URL".to_string()],
        created_at: chrono::Utc::now(),
    };

    let mut forged_grants = HashMap::new();
    forged_grants.insert(fp.clone(), forged_grant);

    // Attacker signs it with an invalid/forged signature
    let attacker_fake_file = PolicyFile {
        grants: forged_grants,
        signature: Some(
            "attacker_forged_hmac_signature_00000000000000000000000000000000".to_string(),
        ),
    };

    let bad_json = serde_json::to_string_pretty(&attacker_fake_file).unwrap();
    fs::write(&path, bad_json).expect("Failed to simulate attack on disk");

    // When mcp-sentinel checks authorization, it MUST reject the forged permission!
    let authorized = is_authorized(&fp, &["RESTRICTED_PRODUCTION_DATABASE_URL".to_string()]);
    assert!(
        !authorized,
        "Forged permissions in permissions.json MUST be rejected by HMAC verification!"
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
    let cmd = vec![
        "node".to_string(),
        "-e".to_string(),
        "console.log('SHOULD_NOT_EXECUTE');".to_string(),
    ];
    let fp = compute_fingerprint(&cmd);
    let missing_secret = "NON_EXISTENT_UNKNOWN_KEY_9999".to_string();

    // Pre-authorize this test command so it skips the interactive GUI prompt
    let _ =
        mcp_sentinel::policy::record_grant(&fp, None, &cmd, std::slice::from_ref(&missing_secret));

    let output = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
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
        "Must report missing secret name in error log"
    );
}
