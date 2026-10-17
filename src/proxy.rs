use std::collections::HashMap;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

/// Evaluates a single JSON-RPC request object against the active tool policy.
/// Returns Some(error_response_value) if blocked, None if allowed.
fn check_single_tool_request(
    req: &serde_json::Value,
    tool_profile: &Option<crate::tool_policy::ToolProfile>,
    audit_enabled: bool,
    server_name: &str,
) -> Option<serde_json::Value> {
    if req.get("method").and_then(|m| m.as_str()) != Some("tools/call") {
        return None;
    }

    let tool_name = req
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())?;

    if let Some(ref profile) = tool_profile {
        let decision = crate::tool_policy::evaluate_tool_call(tool_name, profile);
        if let crate::tool_policy::ToolDecision::Blocked { reason } = decision {
            eprintln!(
                "[mcp-sentinel] Security Alert: Blocked unauthorized tool call '{}' by policy '{}': {}",
                tool_name, profile.name, reason
            );

            if audit_enabled {
                let _ = crate::audit::log_event(&crate::audit::AuditEntry {
                    timestamp: chrono::Utc::now(),
                    event: crate::audit::AuditEventType::ToolCallBlocked,
                    server_name: Some(server_name.to_string()),
                    command: None,
                    tool_name: Some(tool_name.to_string()),
                    decision: Some("BLOCKED".to_string()),
                    reason: Some(reason.clone()),
                    secrets: None,
                    profile: Some(profile.name.clone()),
                    exit_code: None,
                });
            }

            let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
            return Some(serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32001,
                    "message": format!(
                        "[MCP-SENTINEL] Tool '{}' is blocked by security policy '{}': {}",
                        tool_name, profile.name, reason
                    )
                }
            }));
        } else if audit_enabled {
            let _ = crate::audit::log_event(&crate::audit::AuditEntry {
                timestamp: chrono::Utc::now(),
                event: crate::audit::AuditEventType::ToolCallAllowed,
                server_name: Some(server_name.to_string()),
                command: None,
                tool_name: Some(tool_name.to_string()),
                decision: Some("ALLOWED".to_string()),
                reason: None,
                secrets: None,
                profile: Some(profile.name.clone()),
                exit_code: None,
            });
        }
    } else if audit_enabled {
        let _ = crate::audit::log_event(&crate::audit::AuditEntry {
            timestamp: chrono::Utc::now(),
            event: crate::audit::AuditEventType::ToolCallAllowed,
            server_name: Some(server_name.to_string()),
            command: None,
            tool_name: Some(tool_name.to_string()),
            decision: Some("ALLOWED".to_string()),
            reason: None,
            secrets: None,
            profile: None,
            exit_code: None,
        });
    }

    None
}

pub async fn run_child_and_pipe(
    cmd_args: &[String],
    env_vars: HashMap<String, String>,
    redact_secrets: Vec<String>,
    tool_profile: Option<crate::tool_policy::ToolProfile>,
    audit_enabled: bool,
    server_name: Option<String>,
) -> Result<i32, Box<dyn std::error::Error>> {
    if cmd_args.is_empty() {
        return Err("No command specified to execute".into());
    }

    // Resolve executable path (resolves npx -> npx.cmd on Windows, etc.)
    let resolved_program = which::which(&cmd_args[0])
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| cmd_args[0].clone());

    let mut command = Command::new(&resolved_program);
    if cmd_args.len() > 1 {
        command.args(&cmd_args[1..]);
    }

    // Completely clear existing host environment and apply sanitized environment
    command.env_clear();
    command.envs(&env_vars);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn()?;

    // Attach child process to lifecycle guards
    #[cfg(windows)]
    let _job_guard = {
        if let Ok(job) = crate::platform::windows::JobObjectGuard::new() {
            if let Some(handle) = child.raw_handle() {
                unsafe {
                    let _ = job.assign_process(handle as _);
                }
            }
            Some(job)
        } else {
            None
        }
    };

    #[cfg(unix)]
    let mut _unix_guard = {
        let mut guard = crate::platform::unix::ProcessGroupGuard::new().ok();
        if let (Some(ref mut g), Some(pid)) = (&mut guard, child.id()) {
            g.set_child_pid(pid);
        }
        guard
    };

    let mut child_stdin = child.stdin.take().expect("Failed to open child stdin");
    let mut child_stdout = child.stdout.take().expect("Failed to open child stdout");
    let mut child_stderr = child.stderr.take().expect("Failed to open child stderr");

    let mut host_stdin = tokio::io::stdin();
    let mut host_stdout = tokio::io::stdout();
    let mut host_stderr = tokio::io::stderr();

    let server_name_str = server_name.unwrap_or_else(|| "MCP Server".to_string());
    let server_name_clone = server_name_str.clone();

    // Atomic STDOUT synchronization pipeline: prevents interleaving between child output and synthetic errors
    let (mut duplex_write, mut duplex_read) = tokio::io::duplex(65536);
    let (err_tx, mut err_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    let stdout_writer_task = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            tokio::select! {
                Some(err_bytes) = err_rx.recv() => {
                    if host_stdout.write_all(&err_bytes).await.is_err() {
                        break;
                    }
                    let _ = host_stdout.flush().await;
                }
                res = duplex_read.read(&mut buf) => {
                    match res {
                        Ok(0) => break, // EOF from child_stdout pipeline
                        Ok(n) => {
                            if host_stdout.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                            let _ = host_stdout.flush().await;
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        // Drain any remaining synthetic errors
        while let Ok(err_bytes) = err_rx.try_recv() {
            let _ = host_stdout.write_all(&err_bytes).await;
        }
        let _ = host_stdout.flush().await;
    });

    // Spawn async background tasks for stdin, stdout, stderr forwarding
    let in_task = tokio::spawn(async move {
        if tool_profile.is_some() || audit_enabled {
            let mut reader = BufReader::new(host_stdin).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                let trimmed = line.trim();

                if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                    match val {
                        serde_json::Value::Object(_) => {
                            if let Some(err_resp) = check_single_tool_request(
                                &val,
                                &tool_profile,
                                audit_enabled,
                                &server_name_clone,
                            ) {
                                let mut err_bytes = err_resp.to_string();
                                err_bytes.push('\n');
                                let _ = err_tx.send(err_bytes.into_bytes()).await;
                                continue; // Blocked: do not forward request to child
                            }
                        }
                        serde_json::Value::Array(ref mut arr) => {
                            let mut blocked_errors = Vec::new();
                            let mut allowed_requests = Vec::new();

                            for item in arr.drain(..) {
                                if let Some(err_resp) = check_single_tool_request(
                                    &item,
                                    &tool_profile,
                                    audit_enabled,
                                    &server_name_clone,
                                ) {
                                    blocked_errors.push(err_resp);
                                } else {
                                    allowed_requests.push(item);
                                }
                            }

                            if !blocked_errors.is_empty() {
                                let mut err_bytes = serde_json::to_string(
                                    &serde_json::Value::Array(blocked_errors),
                                )
                                .unwrap_or_default();
                                err_bytes.push('\n');
                                let _ = err_tx.send(err_bytes.into_bytes()).await;
                            }

                            if allowed_requests.is_empty() {
                                continue; // Entire batch blocked: nothing forwarded to child
                            }

                            // Forward allowed requests as a batch to child
                            val = serde_json::Value::Array(allowed_requests);
                            let mut payload = val.to_string();
                            payload.push('\n');
                            if child_stdin.write_all(payload.as_bytes()).await.is_err() {
                                break;
                            }
                            if child_stdin.flush().await.is_err() {
                                break;
                            }
                            continue;
                        }
                        _ => {}
                    }
                }

                // Normal unblocked forwarding
                let mut payload = line;
                payload.push('\n');
                if child_stdin.write_all(payload.as_bytes()).await.is_err() {
                    break;
                }
                if child_stdin.flush().await.is_err() {
                    break;
                }
            }
        } else {
            let _ = tokio::io::copy(&mut host_stdin, &mut child_stdin).await;
        }
    });

    let out_task = tokio::spawn(async move {
        if redact_secrets.is_empty() {
            let _ = tokio::io::copy(&mut child_stdout, &mut duplex_write).await;
        } else {
            let mut redactor = crate::redactor::StreamRedactor::new(&redact_secrets);
            let _ = redactor
                .pipe_and_redact(&mut child_stdout, &mut duplex_write)
                .await;
        }
    });

    let err_task = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut child_stderr, &mut host_stderr).await;
    });

    // Wait for the child process to exit with a 5-second graceful timeout once input terminates
    let status = match tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await {
        Ok(res) => res?,
        Err(_) => {
            eprintln!("[mcp-sentinel] Child process did not exit within timeout. Terminating...");
            let _ = child.kill().await;
            child.wait().await?
        }
    };

    // Close in_task, join stdout & stderr tasks
    in_task.abort();
    let _ = out_task.await;
    let _ = stdout_writer_task.await;
    let _ = err_task.await;

    Ok(status.code().unwrap_or(0))
}
