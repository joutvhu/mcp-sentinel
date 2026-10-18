use std::collections::HashMap;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

    let tool_name = match req
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
    {
        Some(name) => name,
        None => {
            // Fail-closed: The request declares method "tools/call" but parameter 'name' is missing or not a string
            eprintln!(
                "[mcp-sentinel] Security Violation: Blocked malformed tool call missing valid 'name' parameter"
            );

            if audit_enabled {
                let _ = crate::audit::log_event(&crate::audit::AuditEntry {
                    timestamp: chrono::Utc::now(),
                    event: crate::audit::AuditEventType::ToolCallBlocked,
                    server_name: Some(server_name.to_string()),
                    command: None,
                    tool_name: Some("<MALFORMED_NAME>".to_string()),
                    decision: Some("BLOCKED".to_string()),
                    reason: Some("Missing or non-string 'params.name' parameter".to_string()),
                    secrets: None,
                    profile: tool_profile.as_ref().map(|p| p.name.clone()),
                    exit_code: None,
                });
            }

            let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
            return Some(serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32602,
                    "message": "[MCP-SENTINEL] Malformed tool call: 'params.name' string parameter is required."
                }
            }));
        }
    };

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
        let mut child_buf = Vec::new();
        let mut raw_buf = [0u8; 8192];
        let mut stdout_at_newline = true;
        let mut err_rx_closed = false;
        loop {
            tokio::select! {
                // Synthetic errors are written immediately without corrupting in-progress child output
                msg = err_rx.recv(), if !err_rx_closed => {
                    match msg {
                        Some(err_bytes) => {
                            if !stdout_at_newline {
                                if host_stdout.write_all(b"\n").await.is_err() {
                                    break;
                                }
                            }
                            if host_stdout.write_all(&err_bytes).await.is_err() {
                                break;
                            }
                            let _ = host_stdout.flush().await;
                            stdout_at_newline = err_bytes.last() == Some(&b'\n');
                        }
                        None => {
                            err_rx_closed = true;
                        }
                    }
                }
                res = duplex_read.read(&mut raw_buf) => {
                    match res {
                        Ok(0) => {
                            if !child_buf.is_empty() {
                                let _ = host_stdout.write_all(&child_buf).await;
                                let _ = host_stdout.flush().await;
                                child_buf.clear();
                            }
                            break;
                        }
                        Ok(n) => {
                            child_buf.extend_from_slice(&raw_buf[..n]);
                            // Only flush complete lines ending in \n to prevent corrupting concurrent writes
                            if let Some(last_nl) = child_buf.iter().rposition(|&b| b == b'\n') {
                                let to_write = &child_buf[..=last_nl];
                                if host_stdout.write_all(to_write).await.is_err() {
                                    break;
                                }
                                let _ = host_stdout.flush().await;
                                stdout_at_newline = true;
                                child_buf.drain(..=last_nl);
                            } else if child_buf.len() >= 65536 {
                                // Safeguard against unbounded memory growth if child sends massive stream without newline
                                let ends_with_nl = child_buf.last() == Some(&b'\n');
                                if host_stdout.write_all(&child_buf).await.is_err() {
                                    break;
                                }
                                let _ = host_stdout.flush().await;
                                stdout_at_newline = ends_with_nl;
                                child_buf.clear();
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        // Drain any remaining child_buf
        if !child_buf.is_empty() {
            let _ = host_stdout.write_all(&child_buf).await;
            if child_buf.last() != Some(&b'\n') {
                let _ = host_stdout.write_all(b"\n").await;
            }
            child_buf.clear();
        }
        // Drain any remaining synthetic errors
        while let Ok(err_bytes) = err_rx.try_recv() {
            let _ = host_stdout.write_all(&err_bytes).await;
        }
        let _ = host_stdout.flush().await;
    });

    // Spawn async background tasks for stdin, stdout, stderr forwarding
    let mut in_task = tokio::spawn(async move {
        if tool_profile.is_some() || audit_enabled {
            let mut in_buf = Vec::new();
            let mut read_buf = [0u8; 8192];

            loop {
                let n = match host_stdin.read(&mut read_buf).await {
                    Ok(0) => break, // EOF
                    Ok(n) => n,
                    Err(_) => break,
                };
                in_buf.extend_from_slice(&read_buf[..n]);

                loop {
                    // Skip leading whitespace
                    let start_idx = in_buf
                        .iter()
                        .position(|b| !b.is_ascii_whitespace())
                        .unwrap_or(in_buf.len());
                    if start_idx > 0 {
                        in_buf.drain(..start_idx);
                    }
                    if in_buf.is_empty() {
                        break;
                    }

                    // Attempt to parse a complete JSON value from the stream buffer
                    let mut de = serde_json::Deserializer::from_slice(&in_buf)
                        .into_iter::<serde_json::Value>();
                    match de.next() {
                        Some(Ok(mut val)) => {
                            let consumed = de.byte_offset();
                            in_buf.drain(..consumed);

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
                                        continue; // Entire batch blocked
                                    }

                                    val = serde_json::Value::Array(allowed_requests);
                                }
                                _ => {}
                            }

                            // Forward allowed JSON to child stdin
                            let mut payload = val.to_string();
                            payload.push('\n');
                            if child_stdin.write_all(payload.as_bytes()).await.is_err() {
                                return;
                            }
                            if child_stdin.flush().await.is_err() {
                                return;
                            }
                        }
                        Some(Err(ref e)) if e.is_eof() => {
                            // Incomplete JSON value: wait for more bytes from host_stdin
                            break;
                        }
                        Some(Err(_)) => {
                            // Non-JSON line or syntax error: forward up to next newline if present
                            if let Some(pos) = in_buf.iter().position(|&b| b == b'\n') {
                                let chunk: Vec<u8> = in_buf.drain(..=pos).collect();
                                if child_stdin.write_all(&chunk).await.is_err() {
                                    return;
                                }
                                let _ = child_stdin.flush().await;
                            } else {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }

            // Flush remaining buffer at EOF if non-empty
            if !in_buf.is_empty() {
                let _ = child_stdin.write_all(&in_buf).await;
                let _ = child_stdin.flush().await;
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
    // We wait for EITHER:
    // 1. The child process exits on its own (child.wait() completes).
    // 2. OR host STDIN reaches EOF (in_task finishes). Once STDIN closes, we give the child
    //    a graceful 5-second timeout to exit before sending kill.
    let status = tokio::select! {
        res = child.wait() => {
            res?
        }
        _ = &mut in_task => {
            // STDIN closed by client. Give child 5 seconds to gracefully exit
            match tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await {
                Ok(res) => res?,
                Err(_) => {
                    eprintln!("[mcp-sentinel] Child process did not exit within 5s after STDIN closed. Terminating...");
                    let _ = child.kill().await;
                    child.wait().await?
                }
            }
        }
    };

    // Abort in_task to avoid lingering task reading host_stdin if child exited first
    in_task.abort();

    // Join remaining forwarding tasks
    let _ = out_task.await;
    let _ = stdout_writer_task.await;
    let _ = err_task.await;

    Ok(status.code().unwrap_or(0))
}
