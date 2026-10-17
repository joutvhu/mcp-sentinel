use std::collections::HashMap;
use std::process::Stdio;
use tokio::process::Command;

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

    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn()?;

    // Attach child process to Windows Job Object for lifecycle guard
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

    let mut child_stdin = child.stdin.take().expect("Failed to open child stdin");
    let mut child_stdout = child.stdout.take().expect("Failed to open child stdout");
    let mut child_stderr = child.stderr.take().expect("Failed to open child stderr");

    let mut host_stdin = tokio::io::stdin();
    let mut host_stdout = tokio::io::stdout();
    let mut host_stderr = tokio::io::stderr();

    let server_name_clone = server_name.clone();

    // Spawn async background tasks for stdin, stdout, stderr forwarding
    let in_task = tokio::spawn(async move {
        if tool_profile.is_some() || audit_enabled {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let mut reader = BufReader::new(host_stdin).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                let trimmed = line.trim();
                let mut is_blocked = false;

                if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                    if val.get("method").and_then(|m| m.as_str()) == Some("tools/call") {
                        if let Some(tool_name) = val
                            .get("params")
                            .and_then(|p| p.get("name"))
                            .and_then(|n| n.as_str())
                        {
                            if let Some(ref profile) = tool_profile {
                                let decision =
                                    crate::tool_policy::evaluate_tool_call(tool_name, profile);
                                if let crate::tool_policy::ToolDecision::Blocked { reason } =
                                    decision
                                {
                                    is_blocked = true;
                                    eprintln!(
                                        "[mcp-sentinel] Security Alert: Blocked unauthorized tool call '{}' by policy '{}': {}",
                                        tool_name, profile.name, reason
                                    );

                                    if audit_enabled {
                                        let _ =
                                            crate::audit::log_event(&crate::audit::AuditEntry {
                                                timestamp: chrono::Utc::now(),
                                                event:
                                                    crate::audit::AuditEventType::ToolCallBlocked,
                                                server_name: server_name_clone.clone(),
                                                command: None,
                                                tool_name: Some(tool_name.to_string()),
                                                decision: Some("BLOCKED".to_string()),
                                                reason: Some(reason.clone()),
                                                secrets: None,
                                                profile: Some(profile.name.clone()),
                                                exit_code: None,
                                            });
                                    }

                                    let id =
                                        val.get("id").cloned().unwrap_or(serde_json::Value::Null);
                                    let err_resp = serde_json::json!({
                                        "jsonrpc": "2.0",
                                        "id": id,
                                        "error": {
                                            "code": -32001,
                                            "message": format!(
                                                "[MCP-SENTINEL] Tool '{}' is blocked by security policy '{}': {}",
                                                tool_name, profile.name, reason
                                            )
                                        }
                                    });

                                    let mut err_bytes = err_resp.to_string();
                                    err_bytes.push('\n');
                                    let mut stdout = tokio::io::stdout();
                                    let _ = stdout.write_all(err_bytes.as_bytes()).await;
                                    let _ = stdout.flush().await;
                                } else if audit_enabled {
                                    let _ = crate::audit::log_event(&crate::audit::AuditEntry {
                                        timestamp: chrono::Utc::now(),
                                        event: crate::audit::AuditEventType::ToolCallAllowed,
                                        server_name: server_name_clone.clone(),
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
                                    server_name: server_name_clone.clone(),
                                    command: None,
                                    tool_name: Some(tool_name.to_string()),
                                    decision: Some("ALLOWED".to_string()),
                                    reason: None,
                                    secrets: None,
                                    profile: None,
                                    exit_code: None,
                                });
                            }
                        }
                    }
                }

                if !is_blocked {
                    let mut payload = line;
                    payload.push('\n');
                    if child_stdin.write_all(payload.as_bytes()).await.is_err() {
                        break;
                    }
                    if child_stdin.flush().await.is_err() {
                        break;
                    }
                }
            }
        } else {
            let _ = tokio::io::copy(&mut host_stdin, &mut child_stdin).await;
        }
    });

    let out_task = tokio::spawn(async move {
        if redact_secrets.is_empty() {
            let _ = tokio::io::copy(&mut child_stdout, &mut host_stdout).await;
        } else {
            let mut redactor = crate::redactor::StreamRedactor::new(&redact_secrets);
            let _ = redactor
                .pipe_and_redact(&mut child_stdout, &mut host_stdout)
                .await;
        }
    });

    let err_task = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut child_stderr, &mut host_stderr).await;
    });

    // Wait for the child process to exit
    let status = child.wait().await?;

    // Allow stdout & stderr to finish draining remaining child output
    let _ = tokio::join!(out_task, err_task);

    // Cancel host stdin reader if still waiting for input
    in_task.abort();

    Ok(status.code().unwrap_or(0))
}
