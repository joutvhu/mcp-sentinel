use std::collections::HashMap;
use std::process::Stdio;
use tokio::process::Command;

pub async fn run_child_and_pipe(
    cmd_args: &[String],
    env_vars: HashMap<String, String>,
    redact_secrets: Vec<String>,
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

    // Spawn async background tasks for stdin, stdout, stderr forwarding
    let in_task = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut host_stdin, &mut child_stdin).await;
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
