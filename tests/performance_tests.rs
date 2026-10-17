use mcp_sentinel::policy::compute_fingerprint;
use mcp_sentinel::sanitizer::build_sanitized_env;
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

#[test]
fn bench_fingerprint_computation_10000_ops() {
    let cmd = vec![
        "npx".to_string(),
        "-y".to_string(),
        "@modelcontextprotocol/server-postgres".to_string(),
        "postgresql://user:password@localhost:5432/production_db".to_string(),
    ];

    let start = Instant::now();
    let iterations = 10_000;

    for _ in 0..iterations {
        let fp = compute_fingerprint(&cmd);
        // Verify output sanity
        assert_eq!(fp.len(), 64);
    }

    let elapsed = start.elapsed();
    let ops_per_sec = (iterations as f64) / elapsed.as_secs_f64();

    println!(
        "\n[PERF BENCHMARK] Fingerprint: 10,000 ops completed in {:.2?} (~{:.0} ops/sec)",
        elapsed, ops_per_sec
    );

    // 10k SHA-256 hashes in Rust should comfortably finish in under 500ms
    assert!(
        elapsed.as_millis() < 500,
        "Fingerprint hashing too slow: {:?}",
        elapsed
    );
}

#[test]
fn bench_sanitizer_environment_building_10000_ops() {
    let mut secrets = HashMap::new();
    secrets.insert("GITHUB_TOKEN".to_string(), "ghp_123456789".to_string());
    secrets.insert(
        "DATABASE_URL".to_string(),
        "postgres://localhost/db".to_string(),
    );
    secrets.insert("API_KEY".to_string(), "secret_api_key_abc".to_string());

    let start = Instant::now();
    let iterations = 10_000;

    for _ in 0..iterations {
        let clean_env = build_sanitized_env(&secrets);
        assert_eq!(
            clean_env.get("GITHUB_TOKEN"),
            Some(&"ghp_123456789".to_string())
        );
    }

    let elapsed = start.elapsed();
    let ops_per_sec = (iterations as f64) / elapsed.as_secs_f64();

    println!(
        "[PERF BENCHMARK] Sanitizer: 10,000 ops completed in {:.2?} (~{:.0} ops/sec)",
        elapsed, ops_per_sec
    );

    // 10k environment sanitizations (170,000 OS syscalls) in debug profile
    assert!(
        elapsed.as_secs() < 10,
        "Environment sanitization too slow: {:?}",
        elapsed
    );
}

#[test]
fn bench_concurrent_fingerprint_multithreading() {
    let thread_count = 16;
    let ops_per_thread = 2_000;
    let cmd = Arc::new(vec![
        "python".to_string(),
        "-m".to_string(),
        "mcp_server".to_string(),
        "--port".to_string(),
        "8080".to_string(),
    ]);

    let start = Instant::now();
    let mut handles = Vec::new();

    for _ in 0..thread_count {
        let cmd_clone = Arc::clone(&cmd);
        handles.push(thread::spawn(move || {
            for _ in 0..ops_per_thread {
                let fp = compute_fingerprint(&cmd_clone);
                assert_eq!(fp.len(), 64);
            }
        }));
    }

    for h in handles {
        h.join().expect("Thread should not panic");
    }

    let elapsed = start.elapsed();
    let total_ops = thread_count * ops_per_thread;
    let ops_per_sec = (total_ops as f64) / elapsed.as_secs_f64();

    println!(
        "[PERF BENCHMARK] Multithreaded Hashing ({} threads): {} total ops in {:.2?} (~{:.0} ops/sec)",
        thread_count, total_ops, elapsed, ops_per_sec
    );

    assert!(elapsed.as_secs() < 1);
}

#[test]
fn bench_stdio_stream_high_throughput() {
    // Test piping 5,000 JSON lines through mcp-sentinel to verify streaming throughput
    let script = r#"
        const readline = require('readline');
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: false });
        rl.on('line', (line) => {
            process.stdout.write(line + '\n');
        });
    "#;

    let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-sentinel"))
        .args(["run", "--", "node", "-e", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn mcp-sentinel child");

    let mut stdin = child.stdin.take().expect("Child stdin should be open");

    let num_lines = 5_000;
    let start = Instant::now();

    // Stream lines into stdin in a background thread
    let writer_thread = thread::spawn(move || {
        for i in 0..num_lines {
            writeln!(stdin, r#"{{"jsonrpc":"2.0","method":"ping","id":{}}}"#, i)
                .expect("Write to stdin failed");
        }
        // stdin dropped here, sending EOF
    });

    writer_thread.join().expect("Writer thread finished");

    let output = child.wait_with_output().expect("Failed to read output");
    let elapsed = start.elapsed();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line_count = stdout.lines().count();

    println!(
        "[PERF BENCHMARK] Stdio Streaming: {} JSON-RPC messages piped in {:.2?} ({:.0} msgs/sec, payload size: {} KB)",
        line_count,
        elapsed,
        (line_count as f64) / elapsed.as_secs_f64(),
        output.stdout.len() / 1024
    );

    assert_eq!(line_count, num_lines, "Zero messages dropped");
}
