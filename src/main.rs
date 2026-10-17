use clap::Parser;
use std::collections::HashMap;
use std::process::exit;

use mcp_sentinel::cli::{Cli, Commands, PermCommands, SecretCommands};
use mcp_sentinel::{dialog, policy, proxy, sanitizer, tui, vault};

#[tokio::main]
async fn main() {
    // Direct all tracing logs strictly to STDERR so JSON-RPC on STDOUT remains uncorrupted
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::WARN.into()),
        )
        .init();

    let cli = Cli::parse();

    // Security Hardening: Anti-recursion / Child process isolation
    // If mcp-sentinel is invoked from within a child MCP process sandbox, block it immediately!
    if std::env::var("MCP_SENTINEL_CHILD_CONTEXT").is_ok() {
        eprintln!(
            "[mcp-sentinel] Security Violation: Invoking mcp-sentinel is strictly prohibited from within a child MCP sandbox."
        );
        exit(13);
    }

    match cli.command {
        Commands::Run { secrets, name, cmd } => {
            if cmd.is_empty() {
                eprintln!("[mcp-sentinel] Error: No command specified to run.");
                exit(1);
            }

            // Parse and validate all secret mappings
            let mappings = match vault::parse_specs(&secrets) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("[mcp-sentinel] Configuration Error: {}", e);
                    exit(1);
                }
            };

            let canonical_specs: Vec<String> =
                mappings.iter().map(|m| m.canonical_spec()).collect();
            let display_labels: Vec<String> = mappings.iter().map(|m| m.display_label()).collect();
            let display_name = name.clone().unwrap_or_else(|| cmd[0].clone());
            let fingerprint = policy::compute_fingerprint(&cmd);

            // 1. TOFU Authorization check
            if !mappings.is_empty() && !policy::is_authorized(&fingerprint, &canonical_specs) {
                eprintln!(
                    "[mcp-sentinel] Requesting user permission for '{}' (Fingerprint: {})...",
                    display_name,
                    &fingerprint[..12]
                );

                let allowed = dialog::ask_user_permission(&display_name, &display_labels);
                if !allowed {
                    eprintln!(
                        "[mcp-sentinel] Security Error: Access to secrets denied by user or timed out."
                    );
                    exit(1);
                }

                if let Err(e) = policy::record_grant(&fingerprint, name, &cmd, &canonical_specs) {
                    eprintln!(
                        "[mcp-sentinel] Warning: Failed to persist permission grant: {}",
                        e
                    );
                } else {
                    eprintln!("[mcp-sentinel] Permission granted and saved for future sessions.");
                }
            }

            // 2. Fetch secrets from OS Keyring
            let mut secrets_map = HashMap::new();
            for mapping in &mappings {
                match vault::get_secret(&mapping.vault_key) {
                    Ok(val) => {
                        secrets_map.insert(mapping.target_env.clone(), val);
                    }
                    Err(e) => {
                        eprintln!(
                            "[mcp-sentinel] Error: Secret '{}' not found in Keyring ({}). Please run 'mcp-sentinel secret set {} <value>' first.",
                            mapping.vault_key, e, mapping.vault_key
                        );
                        exit(1);
                    }
                }
            }

            // 3. Prepare clean environment
            let clean_env = sanitizer::build_sanitized_env(&secrets_map);

            // 4. Run proxy supervisor
            match proxy::run_child_and_pipe(&cmd, clean_env).await {
                Ok(code) => exit(code),
                Err(e) => {
                    eprintln!("[mcp-sentinel] Execution error: {}", e);
                    exit(1);
                }
            }
        }

        Commands::Secrets { action } => match action {
            SecretCommands::Set { key, value } => {
                if let Err(msg) = vault::validate_key_name(&key) {
                    eprintln!("Error: {}", msg);
                    exit(1);
                }
                match vault::set_secret(&key, &value) {
                    Ok(_) => println!("Secret '{}' successfully stored in OS Keyring.", key),
                    Err(e) => {
                        eprintln!("Error saving secret '{}': {}", key, e);
                        exit(1);
                    }
                }
            }
            SecretCommands::Get { key } => match vault::get_secret(&key) {
                Ok(val) => println!("{}", val),
                Err(e) => {
                    eprintln!("Error reading secret '{}': {}", key, e);
                    exit(1);
                }
            },
            SecretCommands::Delete { key } => match vault::delete_secret(&key) {
                Ok(_) => println!("Secret '{}' removed from OS Keyring.", key),
                Err(e) => {
                    eprintln!("Error deleting secret '{}': {}", key, e);
                    exit(1);
                }
            },
            SecretCommands::List => {
                let keys = vault::list_keys();
                if keys.is_empty() {
                    println!("No secrets stored in OS Keyring.");
                } else {
                    println!("Stored secret keys in OS Keyring ({}):", keys.len());
                    for key in keys {
                        println!("  - {}", key);
                    }
                }
            }
        },

        Commands::Permissions { action } => match action {
            PermCommands::List => {
                let policy = policy::load_policy();
                if policy.grants.is_empty() {
                    println!("No permissions have been granted yet.");
                } else {
                    println!(
                        "{:<14} {:<30} {:<30} {:<24}",
                        "ID", "NAME/COMMAND", "SECRETS", "CREATED AT"
                    );
                    println!("{:-<100}", "");
                    for (id, grant) in policy.grants {
                        let id_short = if id.len() > 12 { &id[..12] } else { &id };
                        let label = grant.name.unwrap_or(grant.command);
                        let label_short = if label.len() > 28 {
                            format!("{}...", &label[..25])
                        } else {
                            label
                        };
                        let sec_str = grant.granted_secrets.join(", ");
                        let sec_short = if sec_str.len() > 28 {
                            format!("{}...", &sec_str[..25])
                        } else {
                            sec_str
                        };
                        println!(
                            "{:<14} {:<30} {:<30} {:<24}",
                            id_short,
                            label_short,
                            sec_short,
                            grant.created_at.to_rfc3339()
                        );
                    }
                }
            }
            PermCommands::Revoke { id } => match policy::revoke_grant(&id) {
                Ok(true) => println!("Permission '{}' has been revoked.", id),
                Ok(false) => {
                    println!("No grant found with ID '{}'.", id);
                    exit(1);
                }
                Err(e) => {
                    eprintln!("Error revoking grant: {}", e);
                    exit(1);
                }
            },
            PermCommands::Reset => match policy::reset_grants() {
                Ok(_) => println!("All permissions have been reset."),
                Err(e) => {
                    eprintln!("Error resetting permissions: {}", e);
                    exit(1);
                }
            },
        },

        Commands::Ui => {
            if let Err(e) = tui::run_tui() {
                eprintln!("[mcp-sentinel] TUI error: {}", e);
                exit(1);
            }
        }

        Commands::Migrate {
            target,
            file,
            dry_run,
            no_backup,
        } => {
            let files_to_migrate = if let Some(custom_file) = file {
                vec![custom_file]
            } else {
                let t = target.unwrap_or(mcp_sentinel::migrate::MigrateTarget::All);
                let discovered = mcp_sentinel::migrate::find_config_paths(t);
                if discovered.is_empty() {
                    println!(
                        "[mcp-sentinel] No standard MCP configuration files found for target '{:?}'.",
                        t
                    );
                    println!(
                        "Tip: Specify the file directly using: mcp-sentinel migrate --file <PATH>"
                    );
                    return;
                }
                discovered
            };

            if dry_run {
                println!("🔍 Running migration in DRY-RUN mode (no changes will be applied)...\n");
            }

            for path in files_to_migrate {
                println!("📦 Migrating: {}", path.display());
                match mcp_sentinel::migrate::migrate_file(&path, dry_run, no_backup) {
                    Ok(report) => {
                        if let Some(bak) = report.backup_path {
                            println!("   📄 Created backup at: {}", bak.display());
                        }
                        for res in report.results {
                            if res.already_migrated {
                                println!(
                                    "   ⏭️  [{}] Already migrated with mcp-sentinel.",
                                    res.server_name
                                );
                            } else {
                                println!("   ✅ [{}] {}", res.server_name, res.status);
                                for sec in res.extracted_secrets {
                                    println!("      🔑 Stored secret '{}' in Keyring", sec);
                                }
                            }
                        }
                        println!();
                    }
                    Err(e) => {
                        eprintln!("   ❌ Failed to migrate '{}': {}", path.display(), e);
                    }
                }
            }
            if dry_run {
                println!("✨ Dry run complete! Run without '--dry-run' to execute the migration.");
            } else {
                println!(
                    "🎉 Migration complete! Your MCP servers are now protected with Zero-Trust."
                );
            }
        }
    }
}
