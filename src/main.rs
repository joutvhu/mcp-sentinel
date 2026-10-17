use clap::Parser;
use std::collections::HashMap;
use std::process::exit;

use mcp_sentinel::cli::{
    AuditCommands, Cli, Commands, PermCommands, SecretCommands, ToolPolicyCommands,
};
use mcp_sentinel::{audit, dialog, policy, proxy, sanitizer, tool_policy, tui, vault};

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
        Commands::Run {
            secrets,
            name,
            no_redact,
            allow_once,
            profile,
            deny_tools,
            allow_tools,
            audit,
            cmd,
        } => {
            if cmd.is_empty() {
                eprintln!("[mcp-sentinel] Error: No command specified to run.");
                exit(1);
            }

            let audit_enabled = audit::is_audit_enabled(audit);

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
            let is_pre_authorized = policy::is_authorized(&fingerprint, &canonical_specs);
            if !mappings.is_empty() && !is_pre_authorized {
                eprintln!(
                    "[mcp-sentinel] Requesting user permission for '{}' (Fingerprint: {})...",
                    display_name,
                    &fingerprint[..12]
                );

                let decision = dialog::ask_user_permission(&display_name, &display_labels);
                match decision {
                    dialog::AuthDecision::Deny => {
                        eprintln!(
                            "[mcp-sentinel] Security Error: Access to secrets denied by user or timed out."
                        );

                        if audit_enabled {
                            let _ = audit::log_event(&audit::AuditEntry {
                                timestamp: chrono::Utc::now(),
                                event: audit::AuditEventType::TofuDecision,
                                server_name: Some(display_name.clone()),
                                command: Some(cmd.join(" ")),
                                tool_name: None,
                                decision: Some("DENY".to_string()),
                                reason: Some("User rejected authorization prompt".to_string()),
                                secrets: Some(canonical_specs.clone()),
                                profile: profile.clone(),
                                exit_code: None,
                            });
                        }

                        exit(1);
                    }
                    dialog::AuthDecision::AllowOnce => {
                        eprintln!(
                            "[mcp-sentinel] Permission granted for this session only (Allow Once). Will prompt again on next launch."
                        );

                        if audit_enabled {
                            let _ = audit::log_event(&audit::AuditEntry {
                                timestamp: chrono::Utc::now(),
                                event: audit::AuditEventType::TofuDecision,
                                server_name: Some(display_name.clone()),
                                command: Some(cmd.join(" ")),
                                tool_name: None,
                                decision: Some("ALLOW_ONCE".to_string()),
                                reason: None,
                                secrets: Some(canonical_specs.clone()),
                                profile: profile.clone(),
                                exit_code: None,
                            });
                        }
                    }
                    dialog::AuthDecision::AllowAlways => {
                        if allow_once {
                            eprintln!(
                                "[mcp-sentinel] Permission granted for this session only (--allow-once flag specified)."
                            );
                        } else if let Err(e) =
                            policy::record_grant(&fingerprint, name, &cmd, &canonical_specs)
                        {
                            eprintln!(
                                "[mcp-sentinel] Warning: Failed to persist permission grant: {}",
                                e
                            );
                        } else {
                            eprintln!(
                                "[mcp-sentinel] Permission granted and saved for future sessions."
                            );
                        }

                        if audit_enabled {
                            let _ = audit::log_event(&audit::AuditEntry {
                                timestamp: chrono::Utc::now(),
                                event: audit::AuditEventType::TofuDecision,
                                server_name: Some(display_name.clone()),
                                command: Some(cmd.join(" ")),
                                tool_name: None,
                                decision: Some(if allow_once {
                                    "ALLOW_ONCE".to_string()
                                } else {
                                    "ALLOW_ALWAYS".to_string()
                                }),
                                reason: None,
                                secrets: Some(canonical_specs.clone()),
                                profile: profile.clone(),
                                exit_code: None,
                            });
                        }
                    }
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

            // 4. Determine secrets to redact on stdout (DLP filter)
            let redact_secrets: Vec<String> = if no_redact {
                Vec::new()
            } else {
                secrets_map.values().cloned().collect()
            };

            // 5. Resolve Tool Policy Profile (Layer 7 tool call firewall)
            let mut effective_tool_profile = if let Some(ref prof_name) = profile {
                match tool_policy::get_profile(prof_name) {
                    Some(p) => Some(p),
                    None => {
                        eprintln!(
                            "[mcp-sentinel] Error: Tool policy profile '{}' not found. Run 'mcp-sentinel profile list' to view available profiles.",
                            prof_name
                        );
                        exit(1);
                    }
                }
            } else if !deny_tools.is_empty() || !allow_tools.is_empty() {
                Some(tool_policy::ToolProfile {
                    name: "ad-hoc".to_string(),
                    description: Some("Ad-hoc CLI tool policy rules".to_string()),
                    allow: Vec::new(),
                    deny: Vec::new(),
                })
            } else {
                None
            };

            if let Some(ref mut p) = effective_tool_profile {
                for d in deny_tools {
                    if !p.deny.contains(&d) {
                        p.deny.push(d);
                    }
                }
                for a in allow_tools {
                    if !p.allow.contains(&a) {
                        p.allow.push(a);
                    }
                }
            }

            // Audit: Log Server Start
            if audit_enabled {
                let _ = audit::log_event(&audit::AuditEntry {
                    timestamp: chrono::Utc::now(),
                    event: audit::AuditEventType::ServerStart,
                    server_name: Some(display_name.clone()),
                    command: Some(cmd.join(" ")),
                    tool_name: None,
                    decision: None,
                    reason: None,
                    secrets: Some(canonical_specs.clone()),
                    profile: effective_tool_profile.as_ref().map(|p| p.name.clone()),
                    exit_code: None,
                });
            }

            // 6. Run proxy supervisor
            match proxy::run_child_and_pipe(
                &cmd,
                clean_env,
                redact_secrets,
                effective_tool_profile,
                audit_enabled,
                Some(display_name.clone()),
            )
            .await
            {
                Ok(code) => {
                    if audit_enabled {
                        let _ = audit::log_event(&audit::AuditEntry {
                            timestamp: chrono::Utc::now(),
                            event: audit::AuditEventType::ServerExit,
                            server_name: Some(display_name),
                            command: Some(cmd.join(" ")),
                            tool_name: None,
                            decision: None,
                            reason: None,
                            secrets: None,
                            profile: None,
                            exit_code: Some(code),
                        });
                    }
                    exit(code);
                }
                Err(e) => {
                    eprintln!("[mcp-sentinel] Execution error: {}", e);
                    if audit_enabled {
                        let _ = audit::log_event(&audit::AuditEntry {
                            timestamp: chrono::Utc::now(),
                            event: audit::AuditEventType::ServerExit,
                            server_name: Some(display_name),
                            command: Some(cmd.join(" ")),
                            tool_name: None,
                            decision: None,
                            reason: Some(format!("Error: {}", e)),
                            secrets: None,
                            profile: None,
                            exit_code: Some(1),
                        });
                    }
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

        Commands::ToolPolicy { action } => {
            match action {
                ToolPolicyCommands::List => {
                    let file = match tool_policy::load_profiles() {
                        Ok(f) => f,
                        Err(e) => {
                            eprintln!("Error loading tool profiles: {}", e);
                            exit(1);
                        }
                    };

                    if file.profiles.is_empty() {
                        println!("No tool policy profiles found.");
                        println!("Tip: Create one using 'mcp-sentinel profile set <NAME> --deny <PATTERNS>'");
                        return;
                    }

                    println!(
                        "{:<18} {:<32} {:<24} {:<24}",
                        "PROFILE", "DESCRIPTION", "ALLOWED TOOLS", "DENIED TOOLS"
                    );
                    println!("{:-<18} {:-<32} {:-<24} {:-<24}", "", "", "", "");

                    let mut sorted_keys: Vec<&String> = file.profiles.keys().collect();
                    sorted_keys.sort();

                    for name in sorted_keys {
                        let prof = &file.profiles[name];
                        let desc = prof.description.as_deref().unwrap_or("-");
                        let desc_short = if desc.len() > 30 {
                            format!("{}...", &desc[..27])
                        } else {
                            desc.to_string()
                        };
                        let allow_str = if prof.allow.is_empty() {
                            "* (all)".to_string()
                        } else {
                            prof.allow.join(", ")
                        };
                        let allow_short = if allow_str.len() > 22 {
                            format!("{}...", &allow_str[..19])
                        } else {
                            allow_str
                        };
                        let deny_str = if prof.deny.is_empty() {
                            "none".to_string()
                        } else {
                            prof.deny.join(", ")
                        };
                        let deny_short = if deny_str.len() > 22 {
                            format!("{}...", &deny_str[..19])
                        } else {
                            deny_str
                        };
                        println!(
                            "{:<18} {:<32} {:<24} {:<24}",
                            name, desc_short, allow_short, deny_short
                        );
                    }
                }
                ToolPolicyCommands::Get { name } => match tool_policy::get_profile(&name) {
                    Some(prof) => {
                        println!("Profile:     {}", prof.name);
                        if let Some(desc) = prof.description {
                            println!("Description: {}", desc);
                        }
                        let allow_str = if prof.allow.is_empty() {
                            "* (all not denied)".to_string()
                        } else {
                            prof.allow.join(", ")
                        };
                        println!("Allowed:     {}", allow_str);
                        let deny_str = if prof.deny.is_empty() {
                            "none".to_string()
                        } else {
                            prof.deny.join(", ")
                        };
                        println!("Denied:      {}", deny_str);
                    }
                    None => {
                        eprintln!("Error: Profile '{}' not found.", name);
                        exit(1);
                    }
                },
                ToolPolicyCommands::Set {
                    name,
                    allow,
                    deny,
                    description,
                } => {
                    let prof = tool_policy::ToolProfile {
                        name: name.clone(),
                        description,
                        allow,
                        deny,
                    };
                    match tool_policy::upsert_profile(prof) {
                        Ok(_) => println!("Tool policy profile '{}' successfully saved.", name),
                        Err(e) => {
                            eprintln!("Error saving profile '{}': {}", name, e);
                            exit(1);
                        }
                    }
                }
                ToolPolicyCommands::Delete { name } => match tool_policy::delete_profile(&name) {
                    Ok(true) => println!("Tool policy profile '{}' deleted successfully.", name),
                    Ok(false) => {
                        eprintln!("Error: Profile '{}' does not exist.", name);
                        exit(1);
                    }
                    Err(e) => {
                        eprintln!("Error deleting profile '{}': {}", name, e);
                        exit(1);
                    }
                },
            }
        }

        Commands::Audit { action } => match action {
            AuditCommands::List {
                limit,
                blocked_only,
                event,
            } => {
                let event_filter = if let Some(ref e_str) = event {
                    match e_str.parse::<audit::AuditEventType>() {
                        Ok(ev) => Some(ev),
                        Err(err) => {
                            eprintln!("Error: {}", err);
                            exit(1);
                        }
                    }
                } else {
                    None
                };

                match audit::read_entries(limit, event_filter, blocked_only) {
                    Ok(entries) => {
                        if entries.is_empty() {
                            println!("No audit log events found.");
                            println!("Tip: Enable audit logging using 'mcp-sentinel run --audit -- <COMMAND>' or set MCP_SENTINEL_AUDIT=1.");
                            return;
                        }

                        println!(
                            "{:<20} {:<15} {:<18} {:<22} {:<10} {:<24}",
                            "TIMESTAMP (UTC)", "EVENT", "SERVER", "TOOL", "DECISION", "DETAIL"
                        );
                        println!("{:-<112}", "");

                        for entry in entries {
                            let ts = entry.timestamp.format("%Y-%m-%d %H:%M:%S").to_string();
                            let srv = entry.server_name.unwrap_or_else(|| "-".to_string());
                            let tool = entry.tool_name.unwrap_or_else(|| "-".to_string());
                            let dec = entry.decision.unwrap_or_else(|| "-".to_string());
                            let detail = if let Some(code) = entry.exit_code {
                                format!("Exit Code: {}", code)
                            } else if let Some(r) = entry.reason {
                                r
                            } else if let Some(secs) = entry.secrets {
                                format!("Secrets: {}", secs.join(","))
                            } else {
                                "-".to_string()
                            };

                            let srv_short = if srv.len() > 16 {
                                format!("{}...", &srv[..13])
                            } else {
                                srv
                            };

                            let tool_short = if tool.len() > 20 {
                                format!("{}...", &tool[..17])
                            } else {
                                tool
                            };

                            let detail_short = if detail.len() > 23 {
                                format!("{}...", &detail[..20])
                            } else {
                                detail
                            };

                            println!(
                                "{:<20} {:<15} {:<18} {:<22} {:<10} {:<24}",
                                ts, entry.event, srv_short, tool_short, dec, detail_short
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("Error reading audit log: {}", e);
                        exit(1);
                    }
                }
            }
            AuditCommands::Clear => match audit::clear_log() {
                Ok(true) => println!("✓ Security audit log cleared successfully."),
                Ok(false) => println!("Audit log was already empty or not present."),
                Err(e) => {
                    eprintln!("Error clearing audit log: {}", e);
                    exit(1);
                }
            },
            AuditCommands::Status => match audit::get_audit_status() {
                Ok(status) => {
                    println!("Security Audit Subsystem Status:");
                    println!("  Default State:     Disabled (Zero-Disk Footprint / Opt-in)");
                    println!(
                        "  Active via Env:    {}",
                        if status.is_env_enabled {
                            "Yes (MCP_SENTINEL_AUDIT is set)"
                        } else {
                            "No"
                        }
                    );
                    println!("  Log File Path:     {}", status.log_path.display());
                    println!(
                        "  File Exists:       {}",
                        if status.log_exists { "Yes" } else { "No" }
                    );
                    println!("  Total Entries:     {}", status.total_entries);
                    println!(
                        "  File Size:         {:.2} KB",
                        status.file_size_bytes as f64 / 1024.0
                    );
                    println!(
                        "\nTip: Enable auditing per-session with 'mcp-sentinel run --audit -- <COMMAND>'."
                    );
                }
                Err(e) => {
                    eprintln!("Error retrieving audit status: {}", e);
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
