use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "mcp-sentinel",
    author = "Giáo Hồ",
    version,
    about = "Zero-Trust Secret Vault & Security Proxy for Model Context Protocol (MCP)",
    long_about = "mcp-sentinel isolates environment variables, injects secrets directly from the OS Keychain, and prompts for user authorization on first execution."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Execute an MCP Server within a secured, isolated sandbox
    Run {
        /// Comma-separated list of required secrets or alias mappings (e.g., GITHUB_TOKEN,API_KEY=OPENAI_KEY)
        #[arg(short, long, value_delimiter = ',')]
        secrets: Vec<String>,

        /// Comma-separated list of non-secret host environment variables to pass through
        #[arg(long, alias = "env", value_delimiter = ',')]
        pass_env: Vec<String>,

        /// Optional descriptive name for the MCP server
        #[arg(short, long)]
        name: Option<String>,

        /// Disable automatic Data Loss Prevention (DLP) secret masking on stdout
        #[arg(long)]
        no_redact: bool,

        /// Authorize this execution once without persisting permission to permissions.json
        #[arg(long, alias = "once")]
        allow_once: bool,

        /// Pre-configured Tool Policy Profile to enforce (e.g., read-only, no-destructive)
        #[arg(long)]
        profile: Option<String>,

        /// Comma-separated list of tool name patterns to block (e.g., *drop*,*delete*)
        #[arg(long, value_delimiter = ',')]
        deny_tools: Vec<String>,

        /// Comma-separated list of tool name patterns to allow exclusively (e.g., read_*,get_*)
        #[arg(long, value_delimiter = ',')]
        allow_tools: Vec<String>,

        /// Enable Security Audit Logging (default: false / disabled). Writes security events and tool call history to audit.log
        #[arg(long)]
        audit: bool,

        /// Command and arguments to execute (after --)
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },

    /// Manage secrets stored in the OS Keyring
    #[command(alias = "secret")]
    Secrets {
        #[command(subcommand)]
        action: SecretCommands,
    },

    /// Manage permissions granted to MCP servers (TOFU policy)
    #[command(alias = "permission", alias = "perm", alias = "perms")]
    Permissions {
        #[command(subcommand)]
        action: PermCommands,
    },

    /// Manage tool call access policies and profiles (Layer 7 firewall)
    #[command(alias = "profile", alias = "profiles")]
    ToolPolicy {
        #[command(subcommand)]
        action: ToolPolicyCommands,
    },

    /// Inspect, query, or purge security audit logs
    #[command(alias = "audits")]
    Audit {
        #[command(subcommand)]
        action: AuditCommands,
    },

    /// Launch the interactive Terminal User Interface (TUI) Dashboard
    #[command(alias = "tui", alias = "dashboard")]
    Ui,

    /// Terminate running mcp-sentinel proxy processes (useful before upgrades or to release file locks)
    #[command(alias = "stop")]
    Kill {
        /// Force kill immediately without graceful termination
        #[arg(short, long)]
        force: bool,
    },

    /// Migrate existing plaintext MCP configurations to Zero-Trust vault
    Migrate {
        /// Target application to migrate (claude, cursor, antigravity, kiro, codex, windsurf, cline, roo, vscode, continue, or all)
        #[arg(value_enum)]
        target: Option<crate::migrate::MigrateTarget>,

        /// Path to a specific MCP configuration file to migrate
        #[arg(short, long)]
        file: Option<std::path::PathBuf>,

        /// Dry-run mode: display planned changes without modifying vault or files
        #[arg(long)]
        dry_run: bool,

        /// Skip creating a .bak backup file
        #[arg(long)]
        no_backup: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum SecretCommands {
    /// Store a secret in the OS Keyring
    Set {
        /// Secret key name (e.g., GITHUB_TOKEN)
        key: String,
        /// Secret value
        value: String,
    },
    /// Retrieve a secret from the OS Keyring
    Get {
        /// Secret key name
        key: String,
    },
    /// Delete a secret from the OS Keyring
    Delete {
        /// Secret key name
        key: String,
    },
    /// List all stored secret keys
    List,
}

#[derive(Subcommand, Debug)]
pub enum PermCommands {
    /// List all granted MCP permissions
    List,
    /// Pre-authorize an MCP server command and secrets (ideal for headless, SSH, and CI environments)
    Grant {
        /// Friendly name of the MCP server
        #[arg(short, long)]
        name: Option<String>,

        /// Comma-separated list of required secrets or alias mappings
        #[arg(short, long, value_delimiter = ',')]
        secrets: Vec<String>,

        /// Optional Tool Policy Profile to bind to this grant
        #[arg(long)]
        profile: Option<String>,

        /// Command and arguments of the MCP server to pre-authorize
        #[arg(required = true, last = true)]
        cmd: Vec<String>,
    },
    /// Revoke permission for a specific MCP by fingerprint ID
    Revoke {
        /// Fingerprint ID of the MCP
        id: String,
    },
    /// Revoke all permissions
    Reset,
}

#[derive(Subcommand, Debug)]
pub enum ToolPolicyCommands {
    /// List all configured tool policy profiles
    List,
    /// View details of a specific tool policy profile
    Get {
        /// Name of the profile
        name: String,
    },
    /// Create or update a tool policy profile
    Set {
        /// Name of the profile (e.g. read-only, no-destructive)
        name: String,
        /// Comma-separated allowed tool patterns (e.g. read_*,get_*)
        #[arg(short, long, value_delimiter = ',')]
        allow: Vec<String>,
        /// Comma-separated denied tool patterns (e.g. *drop*,*delete*)
        #[arg(short, long, value_delimiter = ',')]
        deny: Vec<String>,
        /// Optional description of the profile
        #[arg(long)]
        description: Option<String>,
    },
    /// Delete a tool policy profile
    Delete {
        /// Name of the profile to delete
        name: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum AuditCommands {
    /// List recorded audit events
    List {
        /// Maximum number of events to show (default: 50)
        #[arg(short, long, default_value = "50")]
        limit: usize,

        /// Only show events where a tool call was blocked
        #[arg(long)]
        blocked_only: bool,

        /// Filter by specific event type (e.g. TOOL_BLOCKED, SERVER_START)
        #[arg(short, long)]
        event: Option<String>,
    },
    /// Clear and purge all audit logs
    Clear,
    /// View audit logging subsystem status and metrics
    Status,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_run_command() {
        let args = vec![
            "mcp-sentinel",
            "run",
            "--secrets",
            "KEY_A,KEY_B",
            "--name",
            "My Server",
            "--",
            "node",
            "server.js",
        ];
        let cli = Cli::try_parse_from(args).expect("CLI should parse run command successfully");
        match cli.command {
            Commands::Run {
                secrets,
                pass_env,
                name,
                cmd,
                no_redact,
                allow_once,
                profile,
                deny_tools,
                allow_tools,
                audit,
            } => {
                assert_eq!(secrets, vec!["KEY_A".to_string(), "KEY_B".to_string()]);
                assert!(pass_env.is_empty());
                assert_eq!(name, Some("My Server".to_string()));
                assert_eq!(cmd, vec!["node".to_string(), "server.js".to_string()]);
                assert!(!no_redact);
                assert!(!allow_once);
                assert_eq!(profile, None);
                assert!(deny_tools.is_empty());
                assert!(allow_tools.is_empty());
                assert!(!audit);
            }
            _ => panic!("Expected Commands::Run"),
        }
    }

    #[test]
    fn test_parse_run_command_with_pass_env() {
        let args = vec![
            "mcp-sentinel",
            "run",
            "--pass-env",
            "PORT,DB_NAME,DEBUG",
            "--",
            "node",
            "server.js",
        ];
        let cli = Cli::try_parse_from(args).expect("CLI should parse pass-env successfully");
        match cli.command {
            Commands::Run { pass_env, .. } => {
                assert_eq!(
                    pass_env,
                    vec![
                        "PORT".to_string(),
                        "DB_NAME".to_string(),
                        "DEBUG".to_string()
                    ]
                );
            }
            _ => panic!("Expected Commands::Run"),
        }

        // Test alias --env
        let args_alias = vec![
            "mcp-sentinel",
            "run",
            "--env",
            "HOST,PORT",
            "--",
            "node",
            "server.js",
        ];
        let cli_alias =
            Cli::try_parse_from(args_alias).expect("CLI should parse --env alias successfully");
        match cli_alias.command {
            Commands::Run { pass_env, .. } => {
                assert_eq!(pass_env, vec!["HOST".to_string(), "PORT".to_string()]);
            }
            _ => panic!("Expected Commands::Run"),
        }
    }

    #[test]
    fn test_parse_run_command_with_tool_policy_flags() {
        let args = vec![
            "mcp-sentinel",
            "run",
            "--profile",
            "read-only",
            "--deny-tools",
            "*drop*,*delete*",
            "--allow-tools",
            "read_*,get_*",
            "--",
            "node",
            "server.js",
        ];
        let cli =
            Cli::try_parse_from(args).expect("CLI should parse tool policy flags successfully");
        match cli.command {
            Commands::Run {
                profile,
                deny_tools,
                allow_tools,
                ..
            } => {
                assert_eq!(profile, Some("read-only".to_string()));
                assert_eq!(
                    deny_tools,
                    vec!["*drop*".to_string(), "*delete*".to_string()]
                );
                assert_eq!(allow_tools, vec!["read_*".to_string(), "get_*".to_string()]);
            }
            _ => panic!("Expected Commands::Run"),
        }
    }

    #[test]
    fn test_parse_tool_policy_subcommands() {
        // List
        let cli = Cli::try_parse_from(["mcp-sentinel", "profile", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::ToolPolicy {
                action: ToolPolicyCommands::List
            }
        ));

        // Set
        let cli = Cli::try_parse_from([
            "mcp-sentinel",
            "tool-policy",
            "set",
            "custom-db",
            "--allow",
            "read_*,get_*",
            "--deny",
            "*drop*",
            "--description",
            "Safe DB profile",
        ])
        .unwrap();
        match cli.command {
            Commands::ToolPolicy {
                action:
                    ToolPolicyCommands::Set {
                        name,
                        allow,
                        deny,
                        description,
                    },
            } => {
                assert_eq!(name, "custom-db");
                assert_eq!(allow, vec!["read_*", "get_*"]);
                assert_eq!(deny, vec!["*drop*"]);
                assert_eq!(description, Some("Safe DB profile".to_string()));
            }
            _ => panic!("Expected ToolPolicyCommands::Set"),
        }
    }

    #[test]
    fn test_parse_run_command_allow_once() {
        let args = vec![
            "mcp-sentinel",
            "run",
            "--allow-once",
            "--",
            "node",
            "server.js",
        ];
        let cli = Cli::try_parse_from(args).expect("CLI should parse run command successfully");
        match cli.command {
            Commands::Run { allow_once, .. } => {
                assert!(allow_once);
            }
            _ => panic!("Expected Commands::Run"),
        }

        // Test alias --once
        let args_alias = vec!["mcp-sentinel", "run", "--once", "--", "node", "server.js"];
        let cli_alias =
            Cli::try_parse_from(args_alias).expect("CLI should parse --once alias successfully");
        match cli_alias.command {
            Commands::Run { allow_once, .. } => {
                assert!(allow_once);
            }
            _ => panic!("Expected Commands::Run"),
        }
    }

    #[test]
    fn test_parse_run_command_no_redact() {
        let args = vec![
            "mcp-sentinel",
            "run",
            "--no-redact",
            "--",
            "node",
            "server.js",
        ];
        let cli = Cli::try_parse_from(args).expect("CLI should parse run command successfully");
        match cli.command {
            Commands::Run { no_redact, .. } => {
                assert!(no_redact);
            }
            _ => panic!("Expected Commands::Run"),
        }
    }

    #[test]
    fn test_parse_run_command_with_aliases() {
        let args = vec![
            "mcp-sentinel",
            "run",
            "--secrets",
            "API_KEY=OPENAI_PROD_KEY,DATABASE_URL=SUPABASE_URL,GITHUB_TOKEN",
            "--",
            "python",
            "server.py",
        ];
        let cli = Cli::try_parse_from(args).expect("CLI should parse aliased secrets successfully");
        match cli.command {
            Commands::Run { secrets, cmd, .. } => {
                assert_eq!(
                    secrets,
                    vec![
                        "API_KEY=OPENAI_PROD_KEY".to_string(),
                        "DATABASE_URL=SUPABASE_URL".to_string(),
                        "GITHUB_TOKEN".to_string()
                    ]
                );
                assert_eq!(cmd, vec!["python".to_string(), "server.py".to_string()]);
            }
            _ => panic!("Expected Commands::Run"),
        }
    }

    #[test]
    fn test_parse_secret_commands() {
        // Set
        let cli =
            Cli::try_parse_from(["mcp-sentinel", "secrets", "set", "MY_KEY", "MY_VAL"]).unwrap();
        match cli.command {
            Commands::Secrets {
                action: SecretCommands::Set { key, value },
            } => {
                assert_eq!(key, "MY_KEY");
                assert_eq!(value, "MY_VAL");
            }
            _ => panic!("Expected SecretCommands::Set"),
        }

        // Get
        let cli = Cli::try_parse_from(["mcp-sentinel", "secrets", "get", "MY_KEY"]).unwrap();
        match cli.command {
            Commands::Secrets {
                action: SecretCommands::Get { key },
            } => {
                assert_eq!(key, "MY_KEY");
            }
            _ => panic!("Expected SecretCommands::Get"),
        }

        // Delete
        let cli = Cli::try_parse_from(["mcp-sentinel", "secrets", "delete", "MY_KEY"]).unwrap();
        match cli.command {
            Commands::Secrets {
                action: SecretCommands::Delete { key },
            } => {
                assert_eq!(key, "MY_KEY");
            }
            _ => panic!("Expected SecretCommands::Delete"),
        }
    }

    #[test]
    fn test_parse_permission_commands() {
        // List
        let cli = Cli::try_parse_from(["mcp-sentinel", "permissions", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Permissions {
                action: PermCommands::List
            }
        ));

        // Revoke
        let cli =
            Cli::try_parse_from(["mcp-sentinel", "permissions", "revoke", "fp_12345"]).unwrap();
        match cli.command {
            Commands::Permissions {
                action: PermCommands::Revoke { id },
            } => {
                assert_eq!(id, "fp_12345");
            }
            _ => panic!("Expected PermCommands::Revoke"),
        }

        // Reset
        let cli = Cli::try_parse_from(["mcp-sentinel", "permissions", "reset"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Permissions {
                action: PermCommands::Reset
            }
        ));

        // Grant with profile
        let cli = Cli::try_parse_from([
            "mcp-sentinel",
            "permissions",
            "grant",
            "--profile",
            "read-only",
            "--secrets",
            "SECRET_A",
            "--",
            "node",
            "server.js",
        ])
        .unwrap();
        match cli.command {
            Commands::Permissions {
                action:
                    PermCommands::Grant {
                        profile,
                        secrets,
                        cmd,
                        ..
                    },
            } => {
                assert_eq!(profile, Some("read-only".to_string()));
                assert_eq!(secrets, vec!["SECRET_A".to_string()]);
                assert_eq!(cmd, vec!["node".to_string(), "server.js".to_string()]);
            }
            _ => panic!("Expected PermCommands::Grant"),
        }
    }

    #[test]
    fn test_parse_subcommand_aliases() {
        // "permission" singular alias
        let cli_perm = Cli::try_parse_from(["mcp-sentinel", "permission", "list"]).unwrap();
        assert!(matches!(cli_perm.command, Commands::Permissions { .. }));

        // "perm" alias
        let cli_p = Cli::try_parse_from(["mcp-sentinel", "perm", "list"]).unwrap();
        assert!(matches!(cli_p.command, Commands::Permissions { .. }));

        // "secret" singular alias for Secrets
        let cli_sec = Cli::try_parse_from(["mcp-sentinel", "secret", "list"]).unwrap();
        assert!(matches!(cli_sec.command, Commands::Secrets { .. }));

        // "ui", "tui", "dashboard"
        let cli_ui = Cli::try_parse_from(["mcp-sentinel", "ui"]).unwrap();
        assert!(matches!(cli_ui.command, Commands::Ui));

        let cli_tui = Cli::try_parse_from(["mcp-sentinel", "tui"]).unwrap();
        assert!(matches!(cli_tui.command, Commands::Ui));

        let cli_dash = Cli::try_parse_from(["mcp-sentinel", "dashboard"]).unwrap();
        assert!(matches!(cli_dash.command, Commands::Ui));

        // "kill", "stop"
        let cli_kill = Cli::try_parse_from(["mcp-sentinel", "kill"]).unwrap();
        assert!(matches!(cli_kill.command, Commands::Kill { force: false }));

        let cli_stop = Cli::try_parse_from(["mcp-sentinel", "stop", "--force"]).unwrap();
        assert!(matches!(cli_stop.command, Commands::Kill { force: true }));
    }

    #[test]
    fn test_parse_migrate_command() {
        // Default target
        let cli_default = Cli::try_parse_from(["mcp-sentinel", "migrate"]).unwrap();
        match cli_default.command {
            Commands::Migrate {
                target,
                file,
                dry_run,
                no_backup,
            } => {
                assert_eq!(target, None);
                assert_eq!(file, None);
                assert!(!dry_run);
                assert!(!no_backup);
            }
            _ => panic!("Expected Commands::Migrate"),
        }

        // Specific target and flags
        let cli_claude = Cli::try_parse_from([
            "mcp-sentinel",
            "migrate",
            "claude",
            "--dry-run",
            "--no-backup",
        ])
        .unwrap();
        match cli_claude.command {
            Commands::Migrate {
                target,
                dry_run,
                no_backup,
                ..
            } => {
                assert_eq!(target, Some(crate::migrate::MigrateTarget::Claude));
                assert!(dry_run);
                assert!(no_backup);
            }
            _ => panic!("Expected Commands::Migrate"),
        }

        // Test Antigravity target
        let cli_ag = Cli::try_parse_from(["mcp-sentinel", "migrate", "antigravity"]).unwrap();
        match cli_ag.command {
            Commands::Migrate { target, .. } => {
                assert_eq!(target, Some(crate::migrate::MigrateTarget::Antigravity));
            }
            _ => panic!("Expected Commands::Migrate"),
        }

        // Test Kiro target
        let cli_kiro = Cli::try_parse_from(["mcp-sentinel", "migrate", "kiro"]).unwrap();
        match cli_kiro.command {
            Commands::Migrate { target, .. } => {
                assert_eq!(target, Some(crate::migrate::MigrateTarget::Kiro));
            }
            _ => panic!("Expected Commands::Migrate"),
        }

        // Test Codex target
        let cli_codex = Cli::try_parse_from(["mcp-sentinel", "migrate", "codex"]).unwrap();
        match cli_codex.command {
            Commands::Migrate { target, .. } => {
                assert_eq!(target, Some(crate::migrate::MigrateTarget::Codex));
            }
            _ => panic!("Expected Commands::Migrate"),
        }

        // Test Roo alias
        let cli_roo = Cli::try_parse_from(["mcp-sentinel", "migrate", "roo"]).unwrap();
        match cli_roo.command {
            Commands::Migrate { target, .. } => {
                assert_eq!(target, Some(crate::migrate::MigrateTarget::RooCode));
            }
            _ => panic!("Expected Commands::Migrate"),
        }

        // Custom file
        let cli_file =
            Cli::try_parse_from(["mcp-sentinel", "migrate", "--file", "my_config.json"]).unwrap();
        match cli_file.command {
            Commands::Migrate { file, .. } => {
                assert_eq!(file, Some(std::path::PathBuf::from("my_config.json")));
            }
            _ => panic!("Expected Commands::Migrate"),
        }
    }

    #[test]
    fn test_parse_audit_commands() {
        let cli_list = Cli::try_parse_from(["mcp-sentinel", "audit", "list"]).unwrap();
        match cli_list.command {
            Commands::Audit {
                action:
                    AuditCommands::List {
                        limit,
                        blocked_only,
                        event,
                    },
            } => {
                assert_eq!(limit, 50);
                assert!(!blocked_only);
                assert_eq!(event, None);
            }
            _ => panic!("Expected Commands::Audit::List"),
        }

        let cli_blocked = Cli::try_parse_from([
            "mcp-sentinel",
            "audits",
            "list",
            "--limit",
            "20",
            "--blocked-only",
            "--event",
            "TOOL_BLOCKED",
        ])
        .unwrap();
        match cli_blocked.command {
            Commands::Audit {
                action:
                    AuditCommands::List {
                        limit,
                        blocked_only,
                        event,
                    },
            } => {
                assert_eq!(limit, 20);
                assert!(blocked_only);
                assert_eq!(event.as_deref(), Some("TOOL_BLOCKED"));
            }
            _ => panic!("Expected Commands::Audit::List"),
        }

        let cli_clear = Cli::try_parse_from(["mcp-sentinel", "audit", "clear"]).unwrap();
        assert!(matches!(
            cli_clear.command,
            Commands::Audit {
                action: AuditCommands::Clear
            }
        ));

        let cli_status = Cli::try_parse_from(["mcp-sentinel", "audit", "status"]).unwrap();
        assert!(matches!(
            cli_status.command,
            Commands::Audit {
                action: AuditCommands::Status
            }
        ));

        // Test --audit flag on run
        let cli_run =
            Cli::try_parse_from(["mcp-sentinel", "run", "--audit", "--", "node", "srv.js"])
                .unwrap();
        match cli_run.command {
            Commands::Run { audit, .. } => assert!(audit),
            _ => panic!("Expected Commands::Run with audit=true"),
        }
    }
}
