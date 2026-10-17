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

        /// Optional descriptive name for the MCP server
        #[arg(short, long)]
        name: Option<String>,

        /// Disable automatic Data Loss Prevention (DLP) secret masking on stdout
        #[arg(long)]
        no_redact: bool,

        /// Authorize this execution once without persisting permission to permissions.json
        #[arg(long, alias = "once")]
        allow_once: bool,

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

    /// Launch the interactive Terminal User Interface (TUI) Dashboard
    #[command(alias = "tui", alias = "dashboard")]
    Ui,

    /// Migrate existing plaintext MCP configurations to Zero-Trust vault
    Migrate {
        /// Target application to migrate (claude, cursor, all)
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
    /// Revoke permission for a specific MCP by fingerprint ID
    Revoke {
        /// Fingerprint ID of the MCP
        id: String,
    },
    /// Revoke all permissions
    Reset,
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
                name,
                cmd,
                no_redact,
                allow_once,
            } => {
                assert_eq!(secrets, vec!["KEY_A".to_string(), "KEY_B".to_string()]);
                assert_eq!(name, Some("My Server".to_string()));
                assert_eq!(cmd, vec!["node".to_string(), "server.js".to_string()]);
                assert!(!no_redact);
                assert!(!allow_once);
            }
            _ => panic!("Expected Commands::Run"),
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
}
