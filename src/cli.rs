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
        /// Comma-separated list of required secrets (e.g., GITHUB_TOKEN,DATABASE_URL)
        #[arg(short, long, value_delimiter = ',')]
        secrets: Vec<String>,

        /// Optional descriptive name for the MCP server
        #[arg(short, long)]
        name: Option<String>,

        /// Command and arguments to execute (after --)
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },

    /// Manage secrets stored in the OS Keyring
    Secret {
        #[command(subcommand)]
        action: SecretCommands,
    },

    /// Manage permissions granted to MCP servers (TOFU policy)
    Permissions {
        #[command(subcommand)]
        action: PermCommands,
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
            "mcp-shield",
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
            Commands::Run { secrets, name, cmd } => {
                assert_eq!(secrets, vec!["KEY_A".to_string(), "KEY_B".to_string()]);
                assert_eq!(name, Some("My Server".to_string()));
                assert_eq!(cmd, vec!["node".to_string(), "server.js".to_string()]);
            }
            _ => panic!("Expected Commands::Run"),
        }
    }

    #[test]
    fn test_parse_secret_commands() {
        // Set
        let cli = Cli::try_parse_from(["mcp-shield", "secret", "set", "MY_KEY", "MY_VAL"]).unwrap();
        match cli.command {
            Commands::Secret {
                action: SecretCommands::Set { key, value },
            } => {
                assert_eq!(key, "MY_KEY");
                assert_eq!(value, "MY_VAL");
            }
            _ => panic!("Expected SecretCommands::Set"),
        }

        // Get
        let cli = Cli::try_parse_from(["mcp-shield", "secret", "get", "MY_KEY"]).unwrap();
        match cli.command {
            Commands::Secret {
                action: SecretCommands::Get { key },
            } => {
                assert_eq!(key, "MY_KEY");
            }
            _ => panic!("Expected SecretCommands::Get"),
        }

        // Delete
        let cli = Cli::try_parse_from(["mcp-shield", "secret", "delete", "MY_KEY"]).unwrap();
        match cli.command {
            Commands::Secret {
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
        let cli = Cli::try_parse_from(["mcp-shield", "permissions", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Permissions {
                action: PermCommands::List
            }
        ));

        // Revoke
        let cli = Cli::try_parse_from(["mcp-shield", "permissions", "revoke", "fp_12345"]).unwrap();
        match cli.command {
            Commands::Permissions {
                action: PermCommands::Revoke { id },
            } => {
                assert_eq!(id, "fp_12345");
            }
            _ => panic!("Expected PermCommands::Revoke"),
        }

        // Reset
        let cli = Cli::try_parse_from(["mcp-shield", "permissions", "reset"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Permissions {
                action: PermCommands::Reset
            }
        ));
    }
}
