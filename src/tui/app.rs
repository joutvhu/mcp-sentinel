use ratatui::{
    style::Color,
    widgets::{ListState, TableState},
};

use crate::policy::{self, PolicyFile};
use crate::tool_policy::{self, ToolProfile};
use crate::vault;
use super::widgets::InputField;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FocusArea {
    Sidebar,
    Content,
    Detail,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AppTab {
    Secrets = 0,
    Permissions = 1,
    ToolProfiles = 2,
    System = 3,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SidebarAction {
    Tab(AppTab),
    AddSecret,
    RefreshVault,
    ResetGrants,
    Quit,
}

pub const SIDEBAR_MENU: &[(SidebarAction, &str, &str)] = &[
    (SidebarAction::Tab(AppTab::Secrets), "Secrets Vault", "[1]"),
    (
        SidebarAction::Tab(AppTab::Permissions),
        "Permissions (TOFU)",
        "[2]",
    ),
    (
        SidebarAction::Tab(AppTab::ToolProfiles),
        "Tool Policies",
        "[3]",
    ),
    (SidebarAction::Tab(AppTab::System), "System Status", "[4]"),
    (SidebarAction::AddSecret, "Add Secret", "[a]"),
    (SidebarAction::RefreshVault, "Refresh Data", "[r]"),
    (SidebarAction::ResetGrants, "Reset Permissions", "[x]"),
    (SidebarAction::Quit, "Quit Dashboard", "[q]"),
];

pub enum ModalState {
    None,
    AddSecret {
        key: InputField,
        value: InputField,
        focus_value: bool,
    },
    ConfirmDeleteSecret(String),
    ConfirmRevokeGrant(String),
    ConfirmDeleteProfile(String),
    ConfirmResetGrants,
    RevealSecret {
        key: String,
        value: String,
    },
    ViewGrant {
        id: String,
        name: Option<String>,
        command: String,
        secrets: Vec<String>,
        created_at: String,
    },
    ViewProfile {
        name: String,
        description: Option<String>,
        allow: Vec<String>,
        deny: Vec<String>,
    },
    UpdateSecret {
        key: String,
        value: InputField,
    },
}

pub struct App {
    pub focus: FocusArea,
    pub current_tab: AppTab,
    pub sidebar_index: usize,
    pub secrets: Vec<String>,
    pub secrets_state: ListState,
    pub policy: PolicyFile,
    pub grants_list: Vec<(String, String, String, String)>,
    pub permissions_state: TableState,
    pub tool_profiles: Vec<ToolProfile>,
    pub tool_profiles_state: ListState,
    pub modal: ModalState,
    pub status_message: Option<(String, Color)>,
    pub should_quit: bool,
    pub detail_scroll: u16,
    pub modal_scroll: u16,
}

impl App {
    pub fn new() -> Self {
        let mut app = Self {
            focus: FocusArea::Sidebar,
            current_tab: AppTab::Secrets,
            sidebar_index: 0,
            secrets: Vec::new(),
            secrets_state: ListState::default(),
            policy: PolicyFile::default(),
            grants_list: Vec::new(),
            permissions_state: TableState::default(),
            tool_profiles: Vec::new(),
            tool_profiles_state: ListState::default(),
            modal: ModalState::None,
            status_message: Some((
                "Use [Up/Down] arrows to navigate menu, [Enter] to select.".to_string(),
                Color::Cyan,
            )),
            should_quit: false,
            detail_scroll: 0,
            modal_scroll: 0,
        };
        app.reload_secrets();
        app.reload_permissions();
        app.reload_tool_profiles();
        app
    }

    pub fn reload_secrets(&mut self) {
        self.secrets = vault::list_keys();
        if !self.secrets.is_empty() {
            if self.secrets_state.selected().is_none() {
                self.secrets_state.select(Some(0));
            } else if let Some(selected) = self.secrets_state.selected() {
                if selected >= self.secrets.len() {
                    self.secrets_state.select(Some(self.secrets.len() - 1));
                }
            }
        } else {
            self.secrets_state.select(None);
        }
    }

    pub fn reload_permissions(&mut self) {
        self.policy = policy::load_policy();
        self.grants_list = self
            .policy
            .grants
            .values()
            .map(|g| {
                let id_short = if g.id.len() > 12 {
                    g.id[..12].to_string()
                } else {
                    g.id.clone()
                };
                let display_cmd = g.name.clone().unwrap_or_else(|| g.command.clone());
                let secrets_str = g.granted_secrets.join(", ");
                let created_str = g.created_at.format("%Y-%m-%d %H:%M").to_string();
                (id_short, display_cmd, secrets_str, created_str)
            })
            .collect();

        if !self.grants_list.is_empty() {
            if self.permissions_state.selected().is_none() {
                self.permissions_state.select(Some(0));
            } else if let Some(selected) = self.permissions_state.selected() {
                if selected >= self.grants_list.len() {
                    self.permissions_state
                        .select(Some(self.grants_list.len() - 1));
                }
            }
        } else {
            self.permissions_state.select(None);
        }
    }

    pub fn reload_tool_profiles(&mut self) {
        if let Ok(pfile) = tool_policy::load_profiles() {
            let mut profiles: Vec<ToolProfile> = pfile.profiles.into_values().collect();
            profiles.sort_by(|a, b| a.name.cmp(&b.name));
            self.tool_profiles = profiles;

            if !self.tool_profiles.is_empty() {
                if self.tool_profiles_state.selected().is_none() {
                    self.tool_profiles_state.select(Some(0));
                } else if let Some(selected) = self.tool_profiles_state.selected() {
                    if selected >= self.tool_profiles.len() {
                        self.tool_profiles_state
                            .select(Some(self.tool_profiles.len() - 1));
                    }
                }
            } else {
                self.tool_profiles_state.select(None);
            }
        }
    }

    pub fn sidebar_up(&mut self) {
        if self.sidebar_index > 0 {
            self.sidebar_index -= 1;
        } else {
            self.sidebar_index = SIDEBAR_MENU.len() - 1;
        }
        self.sync_sidebar_tab();
    }

    pub fn sidebar_down(&mut self) {
        if self.sidebar_index + 1 < SIDEBAR_MENU.len() {
            self.sidebar_index += 1;
        } else {
            self.sidebar_index = 0;
        }
        self.sync_sidebar_tab();
    }

    fn sync_sidebar_tab(&mut self) {
        if let Some((SidebarAction::Tab(tab), _, _)) = SIDEBAR_MENU.get(self.sidebar_index) {
            self.current_tab = *tab;
        }
    }

    pub fn content_up(&mut self) {
        match self.current_tab {
            AppTab::Secrets => {
                if !self.secrets.is_empty() {
                    let prev = match self.secrets_state.selected() {
                        Some(i) if i > 0 => i - 1,
                        _ => self.secrets.len() - 1,
                    };
                    self.secrets_state.select(Some(prev));
                    self.detail_scroll = 0;
                }
            }
            AppTab::Permissions => {
                if !self.grants_list.is_empty() {
                    let prev = match self.permissions_state.selected() {
                        Some(i) if i > 0 => i - 1,
                        _ => self.grants_list.len() - 1,
                    };
                    self.permissions_state.select(Some(prev));
                    self.detail_scroll = 0;
                }
            }
            AppTab::ToolProfiles => {
                if !self.tool_profiles.is_empty() {
                    let prev = match self.tool_profiles_state.selected() {
                        Some(i) if i > 0 => i - 1,
                        _ => self.tool_profiles.len() - 1,
                    };
                    self.tool_profiles_state.select(Some(prev));
                    self.detail_scroll = 0;
                }
            }
            AppTab::System => {
                self.detail_scroll = self.detail_scroll.saturating_sub(1);
            }
        }
    }

    pub fn content_down(&mut self) {
        match self.current_tab {
            AppTab::Secrets => {
                if !self.secrets.is_empty() {
                    let next = match self.secrets_state.selected() {
                        Some(i) if i + 1 < self.secrets.len() => i + 1,
                        _ => 0,
                    };
                    self.secrets_state.select(Some(next));
                    self.detail_scroll = 0;
                }
            }
            AppTab::Permissions => {
                if !self.grants_list.is_empty() {
                    let next = match self.permissions_state.selected() {
                        Some(i) if i + 1 < self.grants_list.len() => i + 1,
                        _ => 0,
                    };
                    self.permissions_state.select(Some(next));
                    self.detail_scroll = 0;
                }
            }
            AppTab::ToolProfiles => {
                if !self.tool_profiles.is_empty() {
                    let next = match self.tool_profiles_state.selected() {
                        Some(i) if i + 1 < self.tool_profiles.len() => i + 1,
                        _ => 0,
                    };
                    self.tool_profiles_state.select(Some(next));
                    self.detail_scroll = 0;
                }
            }
            AppTab::System => {
                self.detail_scroll = self.detail_scroll.saturating_add(1);
            }
        }
    }

    pub fn open_reveal_modal(&mut self) {
        if let Some(i) = self.secrets_state.selected() {
            if let Some(key_name) = self.secrets.get(i) {
                match vault::get_secret(key_name) {
                    Ok(val) => {
                        self.modal_scroll = 0;
                        self.modal = ModalState::RevealSecret {
                            key: key_name.clone(),
                            value: val,
                        };
                    }
                    Err(e) => {
                        self.status_message =
                            Some((format!("Error reading secret: {}", e), Color::Red));
                    }
                }
            }
        }
    }

    pub fn open_delete_modal(&mut self) {
        if let Some(i) = self.secrets_state.selected() {
            if let Some(key_name) = self.secrets.get(i) {
                self.modal = ModalState::ConfirmDeleteSecret(key_name.clone());
            }
        }
    }

    pub fn open_delete_profile_modal(&mut self) {
        if let Some(i) = self.tool_profiles_state.selected() {
            if let Some(profile) = self.tool_profiles.get(i) {
                if profile.name == "read-only" || profile.name == "no-destructive" {
                    self.status_message = Some((
                        format!("Built-in preset '{}' cannot be deleted.", profile.name),
                        Color::Yellow,
                    ));
                } else {
                    self.modal = ModalState::ConfirmDeleteProfile(profile.name.clone());
                }
            }
        }
    }

    pub fn open_add_modal(&mut self) {
        self.modal = ModalState::AddSecret {
            key: InputField::default(),
            value: InputField::default(),
            focus_value: false,
        };
    }

    pub fn open_update_modal(&mut self) {
        if let Some(i) = self.secrets_state.selected() {
            if let Some(key_name) = self.secrets.get(i) {
                let current_val = vault::get_secret(key_name).unwrap_or_default();
                self.modal = ModalState::UpdateSecret {
                    key: key_name.clone(),
                    value: InputField::new(current_val),
                };
            }
        }
    }

    pub fn open_revoke_modal(&mut self) {
        if let Some(i) = self.permissions_state.selected() {
            if let Some((id, _, _, _)) = self.grants_list.get(i) {
                for full_id in self.policy.grants.keys() {
                    if full_id.starts_with(id) {
                        self.modal = ModalState::ConfirmRevokeGrant(full_id.clone());
                        break;
                    }
                }
            }
        }
    }

    pub fn open_view_grant_modal(&mut self) {
        if let Some(i) = self.permissions_state.selected() {
            if let Some((id, _, _, _)) = self.grants_list.get(i) {
                for (full_id, grant) in &self.policy.grants {
                    if full_id.starts_with(id) {
                        self.modal_scroll = 0;
                        self.modal = ModalState::ViewGrant {
                            id: full_id.clone(),
                            name: grant.name.clone(),
                            command: grant.command.clone(),
                            secrets: grant.granted_secrets.clone(),
                            created_at: grant
                                .created_at
                                .format("%Y-%m-%d %H:%M:%S UTC")
                                .to_string(),
                        };
                        break;
                    }
                }
            }
        }
    }

    pub fn open_view_profile_modal(&mut self) {
        if let Some(i) = self.tool_profiles_state.selected() {
            if let Some(prof) = self.tool_profiles.get(i) {
                self.modal_scroll = 0;
                self.modal = ModalState::ViewProfile {
                    name: prof.name.clone(),
                    description: prof.description.clone(),
                    allow: prof.allow.clone(),
                    deny: prof.deny.clone(),
                };
            }
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_tool_profiles_initialization() {
        let mut app = App {
            focus: FocusArea::Sidebar,
            current_tab: AppTab::ToolProfiles,
            sidebar_index: 2,
            secrets: Vec::new(),
            secrets_state: ListState::default(),
            policy: PolicyFile::default(),
            grants_list: Vec::new(),
            permissions_state: TableState::default(),
            tool_profiles: Vec::new(),
            tool_profiles_state: ListState::default(),
            modal: ModalState::None,
            status_message: None,
            should_quit: false,
            detail_scroll: 0,
            modal_scroll: 0,
        };

        app.reload_tool_profiles();
        // Built-in presets should be loaded
        assert!(app.tool_profiles.iter().any(|p| p.name == "read-only"));
        assert!(app.tool_profiles.iter().any(|p| p.name == "no-destructive"));
        assert!(app.tool_profiles_state.selected().is_some());

        // Test navigation
        let initial_sel = app.tool_profiles_state.selected().unwrap();
        app.content_down();
        let next_sel = app.tool_profiles_state.selected().unwrap();
        if app.tool_profiles.len() > 1 {
            assert_ne!(initial_sel, next_sel);
        }
        app.content_up();
        assert_eq!(app.tool_profiles_state.selected().unwrap(), initial_sel);
    }
}
