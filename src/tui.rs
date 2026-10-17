use std::io;
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Row, Table,
        TableState, Wrap,
    },
    Frame, Terminal,
};

use crate::policy::{self, PolicyFile};
use crate::vault;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FocusArea {
    Sidebar,
    Content,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AppTab {
    Secrets = 0,
    Permissions = 1,
    System = 2,
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
    (SidebarAction::Tab(AppTab::System), "System Status", "[3]"),
    (SidebarAction::AddSecret, "Add Secret", "[a]"),
    (SidebarAction::RefreshVault, "Refresh Data", "[r]"),
    (SidebarAction::ResetGrants, "Reset Permissions", "[x]"),
    (SidebarAction::Quit, "Quit Dashboard", "[q]"),
];

pub enum ModalState {
    None,
    AddSecret {
        key: String,
        value: String,
        focus_value: bool,
    },
    ConfirmDeleteSecret(String),
    ConfirmRevokeGrant(String),
    ConfirmResetGrants,
    RevealSecret {
        key: String,
        value: String,
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
    pub modal: ModalState,
    pub status_message: Option<(String, Color)>,
    pub should_quit: bool,
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
            modal: ModalState::None,
            status_message: Some((
                "Use [Up/Down] arrows to navigate menu, [Enter] to select.".to_string(),
                Color::Cyan,
            )),
            should_quit: false,
        };
        app.reload_secrets();
        app.reload_permissions();
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
                }
            }
            AppTab::Permissions => {
                if !self.grants_list.is_empty() {
                    let prev = match self.permissions_state.selected() {
                        Some(i) if i > 0 => i - 1,
                        _ => self.grants_list.len() - 1,
                    };
                    self.permissions_state.select(Some(prev));
                }
            }
            AppTab::System => {}
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
                }
            }
            AppTab::Permissions => {
                if !self.grants_list.is_empty() {
                    let next = match self.permissions_state.selected() {
                        Some(i) if i + 1 < self.grants_list.len() => i + 1,
                        _ => 0,
                    };
                    self.permissions_state.select(Some(next));
                }
            }
            AppTab::System => {}
        }
    }

    pub fn open_reveal_modal(&mut self) {
        if let Some(i) = self.secrets_state.selected() {
            if let Some(key_name) = self.secrets.get(i) {
                match vault::get_secret(key_name) {
                    Ok(val) => {
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
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

pub fn run_tui() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();

    let res = main_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("[mcp-sentinel ui error]: {:?}", err);
    }

    Ok(())
}

fn main_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        terminal.draw(|f| ui(f, app))?;

        if app.should_quit {
            return Ok(());
        }

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                match &mut app.modal {
                    ModalState::AddSecret {
                        key: k,
                        value: v,
                        focus_value,
                    } => match key.code {
                        KeyCode::Esc => {
                            app.modal = ModalState::None;
                            app.status_message =
                                Some(("Add secret cancelled.".to_string(), Color::DarkGray));
                        }
                        KeyCode::Tab | KeyCode::Down | KeyCode::Up => {
                            *focus_value = !*focus_value;
                        }
                        KeyCode::Enter => {
                            let key_trimmed = k.trim().to_string();
                            let val_trimmed = v.trim().to_string();

                            if key_trimmed.is_empty() {
                                app.status_message = Some((
                                    "Error: Secret key name cannot be empty.".to_string(),
                                    Color::Red,
                                ));
                            } else if let Err(err_msg) = vault::validate_key_name(&key_trimmed) {
                                app.status_message = Some((err_msg, Color::Red));
                            } else {
                                match vault::set_secret(&key_trimmed, &val_trimmed) {
                                    Ok(_) => {
                                        app.reload_secrets();
                                        app.modal = ModalState::None;
                                        app.status_message = Some((
                                            format!(
                                                "✓ Secret '{}' saved in OS Vault!",
                                                key_trimmed
                                            ),
                                            Color::Green,
                                        ));
                                    }
                                    Err(e) => {
                                        app.status_message = Some((
                                            format!("Error saving secret: {}", e),
                                            Color::Red,
                                        ));
                                    }
                                }
                            }
                        }
                        KeyCode::Backspace => {
                            if *focus_value {
                                v.pop();
                            } else {
                                k.pop();
                            }
                        }
                        KeyCode::Char(c) => {
                            if *focus_value {
                                v.push(c);
                            } else {
                                k.push(c);
                            }
                        }
                        _ => {}
                    },

                    ModalState::ConfirmDeleteSecret(secret_name) => match key.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                            let name = secret_name.clone();
                            match vault::delete_secret(&name) {
                                Ok(_) => {
                                    app.reload_secrets();
                                    app.modal = ModalState::None;
                                    app.status_message = Some((
                                        format!("✓ Secret '{}' removed from OS Vault.", name),
                                        Color::Green,
                                    ));
                                }
                                Err(e) => {
                                    app.modal = ModalState::None;
                                    app.status_message =
                                        Some((format!("Error deleting secret: {}", e), Color::Red));
                                }
                            }
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                            app.modal = ModalState::None;
                            app.status_message =
                                Some(("Delete cancelled.".to_string(), Color::DarkGray));
                        }
                        _ => {}
                    },

                    ModalState::ConfirmRevokeGrant(grant_id) => match key.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                            let id = grant_id.clone();
                            match policy::revoke_grant(&id) {
                                Ok(_) => {
                                    app.reload_permissions();
                                    app.modal = ModalState::None;
                                    app.status_message = Some((
                                        format!(
                                            "✓ Permission '{}' revoked.",
                                            &id[..id.len().min(12)]
                                        ),
                                        Color::Green,
                                    ));
                                }
                                Err(e) => {
                                    app.modal = ModalState::None;
                                    app.status_message = Some((
                                        format!("Error revoking permission: {}", e),
                                        Color::Red,
                                    ));
                                }
                            }
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                            app.modal = ModalState::None;
                            app.status_message =
                                Some(("Revoke cancelled.".to_string(), Color::DarkGray));
                        }
                        _ => {}
                    },

                    ModalState::ConfirmResetGrants => match key.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                            match policy::reset_grants() {
                                Ok(_) => {
                                    app.reload_permissions();
                                    app.modal = ModalState::None;
                                    app.status_message = Some((
                                        "✓ All granted permissions have been reset.".to_string(),
                                        Color::Green,
                                    ));
                                }
                                Err(e) => {
                                    app.modal = ModalState::None;
                                    app.status_message = Some((
                                        format!("Error resetting permissions: {}", e),
                                        Color::Red,
                                    ));
                                }
                            }
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                            app.modal = ModalState::None;
                            app.status_message =
                                Some(("Reset cancelled.".to_string(), Color::DarkGray));
                        }
                        _ => {}
                    },

                    ModalState::RevealSecret { .. } => match key.code {
                        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('v') => {
                            app.modal = ModalState::None;
                        }
                        _ => {}
                    },

                    ModalState::None => {
                        // Global shortcuts
                        match key.code {
                            KeyCode::Char('q') => {
                                app.should_quit = true;
                                return Ok(());
                            }
                            KeyCode::Char('1') => {
                                app.current_tab = AppTab::Secrets;
                                app.sidebar_index = 0;
                                app.focus = FocusArea::Content;
                                continue;
                            }
                            KeyCode::Char('2') => {
                                app.current_tab = AppTab::Permissions;
                                app.sidebar_index = 1;
                                app.focus = FocusArea::Content;
                                continue;
                            }
                            KeyCode::Char('3') => {
                                app.current_tab = AppTab::System;
                                app.sidebar_index = 2;
                                app.focus = FocusArea::Content;
                                continue;
                            }
                            KeyCode::Char('a') => {
                                app.modal = ModalState::AddSecret {
                                    key: String::new(),
                                    value: String::new(),
                                    focus_value: false,
                                };
                                continue;
                            }
                            KeyCode::Char('r') => {
                                app.reload_secrets();
                                app.reload_permissions();
                                app.status_message = Some((
                                    "✓ Vault and policies reloaded.".to_string(),
                                    Color::Cyan,
                                ));
                                continue;
                            }
                            KeyCode::Char('x') => {
                                app.modal = ModalState::ConfirmResetGrants;
                                continue;
                            }
                            _ => {}
                        }

                        // Focus-dependent navigation
                        match app.focus {
                            FocusArea::Sidebar => match key.code {
                                KeyCode::Up | KeyCode::Char('k') => {
                                    app.sidebar_up();
                                }
                                KeyCode::Down | KeyCode::Char('j') => {
                                    app.sidebar_down();
                                }
                                KeyCode::Enter => {
                                    if let Some((action, _, _)) =
                                        SIDEBAR_MENU.get(app.sidebar_index)
                                    {
                                        match action {
                                            SidebarAction::Tab(tab) => {
                                                app.current_tab = *tab;
                                                app.focus = FocusArea::Content;
                                            }
                                            SidebarAction::AddSecret => {
                                                app.modal = ModalState::AddSecret {
                                                    key: String::new(),
                                                    value: String::new(),
                                                    focus_value: false,
                                                };
                                            }
                                            SidebarAction::RefreshVault => {
                                                app.reload_secrets();
                                                app.reload_permissions();
                                                app.status_message = Some((
                                                    "✓ Vault and permissions refreshed."
                                                        .to_string(),
                                                    Color::Cyan,
                                                ));
                                            }
                                            SidebarAction::ResetGrants => {
                                                app.modal = ModalState::ConfirmResetGrants;
                                            }
                                            SidebarAction::Quit => {
                                                app.should_quit = true;
                                            }
                                        }
                                    }
                                }
                                KeyCode::Right | KeyCode::Tab => {
                                    app.focus = FocusArea::Content;
                                }
                                KeyCode::Esc => {
                                    app.should_quit = true;
                                }
                                _ => {}
                            },

                            FocusArea::Content => match key.code {
                                KeyCode::Left | KeyCode::BackTab | KeyCode::Esc => {
                                    app.focus = FocusArea::Sidebar;
                                }
                                KeyCode::Up | KeyCode::Char('k') => {
                                    app.content_up();
                                }
                                KeyCode::Down | KeyCode::Char('j') => {
                                    app.content_down();
                                }
                                KeyCode::Tab => {
                                    app.focus = FocusArea::Sidebar;
                                }
                                KeyCode::Enter => match app.current_tab {
                                    AppTab::Secrets => app.open_reveal_modal(),
                                    AppTab::Permissions => app.open_revoke_modal(),
                                    AppTab::System => {}
                                },
                                KeyCode::Char('v') if app.current_tab == AppTab::Secrets => {
                                    app.open_reveal_modal();
                                }
                                KeyCode::Char('d') | KeyCode::Delete => match app.current_tab {
                                    AppTab::Secrets => app.open_delete_modal(),
                                    AppTab::Permissions => app.open_revoke_modal(),
                                    AppTab::System => {}
                                },
                                _ => {}
                            },
                        }
                    }
                }
            }
        }
    }
}

fn ui(f: &mut Frame, app: &mut App) {
    let size = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header Banner
            Constraint::Min(10),   // Sidebar + Content
            Constraint::Length(2), // Footer Keybinds & Status
        ])
        .split(size);

    // 1. Top Header Banner
    render_header(f, chunks[0]);

    // 2. Middle Body: Left Sidebar + Right Content View
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(26), // Sidebar fixed width
            Constraint::Min(40),    // Main content
        ])
        .split(chunks[1]);

    render_sidebar(f, app, body_chunks[0]);

    match app.current_tab {
        AppTab::Secrets => render_secrets_tab(f, app, body_chunks[1]),
        AppTab::Permissions => render_permissions_tab(f, app, body_chunks[1]),
        AppTab::System => render_system_tab(f, app, body_chunks[1]),
    }

    // 3. Footer
    render_footer(f, app, chunks[2]);

    // 4. Modals
    render_modals(f, app, size);
}

fn render_header(f: &mut Frame, area: Rect) {
    let header_text = vec![Line::from(vec![
        Span::styled(
            " MCP SENTINEL ",
            Style::default()
                .fg(Color::Cyan)
                .bold()
                .bg(Color::Rgb(20, 30, 45)),
        ),
        Span::raw(" | "),
        Span::styled(
            "Zero-Trust Secret Vault & Security Proxy (v0.1.0)",
            Style::default().fg(Color::White),
        ),
        Span::raw(" | "),
        Span::styled("STDIO ISOLATED", Style::default().fg(Color::Green).bold()),
    ])];

    let header_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray));

    let header_p = Paragraph::new(header_text)
        .block(header_block)
        .alignment(Alignment::Center);

    f.render_widget(header_p, area);
}

fn render_sidebar(f: &mut Frame, app: &mut App, area: Rect) {
    let is_focused = app.focus == FocusArea::Sidebar;

    let border_color = if is_focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    let title_style = if is_focused {
        Style::default().fg(Color::Cyan).bold()
    } else {
        Style::default().fg(Color::White)
    };

    let mut items = Vec::new();

    for (i, (action, label, shortcut)) in SIDEBAR_MENU.iter().enumerate() {
        let is_selected = i == app.sidebar_index;

        let prefix = if is_selected { "► " } else { "  " };

        let style = if is_selected {
            Style::default()
                .fg(Color::Yellow)
                .bg(Color::Rgb(30, 45, 65))
                .bold()
        } else {
            match action {
                SidebarAction::Tab(_) => Style::default().fg(Color::White),
                SidebarAction::Quit => Style::default().fg(Color::Red),
                _ => Style::default().fg(Color::Gray),
            }
        };

        items.push(ListItem::new(Line::from(vec![
            Span::styled(prefix, style),
            Span::styled(format!("{:<15}", label), style),
            Span::styled(
                format!("{:>4}", shortcut),
                Style::default().fg(Color::DarkGray),
            ),
        ])));
    }

    let sidebar_list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(border_color))
            .title(Span::styled(
                if is_focused {
                    " [ MENU: Active ] "
                } else {
                    " [ MENU ] "
                },
                title_style,
            )),
    );

    f.render_widget(sidebar_list, area);
}

fn render_secrets_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let is_focused = app.focus == FocusArea::Content;
    let border_color = if is_focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    // If screen is wide enough, 2 columns; else stacked
    let chunks = if area.width >= 70 {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area)
    };

    // Left: Keys List
    let items: Vec<ListItem> = if app.secrets.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "  (No secrets stored yet)",
            Style::default().fg(Color::DarkGray),
        )))]
    } else {
        app.secrets
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let is_sel = app.secrets_state.selected() == Some(i);
                let prefix = if is_sel { "► " } else { "  " };
                let style = if is_sel {
                    Style::default()
                        .fg(Color::Yellow)
                        .bg(Color::Rgb(30, 45, 65))
                        .bold()
                } else {
                    Style::default().fg(Color::White)
                };

                ListItem::new(Line::from(vec![
                    Span::styled(prefix, style),
                    Span::styled(key, style),
                ]))
            })
            .collect()
    };

    let list_title = format!(" Stored Secrets ({}) ", app.secrets.len());
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(border_color))
                .title(Span::styled(
                    list_title,
                    if is_focused {
                        Style::default().fg(Color::Cyan).bold()
                    } else {
                        Style::default().fg(Color::White)
                    },
                )),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(30, 45, 65))
                .fg(Color::Yellow)
                .bold(),
        );

    f.render_stateful_widget(list, chunks[0], &mut app.secrets_state);

    // Right: Selected Secret Detail Card
    let detail_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " Secret Detail & Operations ",
            Style::default().fg(Color::White).bold(),
        ));

    if let Some(i) = app.secrets_state.selected() {
        if let Some(key_name) = app.secrets.get(i) {
            let details = vec![
                Line::from(vec![
                    Span::styled("Key Name:     ", Style::default().fg(Color::DarkGray)),
                    Span::styled(key_name, Style::default().fg(Color::Cyan).bold()),
                ]),
                Line::from(vec![
                    Span::styled("Enclave:      ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        "OS Native Credential Vault",
                        Style::default().fg(Color::Green),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Status:       ", Style::default().fg(Color::DarkGray)),
                    Span::styled("Hardware/OS Encrypted", Style::default().fg(Color::Yellow)),
                ]),
                Line::from(vec![
                    Span::styled("Secret Value: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        "••••••••••••••••  (Protected)",
                        Style::default().fg(Color::DarkGray),
                    ),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "Actions for selected secret:",
                    Style::default().fg(Color::Magenta).bold(),
                )),
                Line::from(vec![
                    Span::styled(
                        " [Enter / v] ",
                        Style::default()
                            .fg(Color::Yellow)
                            .bg(Color::Rgb(30, 41, 59))
                            .bold(),
                    ),
                    Span::raw(" Reveal Value in Modal"),
                ]),
                Line::from(vec![
                    Span::styled(
                        " [Delete / d] ",
                        Style::default()
                            .fg(Color::Red)
                            .bg(Color::Rgb(30, 41, 59))
                            .bold(),
                    ),
                    Span::raw(" Delete from OS Vault"),
                ]),
                Line::from(vec![
                    Span::styled(
                        " [a] ",
                        Style::default()
                            .fg(Color::Green)
                            .bg(Color::Rgb(30, 41, 59))
                            .bold(),
                    ),
                    Span::raw(" Add New Secret"),
                ]),
                Line::from(vec![
                    Span::styled(
                        " [r] ",
                        Style::default()
                            .fg(Color::Cyan)
                            .bg(Color::Rgb(30, 41, 59))
                            .bold(),
                    ),
                    Span::raw(" Refresh List"),
                ]),
            ];

            let p = Paragraph::new(details)
                .block(detail_block)
                .wrap(Wrap { trim: true });
            f.render_widget(p, chunks[1]);
            return;
        }
    }

    let empty_msg = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            "No secrets stored in vault yet.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::raw("Press "),
            Span::styled("[a]", Style::default().fg(Color::Green).bold()),
            Span::raw(" or select "),
            Span::styled("'Add Secret'", Style::default().fg(Color::Cyan).bold()),
            Span::raw(" in the menu to add one."),
        ]),
    ])
    .block(detail_block)
    .alignment(Alignment::Center);

    f.render_widget(empty_msg, chunks[1]);
}

fn render_permissions_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let is_focused = app.focus == FocusArea::Content;
    let border_color = if is_focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    let rows: Vec<Row> = if app.grants_list.is_empty() {
        Vec::new()
    } else {
        app.grants_list
            .iter()
            .map(|(id, cmd, secrets, created)| {
                Row::new(vec![
                    Span::styled(id, Style::default().fg(Color::Yellow).bold()),
                    Span::styled(cmd, Style::default().fg(Color::White)),
                    Span::styled(secrets, Style::default().fg(Color::Cyan)),
                    Span::styled(created, Style::default().fg(Color::DarkGray)),
                ])
                .height(1)
            })
            .collect()
    };

    let title = format!(" Active TOFU Permissions ({}) ", app.grants_list.len());

    let table = Table::new(
        rows,
        [
            Constraint::Length(14),
            Constraint::Percentage(40),
            Constraint::Percentage(25),
            Constraint::Length(18),
        ],
    )
    .header(
        Row::new(vec![
            Span::styled("FINGERPRINT", Style::default().fg(Color::Cyan).bold()),
            Span::styled("COMMAND / NAME", Style::default().fg(Color::Cyan).bold()),
            Span::styled("GRANTED SECRETS", Style::default().fg(Color::Cyan).bold()),
            Span::styled("CREATED DATE", Style::default().fg(Color::Cyan).bold()),
        ])
        .bottom_margin(1),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(border_color))
            .title(Span::styled(
                title,
                if is_focused {
                    Style::default().fg(Color::Cyan).bold()
                } else {
                    Style::default().fg(Color::White)
                },
            )),
    )
    .highlight_style(
        Style::default()
            .bg(Color::Rgb(30, 45, 65))
            .fg(Color::Yellow)
            .bold(),
    );

    f.render_stateful_widget(table, area, &mut app.permissions_state);
}

fn render_system_tab(f: &mut Frame, _app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7), // Vault
            Constraint::Length(7), // Policy
            Constraint::Min(6),    // Sandbox
        ])
        .split(area);

    // Card 1: Vault
    let vault_lines = vec![
        Line::from(vec![
            Span::styled("Backend Engine:     ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "Windows Credential Manager / Apple Keychain / Linux SecretService",
                Style::default().fg(Color::White).bold(),
            ),
        ]),
        Line::from(vec![
            Span::styled("Disk Exposure:      ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "ZERO Plaintext Secrets on Disk",
                Style::default().fg(Color::Green).bold(),
            ),
        ]),
        Line::from(vec![
            Span::styled("Injection Vector:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "In-Memory Environment Injection strictly during exec()",
                Style::default().fg(Color::Cyan),
            ),
        ]),
    ];
    let card1 = Paragraph::new(vault_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(Span::styled(
                " [ 1. OS-Native Secret Vault ] ",
                Style::default().fg(Color::Cyan).bold(),
            )),
    );
    f.render_widget(card1, chunks[0]);

    // Card 2: Policy
    let policy_lines = vec![
        Line::from(vec![
            Span::styled("Integrity Guard:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "HMAC-SHA256 Cryptographic Signature on permissions.json",
                Style::default().fg(Color::Green).bold(),
            ),
        ]),
        Line::from(vec![
            Span::styled("Master Entropy:     ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "256-bit Hardware-Generated CSPRNG Key stored in Keyring",
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::styled("Access Control:     ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "DACL (Windows) / 0600 (Unix) — Strict Least Privilege",
                Style::default().fg(Color::Yellow),
            ),
        ]),
    ];
    let card2 = Paragraph::new(policy_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(Span::styled(
                " [ 2. TOFU Policy & Cryptographic Integrity ] ",
                Style::default().fg(Color::Green).bold(),
            )),
    );
    f.render_widget(card2, chunks[1]);

    // Card 3: Isolation Sandbox
    let sandbox_lines = vec![
        Line::from(vec![
            Span::styled("Environment Jail:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "Default-Deny Whitelist (AWS, SSH, GITHUB keys purged from child)",
                Style::default().fg(Color::Green),
            ),
        ]),
        Line::from(vec![
            Span::styled("Anti-Recursion:     ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "MCP_SENTINEL_CHILD_CONTEXT=1 (Child recursion blocked with Exit 13)",
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::styled("Process Lifecycle:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "Windows Job Object (KILL_ON_JOB_CLOSE) / Unix Signal Guard",
                Style::default().fg(Color::Yellow),
            ),
        ]),
    ];
    let card3 = Paragraph::new(sandbox_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(Span::styled(
                " [ 3. Subprocess Sandbox & Proxy Stream ] ",
                Style::default().fg(Color::Yellow).bold(),
            )),
    );
    f.render_widget(card3, chunks[2]);
}

fn render_footer(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(area);

    let tips = match app.focus {
        FocusArea::Sidebar => "[Up/Down] Menu  [Enter] Select  [Right/Tab] Enter View  [q] Quit",
        FocusArea::Content => match app.current_tab {
            AppTab::Secrets => "[Up/Down] Select  [Enter/v] Reveal  [d] Delete  [Left/Esc] Menu",
            AppTab::Permissions => "[Up/Down] Select  [Enter/d] Revoke  [x] Reset  [Left/Esc] Menu",
            AppTab::System => "[Left/Esc] Back to Menu  [q] Quit",
        },
    };

    let p_tips = Paragraph::new(Span::styled(tips, Style::default().fg(Color::DarkGray)));
    f.render_widget(p_tips, chunks[0]);

    if let Some((msg, color)) = &app.status_message {
        let p_status = Paragraph::new(Span::styled(msg, Style::default().fg(*color).bold()))
            .alignment(Alignment::Right);
        f.render_widget(p_status, chunks[1]);
    }
}

fn render_modals(f: &mut Frame, app: &mut App, area: Rect) {
    let modal_bg = Style::default().bg(Color::Rgb(15, 23, 42)).fg(Color::White);

    match &app.modal {
        ModalState::None => {}
        ModalState::AddSecret {
            key,
            value,
            focus_value,
        } => {
            let popup_area = centered_rect_exact(68, 14, area);
            f.render_widget(Clear, popup_area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .style(modal_bg)
                .title(Span::styled(
                    " [ Add New Secret to OS Vault ] ",
                    Style::default().fg(Color::Green).bold(),
                ));

            let inner_area = block.inner(popup_area);
            f.render_widget(block, popup_area);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1), // Hint
                    Constraint::Length(3), // Key Input
                    Constraint::Length(1), // Spacer
                    Constraint::Length(3), // Value Input
                    Constraint::Length(1), // Spacer
                    Constraint::Length(1), // Actions
                ])
                .split(inner_area);

            let hint =
                Paragraph::new("Enter standard identifier (e.g. GITHUB_TOKEN) and secret value:")
                    .style(modal_bg);
            f.render_widget(hint, chunks[0]);

            let key_style = if !*focus_value {
                Style::default().fg(Color::Yellow).bold()
            } else {
                Style::default().fg(Color::White)
            };
            let key_block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" Key Name ")
                .style(key_style);
            let display_key = if !*focus_value {
                format!("{}_", key)
            } else {
                key.clone()
            };
            let p_key = Paragraph::new(display_key).block(key_block).style(modal_bg);
            f.render_widget(p_key, chunks[1]);

            let val_style = if *focus_value {
                Style::default().fg(Color::Yellow).bold()
            } else {
                Style::default().fg(Color::White)
            };
            let val_block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" Secret Value ")
                .style(val_style);
            let display_val = if *focus_value {
                format!("{}_", value)
            } else {
                value.clone()
            };
            let p_val = Paragraph::new(display_val).block(val_block).style(modal_bg);
            f.render_widget(p_val, chunks[3]);

            let actions = Paragraph::new(vec![Line::from(vec![
                Span::styled("[Tab] ", Style::default().fg(Color::Cyan).bold()),
                Span::raw("Switch Field  |  "),
                Span::styled("[Enter] ", Style::default().fg(Color::Green).bold()),
                Span::raw("Save to Vault  |  "),
                Span::styled("[Esc] ", Style::default().fg(Color::Red).bold()),
                Span::raw("Cancel"),
            ])])
            .style(modal_bg);
            f.render_widget(actions, chunks[5]);
        }

        ModalState::ConfirmDeleteSecret(name) => {
            let popup_area = centered_rect_exact(54, 8, area);
            f.render_widget(Clear, popup_area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .style(modal_bg)
                .title(Span::styled(
                    " [ Confirm Delete Secret ] ",
                    Style::default().fg(Color::Red).bold(),
                ));

            let inner = block.inner(popup_area);
            f.render_widget(block, popup_area);

            let p = Paragraph::new(vec![
                Line::from(""),
                Line::from(vec![
                    Span::raw("Are you sure you want to permanently delete: "),
                    Span::styled(name, Style::default().fg(Color::Yellow).bold()),
                    Span::raw("?"),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("  [y / Enter] ", Style::default().fg(Color::Red).bold()),
                    Span::raw("Yes, Delete  |  "),
                    Span::styled("[n / Esc] ", Style::default().fg(Color::Green).bold()),
                    Span::raw("Cancel"),
                ]),
            ])
            .style(modal_bg)
            .alignment(Alignment::Center);

            f.render_widget(p, inner);
        }

        ModalState::ConfirmRevokeGrant(id) => {
            let popup_area = centered_rect_exact(62, 9, area);
            f.render_widget(Clear, popup_area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .style(modal_bg)
                .title(Span::styled(
                    " [ Confirm Revoke Permission ] ",
                    Style::default().fg(Color::Red).bold(),
                ));

            let inner = block.inner(popup_area);
            f.render_widget(block, popup_area);

            let p = Paragraph::new(vec![
                Line::from(""),
                Line::from(vec![
                    Span::raw("Revoke authorization for fingerprint: "),
                    Span::styled(
                        &id[..id.len().min(12)],
                        Style::default().fg(Color::Yellow).bold(),
                    ),
                    Span::raw("?"),
                ]),
                Line::from("The server will be required to re-prompt for consent on next run."),
                Line::from(""),
                Line::from(vec![
                    Span::styled("  [y / Enter] ", Style::default().fg(Color::Red).bold()),
                    Span::raw("Yes, Revoke  |  "),
                    Span::styled("[n / Esc] ", Style::default().fg(Color::Green).bold()),
                    Span::raw("Cancel"),
                ]),
            ])
            .style(modal_bg)
            .alignment(Alignment::Center);

            f.render_widget(p, inner);
        }

        ModalState::ConfirmResetGrants => {
            let popup_area = centered_rect_exact(62, 9, area);
            f.render_widget(Clear, popup_area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .style(modal_bg)
                .title(Span::styled(
                    " [ Confirm Reset All Permissions ] ",
                    Style::default().fg(Color::Red).bold(),
                ));

            let inner = block.inner(popup_area);
            f.render_widget(block, popup_area);

            let p = Paragraph::new(vec![
                Line::from(""),
                Line::from(Span::styled(
                    "DANGER: This will wipe all saved MCP authorizations!",
                    Style::default().fg(Color::Red).bold(),
                )),
                Line::from("Every MCP server will be forced to prompt for consent again."),
                Line::from(""),
                Line::from(vec![
                    Span::styled("  [y / Enter] ", Style::default().fg(Color::Red).bold()),
                    Span::raw("Yes, Reset All  |  "),
                    Span::styled("[n / Esc] ", Style::default().fg(Color::Green).bold()),
                    Span::raw("Cancel"),
                ]),
            ])
            .style(modal_bg)
            .alignment(Alignment::Center);

            f.render_widget(p, inner);
        }

        ModalState::RevealSecret { key, value } => {
            let popup_area = centered_rect_exact(62, 10, area);
            f.render_widget(Clear, popup_area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .style(modal_bg)
                .title(Span::styled(
                    " [ Revealed Secret Value ] ",
                    Style::default().fg(Color::Yellow).bold(),
                ));

            let inner = block.inner(popup_area);
            f.render_widget(block, popup_area);

            let p = Paragraph::new(vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled("Key Name:     ", Style::default().fg(Color::DarkGray)),
                    Span::styled(key, Style::default().fg(Color::Cyan).bold()),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Secret Value: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(value, Style::default().fg(Color::Yellow).bold()),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "Press [Esc] or [Enter] to close",
                    Style::default().fg(Color::DarkGray),
                )),
            ])
            .style(modal_bg)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true });

            f.render_widget(p, inner);
        }
    }
}

fn centered_rect_exact(width: u16, height: u16, r: Rect) -> Rect {
    let actual_width = width.min(r.width.saturating_sub(4));
    let actual_height = height.min(r.height.saturating_sub(2));

    let x = r.x + (r.width.saturating_sub(actual_width)) / 2;
    let y = r.y + (r.height.saturating_sub(actual_height)) / 2;

    Rect {
        x,
        y,
        width: actual_width,
        height: actual_height,
    }
}
