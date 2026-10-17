use std::io;
use std::time::Duration;

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, style::Color, Terminal};

use crate::policy;
use crate::tool_policy;
use crate::vault;
use super::app::{App, AppTab, FocusArea, ModalState, SidebarAction, SIDEBAR_MENU};
use super::views::ui;

pub fn run_tui() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();

    let res = main_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
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
            match event::read()? {
                Event::Key(key) => {
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
                                let key_trimmed = k.text.trim().to_string();
                                let val_trimmed = v.text.trim().to_string();

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
                            KeyCode::Left => {
                                if *focus_value {
                                    v.move_left();
                                } else {
                                    k.move_left();
                                }
                            }
                            KeyCode::Right => {
                                if *focus_value {
                                    v.move_right();
                                } else {
                                    k.move_right();
                                }
                            }
                            KeyCode::Home => {
                                if *focus_value {
                                    v.move_home();
                                } else {
                                    k.move_home();
                                }
                            }
                            KeyCode::End => {
                                if *focus_value {
                                    v.move_end();
                                } else {
                                    k.move_end();
                                }
                            }
                            KeyCode::Delete => {
                                if *focus_value {
                                    v.delete();
                                } else {
                                    k.delete();
                                }
                            }
                            KeyCode::Backspace => {
                                if *focus_value {
                                    v.backspace();
                                } else {
                                    k.backspace();
                                }
                            }
                            KeyCode::Char(c) => {
                                if *focus_value {
                                    v.insert(c);
                                } else {
                                    k.insert(c);
                                }
                            }
                            _ => {}
                        },

                        ModalState::ConfirmDeleteSecret(secret_name) => match key.code {
                            KeyCode::Char('y') | KeyCode::Char('Y') => {
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
                            KeyCode::Char('y') | KeyCode::Char('Y') => {
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

                        ModalState::ConfirmDeleteProfile(profile_name) => match key.code {
                            KeyCode::Char('y') | KeyCode::Char('Y') => {
                                let name = profile_name.clone();
                                match tool_policy::delete_profile(&name) {
                                    Ok(true) => {
                                        app.reload_tool_profiles();
                                        app.modal = ModalState::None;
                                        app.status_message = Some((
                                            format!("✓ Tool profile '{}' deleted successfully.", name),
                                            Color::Green,
                                        ));
                                    }
                                    Ok(false) => {
                                        app.modal = ModalState::None;
                                        app.status_message = Some((
                                            format!("Profile '{}' not found.", name),
                                            Color::Yellow,
                                        ));
                                    }
                                    Err(e) => {
                                        app.modal = ModalState::None;
                                        app.status_message = Some((
                                            format!("Error deleting profile: {}", e),
                                            Color::Red,
                                        ));
                                    }
                                }
                            }
                            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                                app.modal = ModalState::None;
                                app.status_message =
                                    Some(("Delete profile cancelled.".to_string(), Color::DarkGray));
                            }
                            _ => {}
                        },

                        ModalState::ConfirmResetGrants => match key.code {
                            KeyCode::Char('y') | KeyCode::Char('Y') => match policy::reset_grants() {
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
                            },
                            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                                app.modal = ModalState::None;
                                app.status_message =
                                    Some(("Reset cancelled.".to_string(), Color::DarkGray));
                            }
                            _ => {}
                        },

                        ModalState::RevealSecret { .. } => match key.code {
                            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('v') | KeyCode::Char('q') => {
                                app.modal = ModalState::None;
                            }
                            KeyCode::Up | KeyCode::Char('k') => {
                                app.modal_scroll = app.modal_scroll.saturating_sub(1);
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                app.modal_scroll = app.modal_scroll.saturating_add(1);
                            }
                            KeyCode::PageUp => {
                                app.modal_scroll = app.modal_scroll.saturating_sub(4);
                            }
                            KeyCode::PageDown => {
                                app.modal_scroll = app.modal_scroll.saturating_add(4);
                            }
                            _ => {}
                        },

                        ModalState::ViewGrant { id, .. } => match key.code {
                            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                                app.modal = ModalState::None;
                            }
                            KeyCode::Up | KeyCode::Char('k') => {
                                app.modal_scroll = app.modal_scroll.saturating_sub(1);
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                app.modal_scroll = app.modal_scroll.saturating_add(1);
                            }
                            KeyCode::PageUp => {
                                app.modal_scroll = app.modal_scroll.saturating_sub(4);
                            }
                            KeyCode::PageDown => {
                                app.modal_scroll = app.modal_scroll.saturating_add(4);
                            }
                            KeyCode::Char('d') | KeyCode::Delete => {
                                let full_id = id.clone();
                                app.modal = ModalState::ConfirmRevokeGrant(full_id);
                            }
                            _ => {}
                        },

                        ModalState::ViewProfile { name, .. } => match key.code {
                            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char('v') => {
                                app.modal = ModalState::None;
                            }
                            KeyCode::Up | KeyCode::Char('k') => {
                                app.modal_scroll = app.modal_scroll.saturating_sub(1);
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                app.modal_scroll = app.modal_scroll.saturating_add(1);
                            }
                            KeyCode::PageUp => {
                                app.modal_scroll = app.modal_scroll.saturating_sub(4);
                            }
                            KeyCode::PageDown => {
                                app.modal_scroll = app.modal_scroll.saturating_add(4);
                            }
                            KeyCode::Char('d') | KeyCode::Delete => {
                                let full_name = name.clone();
                                app.modal = ModalState::ConfirmDeleteProfile(full_name);
                            }
                            _ => {}
                        },

                        ModalState::UpdateSecret { key: k, value: v } => match key.code {
                            KeyCode::Esc => {
                                app.modal = ModalState::None;
                                app.status_message =
                                    Some(("Update secret cancelled.".to_string(), Color::DarkGray));
                            }
                            KeyCode::Enter => {
                                let key_name = k.clone();
                                let val_trimmed = v.text.trim().to_string();
                                match vault::set_secret(&key_name, &val_trimmed) {
                                    Ok(_) => {
                                        app.reload_secrets();
                                        app.modal = ModalState::None;
                                        app.status_message = Some((
                                            format!("✓ Secret '{}' updated successfully!", key_name),
                                            Color::Green,
                                        ));
                                    }
                                    Err(e) => {
                                        app.status_message =
                                            Some((format!("Error updating secret: {}", e), Color::Red));
                                    }
                                }
                            }
                            KeyCode::Left => {
                                v.move_left();
                            }
                            KeyCode::Right => {
                                v.move_right();
                            }
                            KeyCode::Home => {
                                v.move_home();
                            }
                            KeyCode::End => {
                                v.move_end();
                            }
                            KeyCode::Delete => {
                                v.delete();
                            }
                            KeyCode::Backspace => {
                                v.backspace();
                            }
                            KeyCode::Char(c) => {
                                v.insert(c);
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
                                    app.detail_scroll = 0;
                                    continue;
                                }
                                KeyCode::Char('2') => {
                                    app.current_tab = AppTab::Permissions;
                                    app.sidebar_index = 1;
                                    app.focus = FocusArea::Content;
                                    app.detail_scroll = 0;
                                    continue;
                                }
                                KeyCode::Char('3') => {
                                    app.current_tab = AppTab::ToolProfiles;
                                    app.sidebar_index = 2;
                                    app.focus = FocusArea::Content;
                                    app.detail_scroll = 0;
                                    continue;
                                }
                                KeyCode::Char('4') => {
                                    app.current_tab = AppTab::System;
                                    app.sidebar_index = 3;
                                    app.focus = FocusArea::Content;
                                    app.detail_scroll = 0;
                                    continue;
                                }
                                KeyCode::Char('a') => {
                                    app.open_add_modal();
                                    continue;
                                }
                                KeyCode::Char('r') => {
                                    app.reload_secrets();
                                    app.reload_permissions();
                                    app.reload_tool_profiles();
                                    app.status_message = Some((
                                        "✓ Vault, permissions, and tool profiles reloaded.".to_string(),
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
                                        app.detail_scroll = 0;
                                    }
                                    KeyCode::Down | KeyCode::Char('j') => {
                                        app.sidebar_down();
                                        app.detail_scroll = 0;
                                    }
                                    KeyCode::PageUp => {
                                        app.detail_scroll = app.detail_scroll.saturating_sub(4);
                                    }
                                    KeyCode::PageDown => {
                                        app.detail_scroll = app.detail_scroll.saturating_add(4);
                                    }
                                    KeyCode::Enter => {
                                        if let Some((action, _, _)) =
                                            SIDEBAR_MENU.get(app.sidebar_index)
                                        {
                                            match action {
                                                SidebarAction::Tab(tab) => {
                                                    app.current_tab = *tab;
                                                    if *tab == AppTab::System {
                                                        app.focus = FocusArea::Detail;
                                                    } else {
                                                        app.focus = FocusArea::Content;
                                                    }
                                                    app.detail_scroll = 0;
                                                }
                                                SidebarAction::AddSecret => {
                                                    app.open_add_modal();
                                                }
                                                SidebarAction::RefreshVault => {
                                                    app.reload_secrets();
                                                    app.reload_permissions();
                                                    app.reload_tool_profiles();
                                                    app.status_message = Some((
                                                        "✓ Vault, permissions, and tool profiles refreshed."
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
                                        if app.current_tab == AppTab::System {
                                            app.focus = FocusArea::Detail;
                                        } else {
                                            app.focus = FocusArea::Content;
                                        }
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
                                    KeyCode::Right => {
                                        if app.current_tab == AppTab::ToolProfiles
                                            || app.current_tab == AppTab::Secrets
                                        {
                                            app.focus = FocusArea::Detail;
                                        }
                                    }
                                    KeyCode::Up | KeyCode::Char('k') => {
                                        app.content_up();
                                    }
                                    KeyCode::Down | KeyCode::Char('j') => {
                                        app.content_down();
                                    }
                                    KeyCode::PageUp => {
                                        app.detail_scroll = app.detail_scroll.saturating_sub(4);
                                    }
                                    KeyCode::PageDown => {
                                        app.detail_scroll = app.detail_scroll.saturating_add(4);
                                    }
                                    KeyCode::Tab => {
                                        if app.current_tab == AppTab::ToolProfiles
                                            || app.current_tab == AppTab::Secrets
                                        {
                                            app.focus = FocusArea::Detail;
                                        } else {
                                            app.focus = FocusArea::Sidebar;
                                        }
                                    }
                                    KeyCode::Enter => match app.current_tab {
                                        AppTab::Secrets => app.open_reveal_modal(),
                                        AppTab::Permissions => app.open_view_grant_modal(),
                                        AppTab::ToolProfiles => app.open_view_profile_modal(),
                                        AppTab::System => {}
                                    },
                                    KeyCode::Char('v') => match app.current_tab {
                                        AppTab::Secrets => app.open_reveal_modal(),
                                        AppTab::Permissions => app.open_view_grant_modal(),
                                        AppTab::ToolProfiles => app.open_view_profile_modal(),
                                        _ => {}
                                    },
                                    KeyCode::Char('e') if app.current_tab == AppTab::Secrets => {
                                        app.open_update_modal();
                                    }
                                    KeyCode::Char('d') | KeyCode::Delete => match app.current_tab {
                                        AppTab::Secrets => app.open_delete_modal(),
                                        AppTab::Permissions => app.open_revoke_modal(),
                                        AppTab::ToolProfiles => app.open_delete_profile_modal(),
                                        AppTab::System => {}
                                    },
                                    _ => {}
                                },

                                FocusArea::Detail => match key.code {
                                    KeyCode::Left | KeyCode::BackTab | KeyCode::Esc => {
                                        if app.current_tab == AppTab::System {
                                            app.focus = FocusArea::Sidebar;
                                        } else {
                                            app.focus = FocusArea::Content;
                                        }
                                    }
                                    KeyCode::Tab => {
                                        app.focus = FocusArea::Sidebar;
                                    }
                                    KeyCode::Up | KeyCode::Char('k') => {
                                        app.detail_scroll = app.detail_scroll.saturating_sub(1);
                                    }
                                    KeyCode::Down | KeyCode::Char('j') => {
                                        app.detail_scroll = app.detail_scroll.saturating_add(1);
                                    }
                                    KeyCode::PageUp => {
                                        app.detail_scroll = app.detail_scroll.saturating_sub(4);
                                    }
                                    KeyCode::PageDown => {
                                        app.detail_scroll = app.detail_scroll.saturating_add(4);
                                    }
                                    KeyCode::Home => {
                                        app.detail_scroll = 0;
                                    }
                                    KeyCode::End => {
                                        app.detail_scroll = app.detail_scroll.saturating_add(20);
                                    }
                                    KeyCode::Enter | KeyCode::Char('v') => match app.current_tab {
                                        AppTab::ToolProfiles => app.open_view_profile_modal(),
                                        AppTab::Secrets => app.open_reveal_modal(),
                                        _ => {}
                                    },
                                    KeyCode::Char('d') | KeyCode::Delete
                                        if app.current_tab == AppTab::ToolProfiles =>
                                    {
                                        app.open_delete_profile_modal();
                                    }
                                    KeyCode::Char('d') | KeyCode::Delete
                                        if app.current_tab == AppTab::Secrets =>
                                    {
                                        app.open_delete_modal();
                                    }
                                    _ => {}
                                },
                            }
                        }
                    }
                }
                Event::Mouse(mouse) => match mouse.kind {
                    MouseEventKind::ScrollDown => match &mut app.modal {
                        ModalState::None => {
                            app.detail_scroll = app.detail_scroll.saturating_add(2);
                        }
                        _ => {
                            app.modal_scroll = app.modal_scroll.saturating_add(2);
                        }
                    },
                    MouseEventKind::ScrollUp => match &mut app.modal {
                        ModalState::None => {
                            app.detail_scroll = app.detail_scroll.saturating_sub(2);
                        }
                        _ => {
                            app.modal_scroll = app.modal_scroll.saturating_sub(2);
                        }
                    },
                    _ => {}
                },
                _ => {}
            }
        }
    }
}
