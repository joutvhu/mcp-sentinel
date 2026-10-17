use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap},
    Frame,
};

use crate::tui::app::{App, ModalState};
use crate::tui::widgets::centered_rect_exact;

pub fn render_modals(f: &mut Frame, app: &mut App, area: Rect) {
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
            let p_key = Paragraph::new(key.to_display_line(!*focus_value))
                .block(key_block)
                .style(modal_bg);
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
            let p_val = Paragraph::new(value.to_display_line(*focus_value))
                .block(val_block)
                .style(modal_bg);
            f.render_widget(p_val, chunks[3]);

            let actions = Paragraph::new(vec![Line::from(vec![
                Span::styled("[Tab] ", Style::default().fg(Color::Cyan).bold()),
                Span::raw("Switch  |  "),
                Span::styled("[Left/Right] ", Style::default().fg(Color::Cyan).bold()),
                Span::raw("Move  |  "),
                Span::styled("[Enter] ", Style::default().fg(Color::Green).bold()),
                Span::raw("Save  |  "),
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
                    Span::styled("  [y] ", Style::default().fg(Color::Red).bold()),
                    Span::raw("Yes, Delete  |  "),
                    Span::styled("[n / Esc] ", Style::default().fg(Color::Green).bold()),
                    Span::raw("Cancel"),
                ]),
            ])
            .style(modal_bg)
            .alignment(Alignment::Center);

            f.render_widget(p, inner);
        }

        ModalState::ConfirmDeleteProfile(name) => {
            let popup_area = centered_rect_exact(56, 8, area);
            f.render_widget(Clear, popup_area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .style(modal_bg)
                .title(Span::styled(
                    " [ Confirm Delete Tool Profile ] ",
                    Style::default().fg(Color::Red).bold(),
                ));

            let inner = block.inner(popup_area);
            f.render_widget(block, popup_area);

            let p = Paragraph::new(vec![
                Line::from(""),
                Line::from(vec![
                    Span::raw("Are you sure you want to delete profile: "),
                    Span::styled(name, Style::default().fg(Color::Yellow).bold()),
                    Span::raw("?"),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("  [y] ", Style::default().fg(Color::Red).bold()),
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
                    Span::styled("  [y] ", Style::default().fg(Color::Red).bold()),
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
                    Span::styled("  [y] ", Style::default().fg(Color::Red).bold()),
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
            let popup_area = centered_rect_exact(66, 12, area);
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
                    "[Up/Down/PgUp/Dn] Scroll  |  [Esc/Enter] Close",
                    Style::default().fg(Color::DarkGray),
                )),
            ])
            .style(modal_bg)
            .alignment(Alignment::Center)
            .scroll((app.modal_scroll, 0))
            .wrap(Wrap { trim: true });

            f.render_widget(p, inner);
        }

        ModalState::ViewGrant {
            id,
            name,
            command,
            secrets,
            created_at,
        } => {
            let popup_area = centered_rect_exact(76, 16, area);
            f.render_widget(Clear, popup_area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .style(modal_bg)
                .title(Span::styled(
                    " [ Authorization Grant Inspection ] ",
                    Style::default().fg(Color::Cyan).bold(),
                ));

            let inner = block.inner(popup_area);
            f.render_widget(block, popup_area);

            let mut lines = Vec::new();
            lines.push(Line::from(vec![
                Span::styled("MCP Client Name: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    name.as_deref().unwrap_or("(Unnamed Client)"),
                    Style::default().fg(Color::White).bold(),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Grant Full ID:   ", Style::default().fg(Color::DarkGray)),
                Span::styled(id, Style::default().fg(Color::Rgb(140, 200, 255))),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Authorized At:   ", Style::default().fg(Color::DarkGray)),
                Span::styled(created_at, Style::default().fg(Color::DarkGray)),
            ]));
            lines.push(Line::from(""));

            lines.push(Line::from(Span::styled(
                "Authorized Command & Executable Args:",
                Style::default().fg(Color::Yellow).bold(),
            )));
            lines.push(Line::from(Span::styled(
                format!("  {}", command),
                Style::default().fg(Color::White),
            )));
            lines.push(Line::from(""));

            lines.push(Line::from(Span::styled(
                "Injected Secrets / Environment Aliases:",
                Style::default().fg(Color::Green).bold(),
            )));
            if secrets.is_empty() {
                lines.push(Line::from(Span::styled(
                    "  (No secrets attached to this grant)",
                    Style::default().fg(Color::DarkGray),
                )));
            } else {
                for s in secrets {
                    lines.push(Line::from(vec![
                        Span::styled("  • ", Style::default().fg(Color::Green).bold()),
                        Span::styled(s, Style::default().fg(Color::Cyan)),
                    ]));
                }
            }

            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "[Up/Down/PgUp/Dn] Scroll  |  [d] Revoke  |  [Esc/Enter] Close",
                Style::default().fg(Color::DarkGray),
            )));

            let p = Paragraph::new(lines)
                .style(modal_bg)
                .scroll((app.modal_scroll, 0))
                .wrap(Wrap { trim: true });

            f.render_widget(p, inner);
        }

        ModalState::ViewProfile {
            name,
            description,
            allow,
            deny,
        } => {
            let popup_area = centered_rect_exact(76, 18, area);
            f.render_widget(Clear, popup_area);

            let is_builtin = name == "read-only" || name == "no-destructive";
            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .style(modal_bg)
                .title(Span::styled(
                    format!(" [ Profile Security Specification: {} ] ", name),
                    Style::default().fg(Color::Yellow).bold(),
                ));

            let inner = block.inner(popup_area);
            f.render_widget(block, popup_area);

            let mut lines = Vec::new();
            lines.push(Line::from(vec![
                Span::styled("Profile Name:     ", Style::default().fg(Color::DarkGray)),
                Span::styled(name, Style::default().fg(Color::Yellow).bold()),
                Span::raw("  "),
                if is_builtin {
                    Span::styled(
                        "[ BUILT-IN PRESET ]",
                        Style::default().fg(Color::Cyan).bold(),
                    )
                } else {
                    Span::styled(
                        "[ CUSTOM PROFILE ]",
                        Style::default().fg(Color::Green).bold(),
                    )
                },
            ]));

            let desc = description
                .as_deref()
                .unwrap_or("(No description provided)");
            lines.push(Line::from(vec![
                Span::styled("Description:      ", Style::default().fg(Color::DarkGray)),
                Span::styled(desc, Style::default().fg(Color::White)),
            ]));

            lines.push(Line::from(vec![
                Span::styled("Enforcement:      ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    "Layer 7 JSON-RPC Interceptor & Drop",
                    Style::default().fg(Color::Cyan),
                ),
            ]));
            lines.push(Line::from(""));

            lines.push(Line::from(Span::styled(
                "Allowed Tool Patterns (Whitelist):",
                Style::default().fg(Color::Green).bold(),
            )));
            if allow.is_empty() {
                lines.push(Line::from(Span::styled(
                    "  (None - all tools denied unless permitted)",
                    Style::default().fg(Color::DarkGray),
                )));
            } else {
                for pat in allow {
                    lines.push(Line::from(vec![
                        Span::styled("  ✓ ", Style::default().fg(Color::Green).bold()),
                        Span::styled(pat, Style::default().fg(Color::White)),
                    ]));
                }
            }
            lines.push(Line::from(""));

            lines.push(Line::from(Span::styled(
                "Denied Tool Patterns (Blacklist - Strict Precedence):",
                Style::default().fg(Color::Red).bold(),
            )));
            if deny.is_empty() {
                lines.push(Line::from(Span::styled(
                    "  (None - no tools blacklisted)",
                    Style::default().fg(Color::DarkGray),
                )));
            } else {
                for pat in deny {
                    lines.push(Line::from(vec![
                        Span::styled("  ✗ ", Style::default().fg(Color::Red).bold()),
                        Span::styled(pat, Style::default().fg(Color::Red)),
                    ]));
                }
            }
            lines.push(Line::from(""));

            lines.push(Line::from(vec![
                Span::styled("CLI Run Usage:    ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("mcp-sentinel run --profile {} -- <command>", name),
                    Style::default().fg(Color::Rgb(140, 200, 255)),
                ),
            ]));

            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "[Up/Down/PgUp/Dn/Wheel] Scroll  |  [Esc/Enter] Close",
                Style::default().fg(Color::DarkGray),
            )));

            let p = Paragraph::new(lines)
                .style(modal_bg)
                .scroll((app.modal_scroll, 0))
                .wrap(Wrap { trim: true });

            f.render_widget(p, inner);
        }

        ModalState::UpdateSecret { key, value } => {
            let popup_area = centered_rect_exact(68, 12, area);
            f.render_widget(Clear, popup_area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .style(modal_bg)
                .title(Span::styled(
                    format!(" [ Update Secret: {} ] ", key),
                    Style::default().fg(Color::Cyan).bold(),
                ));

            let inner_area = block.inner(popup_area);
            f.render_widget(block, popup_area);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1), // Hint
                    Constraint::Length(1), // Spacer
                    Constraint::Length(3), // Value Input
                    Constraint::Length(1), // Spacer
                    Constraint::Length(1), // Actions
                ])
                .split(inner_area);

            let hint = Paragraph::new(vec![Line::from(vec![
                Span::raw("Update secret value in OS Vault for: "),
                Span::styled(key, Style::default().fg(Color::Cyan).bold()),
            ])])
            .style(modal_bg);
            f.render_widget(hint, chunks[0]);

            let val_block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" New Secret Value ")
                .style(Style::default().fg(Color::Yellow).bold());
            let p_val = Paragraph::new(value.to_display_line(true))
                .block(val_block)
                .style(modal_bg);
            f.render_widget(p_val, chunks[2]);

            let actions = Paragraph::new(vec![Line::from(vec![
                Span::styled("[Left/Right] ", Style::default().fg(Color::Cyan).bold()),
                Span::raw("Move Cursor  |  "),
                Span::styled("[Enter] ", Style::default().fg(Color::Green).bold()),
                Span::raw("Save / Update  |  "),
                Span::styled("[Esc] ", Style::default().fg(Color::Red).bold()),
                Span::raw("Cancel"),
            ])])
            .style(modal_bg);
            f.render_widget(actions, chunks[4]);
        }
    }
}
