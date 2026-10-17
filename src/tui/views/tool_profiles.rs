use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

use crate::tui::app::{App, FocusArea};

pub fn render_tool_profiles_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let is_focused = app.focus == FocusArea::Content;
    let is_detail_focused = app.focus == FocusArea::Detail;

    let border_color = if is_focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    let chunks = if area.width >= 70 {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area)
    };

    // Left: Profile list
    let items: Vec<ListItem> = if app.tool_profiles.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "  (No tool profiles found)",
            Style::default().fg(Color::DarkGray),
        )))]
    } else {
        app.tool_profiles
            .iter()
            .enumerate()
            .map(|(i, prof)| {
                let is_sel = app.tool_profiles_state.selected() == Some(i);
                let prefix = if is_sel { "► " } else { "  " };
                let is_builtin = prof.name == "read-only" || prof.name == "no-destructive";
                let tag = if is_builtin { " [Preset]" } else { " [Custom]" };
                let style = if is_sel {
                    Style::default()
                        .fg(Color::Yellow)
                        .bg(Color::Rgb(30, 45, 65))
                        .bold()
                } else {
                    Style::default().fg(Color::White)
                };
                let tag_style = if is_builtin {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::Green)
                };

                ListItem::new(Line::from(vec![
                    Span::styled(prefix, style),
                    Span::styled(&prof.name, style),
                    Span::styled(tag, tag_style),
                ]))
            })
            .collect()
    };

    let list_title = format!(" Tool Profiles ({}) ", app.tool_profiles.len());
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

    f.render_stateful_widget(list, chunks[0], &mut app.tool_profiles_state);

    // Right: Selected Profile Details
    let detail_border_color = if is_detail_focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    let detail_title = if is_detail_focused {
        " [ Profile Security Specification — Scroll: Up/Down/Wheel | Enter: Full Modal ] "
    } else if is_focused {
        " Profile Security Specification [Right: Scroll | Enter: Full Modal] "
    } else {
        " Profile Security Specification [Right/Tab to View & Scroll] "
    };

    let detail_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(detail_border_color))
        .title(Span::styled(
            detail_title,
            if is_detail_focused {
                Style::default().fg(Color::Cyan).bold()
            } else {
                Style::default().fg(Color::White).bold()
            },
        ));

    if let Some(i) = app.tool_profiles_state.selected() {
        if let Some(prof) = app.tool_profiles.get(i) {
            let is_builtin = prof.name == "read-only" || prof.name == "no-destructive";
            let mut lines = Vec::new();

            lines.push(Line::from(vec![
                Span::styled("Profile Name:     ", Style::default().fg(Color::DarkGray)),
                Span::styled(&prof.name, Style::default().fg(Color::Yellow).bold()),
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

            let desc = prof
                .description
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

            lines.push(Line::from(vec![Span::styled(
                "Allowed Tool Patterns (Whitelist):",
                Style::default().fg(Color::Green).bold(),
            )]));
            if prof.allow.is_empty() {
                lines.push(Line::from(Span::styled(
                    "  (None)",
                    Style::default().fg(Color::DarkGray),
                )));
            } else {
                for pat in &prof.allow {
                    lines.push(Line::from(vec![
                        Span::styled("  ✓ ", Style::default().fg(Color::Green).bold()),
                        Span::styled(pat, Style::default().fg(Color::White)),
                    ]));
                }
            }

            lines.push(Line::from(""));

            lines.push(Line::from(vec![Span::styled(
                "Denied Tool Patterns (Blacklist - Strict Precedence):",
                Style::default().fg(Color::Red).bold(),
            )]));
            if prof.deny.is_empty() {
                lines.push(Line::from(Span::styled(
                    "  (None - no tools blacklisted)",
                    Style::default().fg(Color::DarkGray),
                )));
            } else {
                for pat in &prof.deny {
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
                    format!("mcp-sentinel run --profile {} -- <command>", prof.name),
                    Style::default().fg(Color::Rgb(140, 200, 255)),
                ),
            ]));

            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Controls: [Up/Down/Wheel] Scroll  |  [Enter/v] Full Modal  |  [Left] List",
                Style::default().fg(Color::DarkGray),
            )));

            let p_detail = Paragraph::new(lines)
                .block(detail_block)
                .scroll((app.detail_scroll, 0))
                .wrap(Wrap { trim: true });
            f.render_widget(p_detail, chunks[1]);
            return;
        }
    }

    let empty_msg = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            "Select a profile on the left to inspect its security rules.",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .block(detail_block)
    .alignment(Alignment::Center);

    f.render_widget(empty_msg, chunks[1]);
}
