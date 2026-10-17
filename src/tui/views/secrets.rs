use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

use crate::tui::app::{App, FocusArea};

pub fn render_secrets_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let is_focused = app.focus == FocusArea::Content;
    let is_detail_focused = app.focus == FocusArea::Detail;
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
    let detail_border_color = if is_detail_focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    let detail_title = if is_detail_focused {
        " [ Secret Detail & Operations — Scroll: Up/Down/Wheel ] "
    } else if is_focused {
        " Secret Detail & Operations [Right: Scroll Details] "
    } else {
        " Secret Detail & Operations "
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
                        " [e] ",
                        Style::default()
                            .fg(Color::Cyan)
                            .bg(Color::Rgb(30, 41, 59))
                            .bold(),
                    ),
                    Span::raw(" Edit / Update Secret Value"),
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
                .wrap(Wrap { trim: true })
                .scroll((app.detail_scroll, 0));
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
