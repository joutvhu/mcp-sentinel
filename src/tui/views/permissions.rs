use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Style, Stylize},
    text::Span,
    widgets::{Block, BorderType, Borders, Row, Table},
    Frame,
};

use crate::tui::app::{App, FocusArea};

pub fn render_permissions_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let is_focused = app.focus == FocusArea::Content;
    let border_color = if is_focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    let col_constraints = if area.width < 75 {
        vec![
            Constraint::Length(12),
            Constraint::Percentage(55),
            Constraint::Percentage(45),
        ]
    } else {
        vec![
            Constraint::Length(14),
            Constraint::Percentage(40),
            Constraint::Percentage(25),
            Constraint::Length(18),
        ]
    };

    let header_cells = if area.width < 75 {
        vec![
            Span::styled("FINGERPRINT", Style::default().fg(Color::Cyan).bold()),
            Span::styled("COMMAND / NAME", Style::default().fg(Color::Cyan).bold()),
            Span::styled("SECRETS", Style::default().fg(Color::Cyan).bold()),
        ]
    } else {
        vec![
            Span::styled("FINGERPRINT", Style::default().fg(Color::Cyan).bold()),
            Span::styled("COMMAND / NAME", Style::default().fg(Color::Cyan).bold()),
            Span::styled("GRANTED SECRETS", Style::default().fg(Color::Cyan).bold()),
            Span::styled("CREATED DATE", Style::default().fg(Color::Cyan).bold()),
        ]
    };

    let rows: Vec<Row> = if app.grants_list.is_empty() {
        Vec::new()
    } else {
        app.grants_list
            .iter()
            .map(|(id, cmd, secrets, created)| {
                let cells = if area.width < 75 {
                    vec![
                        Span::styled(id, Style::default().fg(Color::Yellow).bold()),
                        Span::styled(cmd, Style::default().fg(Color::White)),
                        Span::styled(secrets, Style::default().fg(Color::Cyan)),
                    ]
                } else {
                    vec![
                        Span::styled(id, Style::default().fg(Color::Yellow).bold()),
                        Span::styled(cmd, Style::default().fg(Color::White)),
                        Span::styled(secrets, Style::default().fg(Color::Cyan)),
                        Span::styled(created, Style::default().fg(Color::DarkGray)),
                    ]
                };
                Row::new(cells).height(1)
            })
            .collect()
    };

    let title = format!(
        " Active TOFU Permissions ({}) [Enter: Full Details] ",
        app.grants_list.len()
    );

    let table = Table::new(rows, col_constraints)
        .header(Row::new(header_cells).bottom_margin(1))
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
