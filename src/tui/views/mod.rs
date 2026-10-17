pub mod modals;
pub mod permissions;
pub mod secrets;
pub mod system;
pub mod tool_profiles;

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, Paragraph},
    Frame,
};

use crate::tui::app::{App, AppTab, FocusArea, SidebarAction, SIDEBAR_MENU};
use modals::render_modals;
use permissions::render_permissions_tab;
use secrets::render_secrets_tab;
use system::render_system_tab;
use tool_profiles::render_tool_profiles_tab;

pub fn ui(f: &mut Frame, app: &mut App) {
    let size = f.area();

    // Responsive header & footer height
    let header_height = if size.height < 12 {
        0
    } else if size.height < 20 {
        1
    } else {
        3
    };
    let footer_height = if size.height < 16 { 1 } else { 2 };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(header_height), // Header Banner
            Constraint::Min(6),                // Sidebar + Content
            Constraint::Length(footer_height), // Footer Keybinds & Status
        ])
        .split(size);

    // Responsive sidebar width based on available terminal columns
    let sidebar_width = if size.width < 70 {
        18
    } else if size.width < 90 {
        22
    } else {
        28
    };

    // 1. Header
    render_header(f, chunks[0]);

    // 2. Middle Body: Left Sidebar + Right Content View
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(sidebar_width), // Adaptive sidebar width
            Constraint::Min(24),               // Main content
        ])
        .split(chunks[1]);

    render_sidebar(f, app, body_chunks[0]);

    match app.current_tab {
        AppTab::Secrets => render_secrets_tab(f, app, body_chunks[1]),
        AppTab::Permissions => render_permissions_tab(f, app, body_chunks[1]),
        AppTab::ToolProfiles => render_tool_profiles_tab(f, app, body_chunks[1]),
        AppTab::System => render_system_tab(f, app, body_chunks[1]),
    }

    // 3. Footer
    render_footer(f, app, chunks[2]);

    // 4. Modals
    render_modals(f, app, size);
}

pub fn render_header(f: &mut Frame, area: Rect) {
    if area.height == 0 {
        return;
    }

    let is_compact = area.height < 3;

    let header_lines = if is_compact {
        vec![Line::from(vec![
            Span::styled(
                " MCP SENTINEL ",
                Style::default().bg(Color::Cyan).fg(Color::Black).bold(),
            ),
            Span::raw(" | "),
            Span::styled(
                format!("v{}", env!("CARGO_PKG_VERSION")),
                Style::default().fg(Color::Yellow).bold(),
            ),
            Span::raw(" | "),
            Span::styled(
                "Zero-Trust Secret Vault & Proxy",
                Style::default().fg(Color::White),
            ),
        ])]
    } else {
        vec![
            Line::from(vec![
                Span::styled(
                    " MCP SENTINEL ",
                    Style::default().bg(Color::Cyan).fg(Color::Black).bold(),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("v{}", env!("CARGO_PKG_VERSION")),
                    Style::default().fg(Color::Yellow).bold(),
                ),
                Span::raw("  •  "),
                Span::styled(
                    "Zero-Trust Secret Vault & Subprocess Isolation Proxy",
                    Style::default().fg(Color::White).bold(),
                ),
            ]),
            Line::from(vec![
                Span::styled("OS Credential Enclave", Style::default().fg(Color::Green)),
                Span::raw(" | "),
                Span::styled("HMAC-SHA256 TOFU Policy", Style::default().fg(Color::Cyan)),
                Span::raw(" | "),
                Span::styled("Subprocess Sandbox", Style::default().fg(Color::Yellow)),
                Span::raw(" | "),
                Span::styled("Real-Time Redaction", Style::default().fg(Color::Magenta)),
            ]),
        ]
    };

    let header_block = if is_compact {
        Block::default()
    } else {
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::DarkGray))
    };

    let header_p = Paragraph::new(header_lines)
        .block(header_block)
        .alignment(Alignment::Center);

    f.render_widget(header_p, area);
}

pub fn render_sidebar(f: &mut Frame, app: &mut App, area: Rect) {
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

    let inner_width = (area.width.saturating_sub(2) as usize).max(10);
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

        let shortcut_style = if is_selected {
            Style::default().fg(Color::Cyan).bold()
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let item_line = if area.width < 22 {
            // Compact sidebar without extra shortcut padding for narrow terminals
            Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(*label, style),
            ])
        } else {
            let fixed_len = 2 + label.len() + shortcut.len();
            let pad_len = if inner_width > fixed_len {
                inner_width - fixed_len
            } else {
                1
            };
            let padding = " ".repeat(pad_len);
            Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(*label, style),
                Span::raw(padding),
                Span::styled(*shortcut, shortcut_style),
            ])
        };

        items.push(ListItem::new(item_line));
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

pub fn render_footer(f: &mut Frame, app: &mut App, area: Rect) {
    let (left_pct, right_pct) = if area.width < 90 { (65, 35) } else { (58, 42) };

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(left_pct),
            Constraint::Percentage(right_pct),
        ])
        .split(area);

    let tips = match app.focus {
        FocusArea::Sidebar => {
            "[Up/Down] Menu  [Right/Enter] Enter View  [PgUp/Dn/Wheel] Scroll  [q] Quit"
        }
        FocusArea::Content => match app.current_tab {
            AppTab::Secrets => {
                "[Up/Down] Secret  [Right] Scroll Details  [Enter/v] Reveal  [Left] Menu"
            }
            AppTab::Permissions => {
                "[Up/Down] Select  [Enter/v] Full Details  [d] Revoke  [x] Reset  [Left] Menu"
            }
            AppTab::ToolProfiles => {
                "[Up/Down] Profile  [Right] Scroll Rules  [Enter/v] Full Modal  [Left] Menu"
            }
            AppTab::System => "[Up/Down/PgUp/Dn/Wheel] Scroll Overview  [Left/Esc] Menu  [q] Quit",
        },
        FocusArea::Detail => match app.current_tab {
            AppTab::Secrets => {
                "[Up/Down/Wheel] Scroll Text  [Enter/v] Reveal Modal  [Left/Esc] Back to List"
            }
            AppTab::Permissions => {
                "[Up/Down/Wheel] Scroll Grants  [Enter/v] Full Details  [Left/Esc] Back"
            }
            AppTab::ToolProfiles => {
                "[Up/Down/Wheel] Scroll Rules  [Enter/v] Full Modal  [Left/Esc] Back to List"
            }
            AppTab::System => "[Up/Down/Wheel] Scroll Overview  [Left/Esc] Back to Menu  [q] Quit",
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
