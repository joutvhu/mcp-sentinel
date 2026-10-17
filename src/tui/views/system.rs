use ratatui::{
    layout::Rect,
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph, Wrap},
    Frame,
};

use crate::tui::app::{App, FocusArea};

pub fn render_system_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let is_detail_focused = app.focus == FocusArea::Detail;
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(if is_detail_focused {
            Color::Cyan
        } else {
            Color::DarkGray
        }))
        .title(Span::styled(
            if is_detail_focused {
                " [ MCP Sentinel — Security & System Architecture — Scroll: Up/Down/Wheel ] "
            } else {
                " MCP Sentinel — Security & System Architecture [Right/Tab to Scroll] "
            },
            if is_detail_focused {
                Style::default().fg(Color::Cyan).bold()
            } else {
                Style::default().fg(Color::White).bold()
            },
        ));

    let lines = vec![
        // Section 1: OS-Native Secret Vault
        Line::from(vec![
            Span::styled(
                "1. OS-Native Secret Vault",
                Style::default().fg(Color::Cyan).bold(),
            ),
            Span::styled(" (Hardware Keyring)", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled(
                "  • Backend Engine:   ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "Windows Credential Manager / Apple Keychain / Linux SecretService",
                Style::default().fg(Color::White).bold(),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  • Disk Exposure:    ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "ZERO Plaintext Secrets on Disk",
                Style::default().fg(Color::Green).bold(),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  • Injection Vector: ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "In-Memory Environment Injection strictly during exec()",
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(""),
        // Section 2: Policy & Cryptographic Integrity
        Line::from(vec![
            Span::styled(
                "2. TOFU Policy & Cryptographic Integrity",
                Style::default().fg(Color::Green).bold(),
            ),
            Span::styled(" (Anti-Tamper)", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled(
                "  • Integrity Guard:  ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "HMAC-SHA256 Cryptographic Signature on permissions.json",
                Style::default().fg(Color::Green).bold(),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  • Master Entropy:   ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "256-bit Hardware-Generated CSPRNG Key stored in Keyring",
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  • Access Control:   ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "DACL (Windows) / 0600 (Unix) — Strict Least Privilege",
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(""),
        // Section 3: Isolation Sandbox & Stream Proxy
        Line::from(vec![
            Span::styled(
                "3. Subprocess Sandbox & Proxy Stream",
                Style::default().fg(Color::Yellow).bold(),
            ),
            Span::styled(" (L7 Guard)", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled(
                "  • Environment Jail: ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "Default-Deny Whitelist (AWS, SSH, GITHUB keys purged from child)",
                Style::default().fg(Color::Green),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  • Anti-Recursion:   ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "MCP_SENTINEL_CHILD_CONTEXT=1 (Child recursion blocked with Exit 13)",
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  • Process Lifecycle:",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "Windows Job Object (KILL_ON_JOB_CLOSE) / Unix Signal Guard",
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(""),
        // Section 4: Audit & Tool Policies
        Line::from(vec![
            Span::styled(
                "4. Audit Logging & Tool Policies",
                Style::default().fg(Color::Magenta).bold(),
            ),
            Span::styled(" (Monitoring)", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled(
                "  • Audit Log File:   ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "~/.mcp-sentinel/audit.log (Opt-in via 'mcp-sentinel audit enable')",
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  • Tool Policies:    ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "~/.mcp-sentinel/tool_policies.json (Whitelist / Blacklist presets)",
                Style::default().fg(Color::White),
            ),
        ]),
    ];

    let p = Paragraph::new(lines)
        .block(block)
        .scroll((app.detail_scroll, 0))
        .wrap(Wrap { trim: true });

    f.render_widget(p, area);
}
