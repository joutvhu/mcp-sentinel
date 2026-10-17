use ratatui::{
    layout::Rect,
    style::{Color, Style, Stylize},
    text::{Line, Span},
};

#[derive(Clone, Debug, Default)]
pub struct InputField {
    pub text: String,
    pub cursor: usize,
}

impl InputField {
    pub fn new(initial: String) -> Self {
        let cursor = initial.chars().count();
        Self {
            text: initial,
            cursor,
        }
    }

    pub fn insert(&mut self, c: char) {
        let mut chars: Vec<char> = self.text.chars().collect();
        let idx = self.cursor.min(chars.len());
        chars.insert(idx, c);
        self.cursor = idx + 1;
        self.text = chars.into_iter().collect();
    }

    pub fn backspace(&mut self) {
        let mut chars: Vec<char> = self.text.chars().collect();
        if self.cursor > 0 && !chars.is_empty() {
            let idx = (self.cursor - 1).min(chars.len() - 1);
            chars.remove(idx);
            self.cursor = idx;
            self.text = chars.into_iter().collect();
        }
    }

    pub fn delete(&mut self) {
        let mut chars: Vec<char> = self.text.chars().collect();
        if self.cursor < chars.len() {
            chars.remove(self.cursor);
            self.text = chars.into_iter().collect();
        }
    }

    pub fn move_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    pub fn move_right(&mut self) {
        let len = self.text.chars().count();
        if self.cursor < len {
            self.cursor += 1;
        }
    }

    pub fn move_home(&mut self) {
        self.cursor = 0;
    }

    pub fn move_end(&mut self) {
        self.cursor = self.text.chars().count();
    }

    pub fn to_display_line(&self, is_focused: bool) -> Line<'static> {
        self.to_display_line_with_width(is_focused, 54)
    }

    pub fn to_display_line_with_width(&self, is_focused: bool, max_width: usize) -> Line<'static> {
        let chars: Vec<char> = self.text.chars().collect();
        let total_chars = chars.len();

        if !is_focused {
            if total_chars > max_width {
                let truncated: String = chars[..max_width.saturating_sub(1)].iter().collect();
                return Line::from(Span::raw(format!("{}…", truncated)));
            }
            return Line::from(Span::raw(self.text.clone()));
        }

        let cursor_pos = self.cursor.min(total_chars);

        // If text comfortably fits within max_width, render directly
        if total_chars < max_width {
            if cursor_pos < total_chars {
                let before: String = chars[..cursor_pos].iter().collect();
                let cursor_char: String = chars[cursor_pos].to_string();
                let after: String = chars[cursor_pos + 1..].iter().collect();

                return Line::from(vec![
                    Span::raw(before),
                    Span::styled(
                        cursor_char,
                        Style::default().bg(Color::White).fg(Color::Black).bold(),
                    ),
                    Span::raw(after),
                ]);
            } else {
                return Line::from(vec![
                    Span::raw(self.text.clone()),
                    Span::styled(" ", Style::default().bg(Color::White).fg(Color::Black)),
                ]);
            }
        }

        // Horizontal scrolling window when text length exceeds max_width
        let visible_window_size = max_width.saturating_sub(2).max(10);
        let offset = if cursor_pos < visible_window_size.saturating_sub(4) {
            0
        } else {
            cursor_pos.saturating_sub(visible_window_size.saturating_sub(6))
        };
        let end = (offset + visible_window_size).min(total_chars);
        let rel_cursor = cursor_pos.saturating_sub(offset);

        let mut spans = Vec::new();
        if offset > 0 {
            spans.push(Span::styled("…", Style::default().fg(Color::DarkGray)));
        }

        let slice = &chars[offset..end];
        if rel_cursor < slice.len() {
            let before: String = slice[..rel_cursor].iter().collect();
            let cur_ch: String = slice[rel_cursor].to_string();
            let after: String = slice[rel_cursor + 1..].iter().collect();

            if !before.is_empty() {
                spans.push(Span::raw(before));
            }
            spans.push(Span::styled(
                cur_ch,
                Style::default().bg(Color::White).fg(Color::Black).bold(),
            ));
            if !after.is_empty() {
                spans.push(Span::raw(after));
            }
        } else {
            let slice_str: String = slice.iter().collect();
            if !slice_str.is_empty() {
                spans.push(Span::raw(slice_str));
            }
            spans.push(Span::styled(
                " ",
                Style::default().bg(Color::White).fg(Color::Black),
            ));
        }

        if end < total_chars {
            spans.push(Span::styled("…", Style::default().fg(Color::DarkGray)));
        }

        Line::from(spans)
    }
}

pub fn centered_rect_exact(width: u16, height: u16, r: Rect) -> Rect {
    let margin_x = if r.width > 4 { 2 } else { 0 };
    let margin_y = if r.height > 2 { 1 } else { 0 };

    let actual_width = width.min(r.width.saturating_sub(margin_x * 2));
    let actual_height = height.min(r.height.saturating_sub(margin_y * 2));

    let x = r.x + (r.width.saturating_sub(actual_width)) / 2;
    let y = r.y + (r.height.saturating_sub(actual_height)) / 2;

    Rect {
        x,
        y,
        width: actual_width,
        height: actual_height,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_input_field_insert_and_cursor() {
        let mut field = InputField::new("hello".to_string());
        assert_eq!(field.cursor, 5);

        field.insert('!');
        assert_eq!(field.text, "hello!");
        assert_eq!(field.cursor, 6);

        field.move_left();
        field.move_left();
        assert_eq!(field.cursor, 4);

        field.insert('-');
        assert_eq!(field.text, "hell-o!");
        assert_eq!(field.cursor, 5);
    }

    #[test]
    fn test_input_field_navigation() {
        let mut field = InputField::new("abcde".to_string());
        field.move_home();
        assert_eq!(field.cursor, 0);

        field.move_left(); // boundary check
        assert_eq!(field.cursor, 0);

        field.move_right();
        assert_eq!(field.cursor, 1);

        field.move_end();
        assert_eq!(field.cursor, 5);

        field.move_right(); // boundary check
        assert_eq!(field.cursor, 5);
    }

    #[test]
    fn test_input_field_backspace_and_delete() {
        let mut field = InputField::new("abc".to_string());
        field.backspace();
        assert_eq!(field.text, "ab");
        assert_eq!(field.cursor, 2);

        field.move_home();
        field.delete();
        assert_eq!(field.text, "b");
        assert_eq!(field.cursor, 0);

        field.backspace(); // boundary check
        assert_eq!(field.text, "b");
        assert_eq!(field.cursor, 0);
    }

    #[test]
    fn test_input_field_long_text_scrolling() {
        let long_val = "x".repeat(100);
        let field = InputField::new(long_val);
        let line = field.to_display_line_with_width(true, 40);
        assert!(!line.spans.is_empty());

        let unfocused = field.to_display_line_with_width(false, 40);
        assert!(!unfocused.spans.is_empty());
    }
}
