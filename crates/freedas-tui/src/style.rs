use ratatui::style::{Color, Modifier, Style};

fn colors_enabled() -> bool {
    !std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
}

fn colored(color: Color) -> Style {
    if colors_enabled() {
        Style::default().fg(color)
    } else {
        Style::default()
    }
}

pub(crate) fn accent() -> Style {
    colored(Color::Cyan)
}

/// Selected list row: a reversed bar stays visible under `NO_COLOR`.
pub(crate) fn selected() -> Style {
    accent().add_modifier(Modifier::REVERSED)
}

pub(crate) fn muted() -> Style {
    colored(Color::Gray)
}

pub(crate) fn error() -> Style {
    colored(Color::Red)
}

pub(crate) fn success() -> Style {
    colored(Color::Green)
}

pub(crate) fn warning() -> Style {
    colored(Color::Yellow)
}

pub(crate) fn dim() -> Style {
    Style::default().add_modifier(Modifier::DIM)
}

pub(crate) fn bold() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}
