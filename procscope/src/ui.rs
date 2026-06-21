//! ratatui rendering. `process_row` is pure and tested; the rest drives the terminal.

use crossterm::{
    event::{self, Event as CEvent, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use procscope::format::format_event;
use procscope::model::{category_of, AppState, Category, Process};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph},
};
use std::io::stdout;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Pure: one process list row (pid, name, syscall count). Tested.
pub fn process_row(p: &Process) -> String {
    let name = if p.name.is_empty() { "?" } else { p.name.as_str() };
    let name: String = name.chars().take(14).collect();
    format!("{:>6}  {:<14} {:>6} syscalls", p.pid, name, p.total)
}

fn category_color(c: Category) -> Color {
    match c {
        Category::File => Color::Cyan,
        Category::Network => Color::Green,
        Category::Process => Color::Yellow,
        Category::Other => Color::Gray,
    }
}

pub async fn run(state: Arc<Mutex<AppState>>) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(out))?;
    let mut selected: usize = 0;

    let res = loop {
        term.draw(|f| draw(f, &state, selected))?;

        if event::poll(Duration::from_millis(100))? {
            if let CEvent::Key(k) = event::read()? {
                match k.code {
                    KeyCode::Char('q') | KeyCode::Esc => break Ok(()),
                    KeyCode::Down => selected = selected.saturating_add(1),
                    KeyCode::Up => selected = selected.saturating_sub(1),
                    _ => {}
                }
            }
        }
    };

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    res
}

fn draw(f: &mut Frame, state: &Arc<Mutex<AppState>>, selected: usize) {
    let st = state.lock().unwrap();
    let procs = st.processes_by_activity();
    let sel = selected.min(procs.len().saturating_sub(1));

    let cols = Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(f.area());

    let items: Vec<ListItem> = procs
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let style = if i == sel {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            ListItem::new(process_row(p)).style(style)
        })
        .collect();
    f.render_widget(
        List::new(items).block(Block::default().borders(Borders::ALL).title("Processes")),
        cols[0],
    );

    let (detail, title) = if let Some(p) = procs.get(sel) {
        let lines: Vec<Line> = st
            .recent_for(p.pid)
            .iter()
            .rev()
            .take(60)
            .map(|e| {
                let col = category_color(category_of(e));
                Line::from(Span::styled(format_event(e), Style::default().fg(col)))
            })
            .collect();
        let title = format!(
            "{} [{}]  file:{} net:{} proc:{}  dropped:{}",
            p.name,
            p.pid,
            p.by_category[Category::File as usize],
            p.by_category[Category::Network as usize],
            p.by_category[Category::Process as usize],
            st.dropped(),
        );
        (Text::from(lines), title)
    } else {
        (Text::from("no process selected"), "Activity".to_string())
    };
    f.render_widget(
        Paragraph::new(detail).block(Block::default().borders(Borders::ALL).title(title)),
        cols[1],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_row_renders_pid_name_and_total() {
        let row = process_row(&Process {
            pid: 1234,
            name: "curl".to_string(),
            total: 99,
            ..Default::default()
        });
        assert!(row.contains("1234"));
        assert!(row.contains("curl"));
        assert!(row.contains("99"));
    }
}
