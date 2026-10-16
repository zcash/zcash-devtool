use crossterm::event::KeyCode;
use futures_util::FutureExt;
use ratatui::{
    prelude::*,
    widgets::{Block, Paragraph},
};
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};
use tui_logger::{TuiLoggerLevelOutput, TuiLoggerSmartWidget};

use super::render_qr;
use crate::tui;

pub(super) struct AppHandle {
    action_tx: mpsc::UnboundedSender<Action>,
}

impl AppHandle {
    /// Returns `true` if the TUI exited.
    pub(super) fn set_ur(&self, ur: String) -> bool {
        match self.action_tx.send(Action::SetUr(ur)) {
            Ok(()) => false,
            Err(e) => {
                error!("Failed to send: {}", e);
                true
            }
        }
    }
}

pub(super) struct App {
    should_quit: bool,
    notify_shutdown: Option<oneshot::Sender<()>>,
    ur: Option<String>,
    action_tx: mpsc::UnboundedSender<Action>,
    action_rx: mpsc::UnboundedReceiver<Action>,
    logger_state: tui_logger::TuiWidgetState,
}

impl App {
    pub(super) fn new(notify_shutdown: oneshot::Sender<()>) -> Self {
        let (action_tx, action_rx) = mpsc::unbounded_channel();
        Self {
            should_quit: false,
            notify_shutdown: Some(notify_shutdown),
            ur: None,
            action_tx,
            action_rx,
            logger_state: tui_logger::TuiWidgetState::new(),
        }
    }

    pub(super) fn handle(&self) -> AppHandle {
        AppHandle {
            action_tx: self.action_tx.clone(),
        }
    }

    pub(super) async fn run(&mut self, mut tui: tui::Tui) -> anyhow::Result<()> {
        tui.enter()?;

        loop {
            let action_queue_len = self.action_rx.len();
            if action_queue_len >= 50 {
                warn!("Action queue lagging! Length: {}", action_queue_len);
            }

            let next_event = tui.next().fuse();
            let next_action = self.action_rx.recv().fuse();
            tokio::select! {
                Some(event) = next_event => if let Some(action) = Action::for_event(event) {
                    self.action_tx.send(action)?;
                },
                Some(action) = next_action => match action {
                    Action::Quit => {
                        info!("Quit requested");
                        self.should_quit = true;
                        let _ = self.notify_shutdown.take().expect("should only occur once").send(());
                        break;
                    }
                    Action::Tick => {}
                    Action::LoggerEvent(event) => self.logger_state.transition(event),
                    Action::SetUr(ur) => self.ur = Some(ur),
                    Action::Render => {
                        tui.draw(|f| self.ui(f))?;
                    }
                }
            }

            if self.should_quit {
                break;
            }
        }

        self.action_rx.close();
        tui.exit()?;

        Ok(())
    }

    fn ui(&mut self, frame: &mut Frame) {
        let [upper_area, mid_area, log_area] = Layout::vertical([
            Constraint::Min(0),
            Constraint::Length(3),
            Constraint::Length(15),
        ])
        .areas(frame.area());

        let qr_block = Block::bordered().title("PCZT QR code (press q to quit)");
        let qr_area = qr_block.inner(upper_area);

        if let Some(ur) = &self.ur {
            match render_qr(ur) {
                Ok(qr) => {
                    let width = qr
                        .lines()
                        .map(|line| line.chars().count())
                        .max()
                        .unwrap_or(0);
                    let height = qr.lines().count();
                    let fits = width <= usize::from(qr_area.width)
                        && height <= usize::from(qr_area.height);
                    let qr_block = if fits {
                        qr_block
                    } else {
                        qr_block.title(
                            Line::from(format!(
                                " QR code needs {width}x{height}, has {}x{}: enlarge the terminal or lower --qr-density ",
                                qr_area.width, qr_area.height
                            ))
                            .yellow(),
                        )
                    };
                    frame.render_widget(qr_block, upper_area);
                    frame.render_widget(Paragraph::new(qr), centered(qr_area, width, height));
                }
                Err(e) => {
                    frame.render_widget(qr_block, upper_area);
                    frame.render_widget(
                        Paragraph::new(format!("Failed to draw QR code: {e}")).red(),
                        qr_area,
                    );
                }
            }

            frame.render_widget(
                Paragraph::new(Line::from_iter(Some(ur.as_str())))
                    .block(Block::bordered().title("UR")),
                mid_area,
            );
        } else {
            frame.render_widget(qr_block, upper_area);
        }

        frame.render_widget(logger_widget(&self.logger_state), log_area);
    }
}

#[derive(Clone)]
pub(super) enum Action {
    Quit,
    Tick,
    LoggerEvent(tui_logger::TuiWidgetEvent),
    SetUr(String),
    Render,
}

impl Action {
    fn for_event(event: tui::Event) -> Option<Self> {
        match event {
            tui::Event::Error => None,
            tui::Event::Tick => Some(Action::Tick),
            tui::Event::Render => Some(Action::Render),
            tui::Event::Key(key) if tui::is_quit_key(&key) => Some(Action::Quit),
            tui::Event::Key(key) => logger_event_for_key(key.code).map(Action::LoggerEvent),
            _ => None,
        }
    }
}

/// Maps a key to the log pane event it triggers, if any.
pub(super) fn logger_event_for_key(code: KeyCode) -> Option<tui_logger::TuiWidgetEvent> {
    match code {
        KeyCode::Char(' ') => Some(tui_logger::TuiWidgetEvent::SpaceKey),
        KeyCode::Up => Some(tui_logger::TuiWidgetEvent::UpKey),
        KeyCode::Down => Some(tui_logger::TuiWidgetEvent::DownKey),
        KeyCode::Left => Some(tui_logger::TuiWidgetEvent::LeftKey),
        KeyCode::Right => Some(tui_logger::TuiWidgetEvent::RightKey),
        KeyCode::Char('+') => Some(tui_logger::TuiWidgetEvent::PlusKey),
        KeyCode::Char('-') => Some(tui_logger::TuiWidgetEvent::MinusKey),
        KeyCode::Char('h') => Some(tui_logger::TuiWidgetEvent::HideKey),
        KeyCode::Char('f') => Some(tui_logger::TuiWidgetEvent::FocusKey),
        KeyCode::PageUp => Some(tui_logger::TuiWidgetEvent::PrevPageKey),
        KeyCode::PageDown => Some(tui_logger::TuiWidgetEvent::NextPageKey),
        KeyCode::Esc => Some(tui_logger::TuiWidgetEvent::EscapeKey),
        _ => None,
    }
}

/// Builds the log pane, with entries colored by level.
pub(super) fn logger_widget(state: &tui_logger::TuiWidgetState) -> TuiLoggerSmartWidget<'_> {
    TuiLoggerSmartWidget::default()
        .title_log("Log Entries")
        .title_target("Log Target Selector")
        .style_error(Style::default().fg(Color::Red))
        .style_debug(Style::default().fg(Color::Green))
        .style_warn(Style::default().fg(Color::Yellow))
        .style_trace(Style::default().fg(Color::Magenta))
        .style_info(Style::default().fg(Color::Cyan))
        .output_separator(':')
        .output_timestamp(Some("%H:%M:%S".to_string()))
        .output_level(Some(TuiLoggerLevelOutput::Abbreviated))
        .output_target(true)
        .output_file(true)
        .output_line(true)
        .state(state)
}

/// Returns a `width` by `height` rectangle centered in `area`, clipped to `area`.
fn centered(area: Rect, width: usize, height: usize) -> Rect {
    let width = u16::try_from(width).unwrap_or(u16::MAX).min(area.width);
    let height = u16::try_from(height).unwrap_or(u16::MAX).min(area.height);
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

#[cfg(test)]
mod tests {
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;

    const UR: &str = "ur:zcash-pczt/1-3/lpadaxcfaxhlcyynhgfwtnhdbbadrdrdrdrdrdrdrdrd";

    /// Draws the app with `UR` into a `width` by `height` terminal, and returns the screen rows.
    fn draw(width: u16, height: u16) -> Vec<String> {
        let (notify_shutdown, _) = oneshot::channel();
        let mut app = App::new(notify_shutdown);
        app.ur = Some(UR.to_string());
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| app.ui(frame)).unwrap();
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|y| (0..width).map(|x| buffer[(x, y)].symbol()).collect())
            .collect()
    }

    #[test]
    fn qr_code_is_drawn_whole_and_centered_when_it_fits() {
        let qr = render_qr(UR).unwrap();
        let qr_lines: Vec<&str> = qr.lines().collect();
        let screen = draw(120, 70);

        assert!(screen[0].contains("PCZT QR code"));
        assert!(!screen[0].contains("enlarge the terminal"));
        let top = screen
            .iter()
            .position(|row| row.contains(qr_lines[0]))
            .expect("QR code is on screen");
        for (offset, line) in qr_lines.iter().enumerate() {
            assert!(
                screen[top + offset].contains(line),
                "QR row {offset} missing"
            );
        }
        let row = &screen[top];
        let left = row[..row.find(qr_lines[0]).unwrap()].chars().count();
        let right = row.chars().count() - left - qr_lines[0].chars().count();
        assert!(left.abs_diff(right) <= 1, "left {left}, right {right}");
    }

    #[test]
    fn title_warns_when_qr_code_does_not_fit() {
        // Two of the 30 rows are left for the QR code, after the borders, UR, and log panes.
        let screen = draw(120, 30);
        assert!(screen[0].contains("enlarge the terminal or lower --qr-density"));
    }
}
