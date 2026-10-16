use futures_util::FutureExt;
use ratatui::{
    prelude::*,
    widgets::{Block, Gauge, Paragraph},
};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use super::{ScanProgress, half_block_pixels, tui::logger_event_for_key, tui::logger_widget};
use crate::tui;

type RgbImage = image::ImageBuffer<image::Rgb<u8>, Vec<u8>>;

/// Sends scan state to a running [`App`].
pub(super) struct AppHandle {
    action_tx: mpsc::UnboundedSender<Action>,
}

impl AppHandle {
    /// Shows a new camera frame and the scan progress as of that frame.
    pub(super) fn update(&self, frame: RgbImage, qr_detected: bool, progress: ScanProgress) {
        // A send fails only after the TUI exits, and that already requests shutdown.
        let _ = self.action_tx.send(Action::Update(Box::new(ScanState {
            frame,
            qr_detected,
            progress,
        })));
    }

    /// Closes the TUI and restores the terminal, without requesting shutdown.
    pub(super) fn finish(&self) {
        let _ = self.action_tx.send(Action::Finish);
    }
}

struct ScanState {
    frame: RgbImage,
    qr_detected: bool,
    progress: ScanProgress,
}

/// A full-screen view of a camera QR scan: the camera feed, scan progress, and the log, each in
/// a fixed pane.
pub(super) struct App {
    notify_shutdown: Option<oneshot::Sender<()>>,
    state: Option<ScanState>,
    action_tx: mpsc::UnboundedSender<Action>,
    action_rx: mpsc::UnboundedReceiver<Action>,
    logger_state: tui_logger::TuiWidgetState,
}

impl App {
    pub(super) fn new(notify_shutdown: oneshot::Sender<()>) -> Self {
        let (action_tx, action_rx) = mpsc::unbounded_channel();
        Self {
            notify_shutdown: Some(notify_shutdown),
            state: None,
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
                        if let Some(notify) = self.notify_shutdown.take() {
                            let _ = notify.send(());
                        }
                        break;
                    }
                    Action::Finish => break,
                    Action::LoggerEvent(event) => self.logger_state.transition(event),
                    Action::Update(state) => self.state = Some(*state),
                    Action::Render => {
                        tui.draw(|f| self.ui(f))?;
                    }
                }
            }
        }

        self.action_rx.close();
        tui.exit()?;

        Ok(())
    }

    fn ui(&self, frame: &mut Frame) {
        let [camera_area, progress_area, log_area] = Layout::vertical([
            Constraint::Min(0),
            Constraint::Length(6),
            Constraint::Length(12),
        ])
        .areas(frame.area());

        let camera_block = Block::bordered().title("Camera (press q to quit)");
        let camera_inner = camera_block.inner(camera_area);
        frame.render_widget(camera_block, camera_area);

        let progress_block = Block::bordered().title("Scan progress");
        let progress_inner = progress_block.inner(progress_area);
        frame.render_widget(progress_block, progress_area);
        let [gauge_area, frames_area, detected_area, status_area] =
            Layout::vertical([Constraint::Length(1); 4]).areas(progress_inner);

        match &self.state {
            Some(state) => {
                render_camera(&state.frame, camera_inner, frame.buffer_mut());
                frame.render_widget(fragments_gauge(&state.progress), gauge_area);
                frame.render_widget(
                    Paragraph::new(format!(
                        "Matching frames read: {}",
                        state.progress.frames_seen
                    )),
                    frames_area,
                );
                frame.render_widget(
                    Paragraph::new(if state.qr_detected {
                        Line::from("QR detected: yes")
                    } else {
                        Line::from(vec![
                            "QR detected: ".into(),
                            "no -- reposition the camera".yellow(),
                        ])
                    }),
                    detected_area,
                );
                frame.render_widget(
                    Paragraph::new(format!("Last event: {}", state.progress.last_status)),
                    status_area,
                );
            }
            None => {
                frame.render_widget(fragments_gauge(&ScanProgress::default()), gauge_area);
                frame.render_widget(Paragraph::new("Waiting for camera"), frames_area);
            }
        }

        frame.render_widget(logger_widget(&self.logger_state), log_area);
    }
}

/// Shows recovered fountain-code fragments as a filled bar.
fn fragments_gauge(progress: &ScanProgress) -> Gauge<'static> {
    let (ratio, label) = match progress.fragments {
        Some((recovered, total)) if total > 0 => (
            recovered as f64 / total as f64,
            format!(
                "fragments recovered: {recovered}/{total} ({}%)",
                recovered * 100 / total
            ),
        ),
        _ => (
            0.0,
            "fragments recovered: waiting for first part".to_string(),
        ),
    };
    Gauge::default()
        .gauge_style(Style::default().fg(Color::Green).bg(Color::DarkGray))
        .ratio(ratio.clamp(0.0, 1.0))
        .label(label)
}

/// Draws `img` as half-block characters, scaled to fit `area` and centered in it. Each
/// character shows two pixels stacked vertically, so the image keeps its aspect ratio in a
/// terminal font about twice as tall as it is wide.
fn render_camera(img: &RgbImage, area: Rect, buf: &mut Buffer) {
    let (w, h) = img.dimensions();
    if w == 0 || h == 0 || area.width == 0 || area.height == 0 {
        return;
    }
    let cols = u32::from(area.width)
        .min(u32::from(area.height) * 2 * w / h)
        .max(1);
    let rows = (cols * h / w / 2).clamp(1, u32::from(area.height));
    let x0 = area.x + (area.width - cols as u16) / 2;
    let y0 = area.y + (area.height - rows as u16) / 2;

    for row in 0..rows {
        for col in 0..cols {
            let (top, bot) = half_block_pixels(img, (col, row), (cols, rows));
            if let Some(cell) = buf.cell_mut((x0 + col as u16, y0 + row as u16)) {
                cell.set_symbol("▀")
                    .set_fg(Color::Rgb(top[0], top[1], top[2]))
                    .set_bg(Color::Rgb(bot[0], bot[1], bot[2]));
            }
        }
    }
}

enum Action {
    Quit,
    Finish,
    LoggerEvent(tui_logger::TuiWidgetEvent),
    Update(Box<ScanState>),
    Render,
}

impl Action {
    fn for_event(event: tui::Event) -> Option<Self> {
        match event {
            tui::Event::Render => Some(Action::Render),
            tui::Event::Key(key) if tui::is_quit_key(&key) => Some(Action::Quit),
            tui::Event::Key(key) => logger_event_for_key(key.code).map(Action::LoggerEvent),
            _ => None,
        }
    }
}
