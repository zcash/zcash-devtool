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
        let sharpness = sharpness(&frame, sharpness_region(frame.dimensions()));
        // A send fails only after the TUI exits, and that already requests shutdown.
        let _ = self.action_tx.send(Action::Update(Box::new(ScanState {
            frame,
            qr_detected,
            sharpness,
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
    sharpness: f64,
    progress: ScanProgress,
}

/// A full-screen view of a camera QR scan: the camera feed, scan progress, and the log, each in
/// a fixed pane.
pub(super) struct App {
    notify_shutdown: Option<oneshot::Sender<()>>,
    state: Option<ScanState>,
    /// The highest sharpness of any frame in this scan.
    peak_sharpness: f64,
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
            peak_sharpness: 0.0,
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
                    Action::Update(state) => {
                        self.peak_sharpness = self.peak_sharpness.max(state.sharpness);
                        self.state = Some(*state);
                    }
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
            Constraint::Length(7),
            Constraint::Length(12),
        ])
        .areas(frame.area());

        let camera_block = Block::bordered().title("Camera (press q to quit)");
        let camera_inner = camera_block.inner(camera_area);
        frame.render_widget(camera_block, camera_area);

        let progress_block = Block::bordered().title("Scan progress");
        let progress_inner = progress_block.inner(progress_area);
        frame.render_widget(progress_block, progress_area);
        let [
            gauge_area,
            sharpness_area,
            frames_area,
            detected_area,
            status_area,
        ] = Layout::vertical([Constraint::Length(1); 5]).areas(progress_inner);

        match &self.state {
            Some(state) => {
                render_camera(&state.frame, camera_inner, frame.buffer_mut());
                frame.render_widget(fragments_gauge(&state.progress), gauge_area);
                frame.render_widget(
                    sharpness_gauge(state.sharpness, self.peak_sharpness),
                    sharpness_area,
                );
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
                frame.render_widget(sharpness_gauge(0.0, 0.0), sharpness_area);
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

/// Shows the frame's sharpness as a bar relative to the sharpest frame so far, so the bar is
/// full when the QR is as sharp as this camera has made it.
fn sharpness_gauge(sharpness: f64, peak: f64) -> Gauge<'static> {
    let ratio = if peak > 0.0 { sharpness / peak } else { 0.0 };
    let color = if ratio >= 0.8 {
        Color::Green
    } else {
        Color::Yellow
    };
    Gauge::default()
        .gauge_style(Style::default().fg(color).bg(Color::DarkGray))
        .ratio(ratio.clamp(0.0, 1.0))
        .label(format!(
            "sharpness in box: {sharpness:.0} (best {peak:.0}) -- move the QR until this peaks"
        ))
}

/// A rectangle of pixels, as `(x, y, width, height)`.
type PixelRegion = (u32, u32, u32, u32);

/// Returns the middle half of a frame with the given dimensions, in each direction. The
/// sharpness meter measures this region only, so that a sharp background does not hide a
/// blurred QR.
fn sharpness_region((w, h): (u32, u32)) -> PixelRegion {
    (w / 4, h / 4, w / 2, h / 2)
}

/// Measures how sharp `region` of `img` is: the variance of the Laplacian of its brightness.
/// Blur removes the fine detail that the Laplacian responds to, so a higher value means a
/// sharper image. The value depends on the scene and the light, so compare it only between
/// frames of the same scene. Returns 0 for a region too small to measure.
fn sharpness(img: &RgbImage, (x0, y0, width, height): PixelRegion) -> f64 {
    let (w, h) = img.dimensions();
    let x_end = (x0 + width).min(w);
    let y_end = (y0 + height).min(h);
    // The Laplacian needs one neighbor on each side.
    let xs = (x0 + 1)..x_end.saturating_sub(1);
    let ys = (y0 + 1)..y_end.saturating_sub(1);
    if xs.is_empty() || ys.is_empty() {
        return 0.0;
    }

    let luma = |x: u32, y: u32| {
        let p = img.get_pixel(x, y);
        (299 * i32::from(p[0]) + 587 * i32::from(p[1]) + 114 * i32::from(p[2])) / 1000
    };

    let (mut count, mut sum, mut sum_sq) = (0.0, 0.0, 0.0);
    for y in ys {
        for x in xs.clone() {
            let laplacian = f64::from(
                4 * luma(x, y) - luma(x - 1, y) - luma(x + 1, y) - luma(x, y - 1) - luma(x, y + 1),
            );
            count += 1.0;
            sum += laplacian;
            sum_sq += laplacian * laplacian;
        }
    }
    let mean = sum / count;
    sum_sq / count - mean * mean
}

/// Draws `img` as half-block characters, scaled to fit `area` and centered in it. Each
/// character shows two pixels stacked vertically, so the image keeps its aspect ratio in a
/// terminal font about twice as tall as it is wide. Outlines the region that the sharpness
/// meter measures.
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

    let (bx, by, bw, bh) = sharpness_region((cols, rows));
    if bw >= 2 && bh >= 2 {
        let box_area = Rect::new(x0 + bx as u16, y0 + by as u16, bw as u16, bh as u16);
        Block::bordered()
            .border_style(Style::default().fg(Color::Yellow))
            .render(box_area, buf);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A checkerboard of `square`-pixel black and white squares.
    fn checkerboard(size: u32, square: u32) -> RgbImage {
        RgbImage::from_fn(size, size, |x, y| {
            if (x / square + y / square).is_multiple_of(2) {
                image::Rgb([0, 0, 0])
            } else {
                image::Rgb([255, 255, 255])
            }
        })
    }

    /// Averages each pixel with its neighbors within `radius`.
    fn box_blur(img: &RgbImage, radius: u32) -> RgbImage {
        let (w, h) = img.dimensions();
        RgbImage::from_fn(w, h, |x, y| {
            let xs = x.saturating_sub(radius)..(x + radius + 1).min(w);
            let ys = y.saturating_sub(radius)..(y + radius + 1).min(h);
            let mut total = [0u32; 3];
            let mut count = 0;
            for yy in ys {
                for xx in xs.clone() {
                    let p = img.get_pixel(xx, yy);
                    for c in 0..3 {
                        total[c] += u32::from(p[c]);
                    }
                    count += 1;
                }
            }
            image::Rgb(total.map(|t| (t / count) as u8))
        })
    }

    #[test]
    fn sharpness_falls_as_blur_rises() {
        let sharp = checkerboard(64, 4);
        let whole = (0, 0, 64, 64);
        let values: Vec<f64> = [0, 1, 2, 4]
            .iter()
            .map(|&radius| sharpness(&box_blur(&sharp, radius), whole))
            .collect();
        assert!(
            values.windows(2).all(|pair| pair[0] > pair[1]),
            "{values:?}"
        );
    }

    #[test]
    fn sharpness_of_uniform_image_is_zero() {
        let gray = RgbImage::from_pixel(32, 32, image::Rgb([128, 128, 128]));
        assert_eq!(sharpness(&gray, (0, 0, 32, 32)), 0.0);
    }

    #[test]
    fn sharpness_measures_only_the_region() {
        // Sharp detail outside the region does not count.
        let mut img = RgbImage::from_pixel(64, 64, image::Rgb([128, 128, 128]));
        for (x, y, p) in checkerboard(64, 2).enumerate_pixels() {
            if x < 16 {
                img.put_pixel(x, y, *p);
            }
        }
        assert_eq!(sharpness(&img, sharpness_region((64, 64))), 0.0);
    }

    #[test]
    fn sharpness_of_tiny_region_is_zero() {
        let img = checkerboard(8, 1);
        assert_eq!(sharpness(&img, (0, 0, 2, 2)), 0.0);
        assert_eq!(sharpness(&RgbImage::new(0, 0), (0, 0, 0, 0)), 0.0);
        // A region that runs past the image edge is clipped to it.
        assert!(sharpness(&img, (4, 4, 100, 100)) > 0.0);
    }
}
