use std::path::PathBuf;
use std::time::Duration;

use anyhow::anyhow;
use clap::Args;
use image::buffer::ConvertBuffer;
use minicbor::data::{Int, Type};
use nokhwa::{
    Camera, nokhwa_check, nokhwa_initialize,
    pixel_format::RgbFormat,
    utils::{CameraInfo, FrameFormat, RequestedFormat, RequestedFormatType, Resolution},
};
use pczt::Pczt;
use pczt::roles::signer::Signer;
use pczt::roles::signer::batch::{BatchSignRequest, BatchSignResponse};
use qrcode::{QrCode, render::unicode};
use rand::RngCore;
use rand::rngs::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt, Stdout, stdin, stdout};

use crate::ShutdownListener;

#[cfg(feature = "tui")]
use crate::tui::Tui;

#[cfg(feature = "tui")]
mod tui;

const ZCASH_PCZT: &str = "zcash-pczt";
const UR_ZCASH_PCZT: &str = "ur:zcash-pczt";

/// Matches `valargroup/keystone-sdk-rust`'s `ur_registry::zcash::zcash_sign_batch::ZCASH_SIGN_BATCH`
/// registry type (`"zcash-sign-batch"`, CBOR tag 49205) -- the UR type Keystone firmware's batch
/// PCZT signing (`check_zcash_batch_tx_cypherpunk`) already decodes.
const ZCASH_SIGN_BATCH: &str = "zcash-sign-batch";

/// Matches firmware's `ZCASH_BATCH_SIG_RESULT` registry type (`"zcash-batch-sig-result"`) --
/// the UR type produced by `check_zcash_batch_tx_cypherpunk`'s signing response, wrapping the
/// PCZT crate's `pczt::roles::signer::batch::BatchSignResponse` bytes plus the request id and
/// firmware version.
const UR_ZCASH_BATCH_SIG_RESULT: &str = "ur:zcash-batch-sig-result";

// Options accepted for the `pczt to-qr` command
#[cfg(feature = "pczt-qr")]
#[derive(Debug, Args)]
pub(crate) struct Send {
    /// The duration in milliseconds to wait between QR codes (default is 500)
    #[arg(long)]
    #[arg(default_value_t = 500)]
    interval: u64,

    #[cfg(feature = "tui")]
    #[arg(long)]
    pub(crate) tui: bool,
}

impl Send {
    pub(crate) async fn run(
        self,
        mut shutdown: ShutdownListener,
        #[cfg(feature = "tui")] tui: Tui,
    ) -> Result<(), anyhow::Error> {
        let mut buf = vec![];
        stdin().read_to_end(&mut buf).await?;

        let pczt = Pczt::parse(&buf).map_err(|e| anyhow!("Failed to read PCZT: {:?}", e))?;

        let pczt_data = pczt
            .serialize()
            .map_err(|e| anyhow!("Failed to serialize PCZT: {:?}", e))?;
        let mut pczt_packet = vec![];
        minicbor::encode(&ZcashPczt { data: pczt_data }, &mut pczt_packet)
            .map_err(|e| anyhow!("Failed to encode PCZT packet: {:?}", e))?;

        #[cfg(feature = "tui")]
        let tui_handle = if self.tui {
            let mut app = tui::App::new(shutdown.tui_quit_signal());
            let handle = app.handle();
            tokio::spawn(async move {
                if let Err(e) = app.run(tui).await {
                    tracing::error!("Error while running TUI: {e}");
                }
            });
            Some(handle)
        } else {
            None
        };

        let mut encoder = ur::Encoder::new(&pczt_packet, 100, ZCASH_PCZT)
            .map_err(|e| anyhow!("Failed to build UR encoder: {e}"))?;

        let mut stdout = stdout();
        let mut interval = tokio::time::interval(Duration::from_millis(self.interval));
        loop {
            interval.tick().await;

            if shutdown.requested() {
                return Ok(());
            }

            let ur = encoder
                .next_part()
                .map_err(|e| anyhow!("Failed to encode PCZT part: {e}"))?;

            async fn render_cli(stdout: &mut Stdout, ur: String) -> anyhow::Result<()> {
                let code = QrCode::new(ur.to_ascii_uppercase())?;
                let string = code
                    .render::<unicode::Dense1x2>()
                    .dark_color(unicode::Dense1x2::Light)
                    .light_color(unicode::Dense1x2::Dark)
                    .quiet_zone(true)
                    .build();

                stdout.write_all(format!("{string}\n").as_bytes()).await?;
                stdout.write_all(format!("{ur}\n\n\n\n").as_bytes()).await?;
                stdout.flush().await?;

                Ok(())
            }

            #[cfg(feature = "tui")]
            if let Some(handle) = tui_handle.as_ref() {
                if handle.set_ur(ur) {
                    // TUI exited.
                    return Ok(());
                }
            } else {
                render_cli(&mut stdout, ur).await?;
            }

            #[cfg(not(feature = "tui"))]
            render_cli(&mut stdout, ur).await?;
        }
    }
}

// Options accepted for the `pczt to-qr-batch` command
#[cfg(feature = "pczt-qr")]
#[derive(Debug, Args)]
pub(crate) struct SendBatch {
    /// Path to a PCZT file. Repeat, or pass multiple paths (e.g. a shell glob), to include
    /// multiple PCZTs in the batch.
    #[arg(long = "pczt", required = true, num_args = 1..)]
    pczts: Vec<PathBuf>,

    /// The duration in milliseconds to wait between QR codes (default is 500). Ignored with
    /// --out-file.
    #[arg(long)]
    #[arg(default_value_t = 500)]
    interval: u64,

    /// Max bytes per UR fragment (default 100, matching `pczt to-qr`). No physical camera scans
    /// this batch path, so a larger value trades QR error-tolerance for fewer frames -- useful
    /// for a large batch, whose default-100-byte fragment count can run into the thousands.
    #[arg(long)]
    #[arg(default_value_t = 100)]
    max_fragment_len: usize,

    /// Instead of rendering an animated QR loop, write every sequential UR fragment to this
    /// file, one per line, then exit -- the format the Keystone simulator's file-based QR input
    /// (`ui_simulator/assets/qrcode_data.txt`) and `e2e/keystone_helper.py` expect.
    #[arg(long)]
    out_file: Option<PathBuf>,

    /// Skip the batch-signer redaction (clearing spend_auth_sig/output_ock/
    /// output_zip32_derivation/output_user_address from every Orchard and Ironwood action)
    /// normally applied before batching.
    /// A freshly-built PCZT's dummy padding actions already carry a self-signed
    /// spend_auth_sig (correct PCZT behavior -- the wallet is the only party that ever holds
    /// their throwaway keys), and Keystone firmware rejects any batch member with a
    /// pre-existing spend_auth_sig outright, real or dummy. Only pass this to reproduce that
    /// rejection or otherwise inspect the raw, unredacted wire bytes.
    #[arg(long)]
    no_redact: bool,
}

/// Clears every Orchard and Ironwood action's `spend_auth_sig`, output `ock`, output
/// `zip32_derivation`, and output `user_address` -- based on the batch-signer redaction
/// `vizor-wallet` applies (`redact_pczt_for_batch_signer`) before Keystone batch signing, minus
/// its `clear_spend_fvk` step (see below).
///
/// The `spend_auth_sig` clear is the one that matters for correctness: any freshly-built
/// PCZT's dummy padding actions already have this filled in (the wallet self-signs them at
/// construction time, since it's the only party that ever holds a dummy action's throwaway
/// key), and Keystone firmware rejects a batch member carrying ANY pre-existing
/// `spend_auth_sig`, dummy or real, before it ever reaches per-signature verification. The
/// other three clears are wire-savings/privacy trims Vizor applies alongside it that don't
/// affect input-ownership checks (they're all on the output half of each action).
///
/// Deliberately does NOT clear spend `fvk`, unlike Vizor's version. Vizor can skip sending it
/// because the device recovers the spending FVK itself from each spend's `zip32_derivation`;
/// `zcash_pool_migration_backend`'s PCZTs never populate that field (confirmed directly:
/// every action's `zip32_derivation` is `None`, real and dummy alike, while `fvk` is always
/// `Some`), so clearing `fvk` here leaves the device with no way to attribute ANY input to
/// the account -- this was confirmed against real hardware output ("Invalid QR Code / None of
/// inputs belong to the provided account").
///
/// The caller keeps the original, unredacted PCZT (whose dummy `spend_auth_sig`s are still
/// intact) for the post-signing combine -- see `ReceiveBatch::run`, which applies the
/// device's returned real-spend signatures onto the original files, not the redacted copies
/// sent over the wire.
fn redact_for_batch_signer(pczt: Pczt) -> Pczt {
    use pczt::roles::redactor::Redactor;

    fn redact_bundle(r: pczt::roles::redactor::orchard::OrchardRedactor<'_>) {
        let mut r = r;
        r.redact_actions(|mut action| {
            action.clear_spend_auth_sig();
            action.clear_output_ock();
            action.clear_output_zip32_derivation();
            action.clear_output_user_address();
        });
    }

    Redactor::new(pczt)
        .redact_orchard_with(redact_bundle)
        .redact_ironwood_with(redact_bundle)
        .finish()
}

impl SendBatch {
    pub(crate) async fn run(self, mut shutdown: ShutdownListener) -> Result<(), anyhow::Error> {
        let mut pczts = Vec::with_capacity(self.pczts.len());
        for path in &self.pczts {
            let bytes = std::fs::read(path)
                .map_err(|e| anyhow!("Failed to read {}: {e}", path.display()))?;
            let pczt = Pczt::parse(&bytes)
                .map_err(|e| anyhow!("Failed to parse {}: {:?}", path.display(), e))?;
            let pczt = if self.no_redact {
                pczt
            } else {
                redact_for_batch_signer(pczt)
            };
            pczts.push(pczt);
        }
        println!("Batching {} PCZT(s)", pczts.len());

        let data = BatchSignRequest::new(pczts)
            .serialize()
            .map_err(|e| anyhow!("Failed to serialize batch: {:?}", e))?;

        // Correlates this request with the device's `zcash-batch-sig-result` response; this tool
        // doesn't consume the response, so a fresh random id is all that's needed.
        let mut request_id = [0u8; 16];
        OsRng.fill_bytes(&mut request_id);

        let mut batch_packet = vec![];
        minicbor::encode(
            &ZcashSignBatch {
                data,
                request_id: request_id.to_vec(),
            },
            &mut batch_packet,
        )
        .map_err(|e| anyhow!("Failed to encode batch packet: {:?}", e))?;

        let mut encoder = ur::Encoder::new(&batch_packet, self.max_fragment_len, ZCASH_SIGN_BATCH)
            .map_err(|e| anyhow!("Failed to build UR encoder: {e}"))?;

        if let Some(out_file) = &self.out_file {
            let fragment_count = encoder.fragment_count();
            let mut lines = Vec::with_capacity(fragment_count);
            for _ in 0..fragment_count {
                lines.push(
                    encoder
                        .next_part()
                        .map_err(|e| anyhow!("Failed to encode batch part: {e}"))?,
                );
            }
            std::fs::write(out_file, lines.join("\n") + "\n")
                .map_err(|e| anyhow!("Failed to write {}: {e}", out_file.display()))?;
            println!(
                "Wrote {fragment_count} UR fragment(s) to {}",
                out_file.display()
            );
            return Ok(());
        }

        let mut stdout = stdout();
        let mut interval = tokio::time::interval(Duration::from_millis(self.interval));
        loop {
            interval.tick().await;

            if shutdown.requested() {
                return Ok(());
            }

            let ur = encoder
                .next_part()
                .map_err(|e| anyhow!("Failed to encode batch part: {e}"))?;
            let code = QrCode::new(ur.to_ascii_uppercase())?;
            let string = code
                .render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Light)
                .light_color(unicode::Dense1x2::Dark)
                .quiet_zone(true)
                .build();

            stdout.write_all(format!("{string}\n").as_bytes()).await?;
            stdout.write_all(format!("{ur}\n\n\n\n").as_bytes()).await?;
            stdout.flush().await?;
        }
    }
}

// Options accepted for the `pczt from-qr` command
#[cfg(feature = "pczt-qr")]
#[derive(Debug, Args)]
pub(crate) struct Receive {
    /// The duration in milliseconds to wait between scanning for QR codes (default is 500)
    #[arg(long)]
    #[arg(default_value_t = 500)]
    interval: u64,

    /// Don't render a live terminal preview of the camera feed. The preview redraws the
    /// screen every tick using ANSI truecolor blocks, which some terminals/loggers don't
    /// handle well -- pass this to fall back to plain scanning-status lines instead.
    #[arg(long)]
    no_preview: bool,

    /// Select the camera whose name contains this text (case-insensitive), e.g. "iphone" to
    /// always use a Continuity Camera phone instead of the built-in webcam. Skips the
    /// interactive picker and errors out if no camera name matches.
    #[arg(long)]
    camera: Option<String>,
}

impl Receive {
    pub(crate) async fn run(self, mut shutdown: ShutdownListener) -> Result<(), anyhow::Error> {
        nokhwa_initialize(|_| ());
        if !nokhwa_check() {
            return Err(anyhow!("Failed to obtain macOS camera permissions"));
        }

        let cameras = nokhwa::query(nokhwa::utils::ApiBackend::Auto)?;
        let camera = select_camera(&cameras, self.camera.as_deref()).await?;

        eprintln!("Creating camera");
        let mut camera = Camera::new(camera.index().clone(), scan_camera_format())?;

        eprintln!("Opening camera stream");
        camera
            .open_stream()
            .map_err(|e| anyhow!("Could not open camera stream: {e}"))?;

        eprintln!("Starting detection loop");
        let mut decoder = ur::Decoder::default();
        let mut interval = tokio::time::interval(Duration::from_millis(self.interval));
        let mut progress = ScanProgress::default();

        while !decoder.complete() {
            interval.tick().await;

            if shutdown.requested() {
                camera.stop_stream()?;
                return Ok(());
            }

            let frame = camera.frame()?;
            // Doesn't work in nokhwa 0.10: https://github.com/l1npengtul/nokhwa/issues/100
            // let decoded = frame.decode_image::<RgbFormat>()?;
            let decoded = convert_buffer_to_image(frame)?;
            let mut detected = false;

            let mut detect_grids = |mut img: rqrr::PreparedImage<
                image::ImageBuffer<image::Luma<u8>, Vec<u8>>,
            >|
             -> anyhow::Result<()> {
                let grids = img.detect_grids();
                if let Some(grid) = grids.first() {
                    detected = true;
                    let (_, content) = grid.decode()?;
                    let content = content.to_ascii_lowercase();
                    if content.starts_with(UR_ZCASH_PCZT) {
                        progress.record(&content);
                        decoder
                            .receive(&content)
                            .map_err(|e| anyhow!("Failed to parse QR code: {:?}", e))?;
                    } else {
                        progress.last_status = format!("Unexpected UR type: {content}");
                    }
                }
                Ok(())
            };

            let result = detect_grids(rqrr::PreparedImage::prepare(decoded.convert()));
            if let Err(e) = &result {
                progress.last_status = format!("Error while detecting grids: {e}");
            }

            if self.no_preview {
                if let Err(e) = result {
                    eprintln!("{e}");
                }
            } else {
                render_preview(&decoded, detected, &progress);
            }
        }

        camera.stop_stream()?;

        let pczt_packet = decoder
            .message()
            .map_err(|e| anyhow!("Failed to extract full message from QR codes: {:?}", e))?
            .expect("complete");

        let pczt = Pczt::parse(
            &minicbor::decode::<'_, ZcashPczt>(&pczt_packet)
                .map_err(|e| anyhow!("Failed to decode PCZT packet: {:?}", e))?
                .data,
        )
        .map_err(|e| anyhow!("Failed to read PCZT from QR codes: {:?}", e))?;

        let pczt_bytes = pczt
            .serialize()
            .map_err(|e| anyhow!("Failed to serialize PCZT: {:?}", e))?;
        stdout().write_all(&pczt_bytes).await?;

        Ok(())
    }
}

// Options accepted for the `pczt from-qr-batch` command
#[cfg(feature = "pczt-qr")]
#[derive(Debug, Args)]
pub(crate) struct ReceiveBatch {
    /// Path to an unsigned PCZT file that was included in the scanned batch, in the SAME
    /// order they were passed to `to-qr-batch`. Each file is overwritten in place with its
    /// signed PCZT once the batch result is decoded, unless --out-suffix is given.
    #[arg(long = "pczt", required = true, num_args = 1..)]
    pczts: Vec<PathBuf>,

    /// Instead of overwriting each --pczt file in place, write the signed PCZT alongside it
    /// with this suffix appended to the filename (e.g. ".signed" writes "0.pczt.signed").
    #[arg(long)]
    out_suffix: Option<String>,

    /// The duration in milliseconds to wait between scanning for QR codes (default is 500)
    #[arg(long)]
    #[arg(default_value_t = 500)]
    interval: u64,

    /// Don't render a live terminal preview of the camera feed. The preview redraws the
    /// screen every tick using ANSI truecolor blocks, which some terminals/loggers don't
    /// handle well -- pass this to fall back to plain scanning-status lines instead.
    #[arg(long)]
    no_preview: bool,

    /// Select the camera whose name contains this text (case-insensitive), e.g. "iphone" to
    /// always use a Continuity Camera phone instead of the built-in webcam. Skips the
    /// interactive picker and errors out if no camera name matches.
    #[arg(long)]
    camera: Option<String>,
}

impl ReceiveBatch {
    pub(crate) async fn run(self, mut shutdown: ShutdownListener) -> Result<(), anyhow::Error> {
        let mut pczts = Vec::with_capacity(self.pczts.len());
        for path in &self.pczts {
            let bytes = std::fs::read(path)
                .map_err(|e| anyhow!("Failed to read {}: {e}", path.display()))?;
            let pczt = Pczt::parse(&bytes)
                .map_err(|e| anyhow!("Failed to parse {}: {:?}", path.display(), e))?;
            pczts.push(pczt);
        }

        nokhwa_initialize(|_| ());
        if !nokhwa_check() {
            return Err(anyhow!("Failed to obtain macOS camera permissions"));
        }

        let cameras = nokhwa::query(nokhwa::utils::ApiBackend::Auto)?;
        let camera = select_camera(&cameras, self.camera.as_deref()).await?;

        eprintln!("Creating camera");
        let mut camera = Camera::new(camera.index().clone(), scan_camera_format())?;

        eprintln!("Opening camera stream");
        camera
            .open_stream()
            .map_err(|e| anyhow!("Could not open camera stream: {e}"))?;

        eprintln!("Starting detection loop");
        let mut decoder = ur::Decoder::default();
        let mut interval = tokio::time::interval(Duration::from_millis(self.interval));
        let mut progress = ScanProgress::default();

        while !decoder.complete() {
            interval.tick().await;

            if shutdown.requested() {
                camera.stop_stream()?;
                return Ok(());
            }

            let frame = camera.frame()?;
            let decoded = convert_buffer_to_image(frame)?;
            let mut detected = false;

            let mut detect_grids = |mut img: rqrr::PreparedImage<
                image::ImageBuffer<image::Luma<u8>, Vec<u8>>,
            >|
             -> anyhow::Result<()> {
                let grids = img.detect_grids();
                if let Some(grid) = grids.first() {
                    detected = true;
                    let (_, content) = grid.decode()?;
                    let content = content.to_ascii_lowercase();
                    if content.starts_with(UR_ZCASH_BATCH_SIG_RESULT) {
                        progress.record(&content);
                        decoder
                            .receive(&content)
                            .map_err(|e| anyhow!("Failed to parse QR code: {:?}", e))?;
                    } else {
                        progress.last_status = format!("Unexpected UR type: {content}");
                    }
                }
                Ok(())
            };

            let result = detect_grids(rqrr::PreparedImage::prepare(decoded.convert()));
            if let Err(e) = &result {
                progress.last_status = format!("Error while detecting grids: {e}");
            }

            if self.no_preview {
                if let Err(e) = result {
                    eprintln!("{e}");
                }
            } else {
                render_preview(&decoded, detected, &progress);
            }
        }

        camera.stop_stream()?;

        let result_packet = decoder
            .message()
            .map_err(|e| anyhow!("Failed to extract full message from QR codes: {:?}", e))?
            .expect("complete");

        let result = minicbor::decode::<'_, ZcashBatchSigResult>(&result_packet)
            .map_err(|e| anyhow!("Failed to decode batch sig result packet: {:?}", e))?;

        println!(
            "Batch signing result from firmware {}.{}.{}, request id {}",
            result.firmware_version[0],
            result.firmware_version[1],
            result.firmware_version[2],
            hex::encode(&result.request_id),
        );

        let response = BatchSignResponse::parse(&result.data)
            .map_err(|e| anyhow!("Failed to parse batch sign response: {:?}", e))?;

        if response.signatures().len() != pczts.len() {
            return Err(anyhow!(
                "Batch sign response has {} PCZT('s) worth of signatures, but {} --pczt file(s) \
                 were given -- pass the SAME files, in the SAME order, given to `to-qr-batch`",
                response.signatures().len(),
                pczts.len()
            ));
        }

        for ((path, pczt), signatures) in self
            .pczts
            .iter()
            .zip(pczts)
            .zip(response.signatures().iter())
        {
            let mut signer = Signer::new(pczt)
                .map_err(|e| anyhow!("Failed to load {}: {:?}", path.display(), e))?;
            for signature in signatures {
                signer
                    .apply_orchard_spend_auth_signature(signature)
                    .map_err(|e| {
                        anyhow!("Failed to apply signature to {}: {:?}", path.display(), e)
                    })?;
            }
            let signed = signer.finish();
            let signed_bytes = signed
                .serialize()
                .map_err(|e| anyhow!("Failed to serialize signed {}: {:?}", path.display(), e))?;

            let out_path = match &self.out_suffix {
                Some(suffix) => PathBuf::from(format!("{}{suffix}", path.display())),
                None => path.clone(),
            };
            std::fs::write(&out_path, &signed_bytes)
                .map_err(|e| anyhow!("Failed to write {}: {e}", out_path.display()))?;
            println!("  wrote signed PCZT to {}", out_path.display());
        }

        Ok(())
    }
}

// Options accepted for the `pczt qr-batch` command
#[cfg(feature = "pczt-qr")]
#[derive(Debug, Args)]
pub(crate) struct RoundTripBatch {
    /// Path to an unsigned PCZT file to include in the batch. Repeat, or pass multiple paths
    /// (e.g. a shell glob), to include multiple PCZTs. Each file is overwritten with its signed
    /// PCZT once the device's response is decoded, unless --out-suffix is given.
    #[arg(long = "pczt", required = true, num_args = 1..)]
    pczts: Vec<PathBuf>,

    /// Instead of overwriting each --pczt file in place, write the signed PCZT alongside it
    /// with this suffix appended to the filename (e.g. ".signed" writes "0.pczt.signed").
    #[arg(long)]
    out_suffix: Option<String>,

    /// The duration in milliseconds between animated-QR frames and camera scans (default 500)
    #[arg(long)]
    #[arg(default_value_t = 500)]
    interval: u64,

    /// Max bytes per outgoing UR fragment (default 100, matching `to-qr-batch`)
    #[arg(long)]
    #[arg(default_value_t = 100)]
    max_fragment_len: usize,

    /// Skip the batch-signer redaction on the outgoing batch. See `to-qr-batch --no-redact`.
    #[arg(long)]
    no_redact: bool,

    /// Don't render a live terminal preview of the camera feed once scanning starts.
    #[arg(long)]
    no_preview: bool,

    /// Select the camera whose name contains this text (case-insensitive), e.g. "iphone".
    /// Skips the interactive picker and errors out if no camera name matches.
    #[arg(long)]
    camera: Option<String>,
}

impl RoundTripBatch {
    /// Shows the outgoing batch QR loop first, with no camera opened at all, then -- once you
    /// press Enter -- opens the camera and switches straight into scanning for the signed
    /// response. One command for the whole round trip instead of `to-qr-batch` stopped by hand
    /// and `from-qr-batch` started separately, but without opening the camera before you're
    /// actually ready to point it at the device.
    ///
    /// There's no way to auto-detect "the device is done scanning the outgoing QR" without the
    /// camera already open and pointed at the device -- and during that phase the physical
    /// setup is the other way around anyway (the *device's* camera is pointed at *this* screen,
    /// not the other way round), so opening ours from the start doesn't reflect reality and
    /// needlessly holds the camera the whole time you're still just showing the outgoing loop.
    /// Enter is the deliberate handoff instead of a guess.
    pub(crate) async fn run(self, mut shutdown: ShutdownListener) -> Result<(), anyhow::Error> {
        let mut original_pczts = Vec::with_capacity(self.pczts.len());
        for path in &self.pczts {
            let bytes = std::fs::read(path)
                .map_err(|e| anyhow!("Failed to read {}: {e}", path.display()))?;
            let pczt = Pczt::parse(&bytes)
                .map_err(|e| anyhow!("Failed to parse {}: {:?}", path.display(), e))?;
            original_pczts.push(pczt);
        }

        let outgoing_pczts: Vec<Pczt> = original_pczts
            .iter()
            .cloned()
            .map(|pczt| {
                if self.no_redact {
                    pczt
                } else {
                    redact_for_batch_signer(pczt)
                }
            })
            .collect();
        println!("Sending batch of {} PCZT(s)", outgoing_pczts.len());

        let request_data = BatchSignRequest::new(outgoing_pczts)
            .serialize()
            .map_err(|e| anyhow!("Failed to serialize batch: {:?}", e))?;
        let mut request_id = [0u8; 16];
        OsRng.fill_bytes(&mut request_id);
        let mut batch_packet = vec![];
        minicbor::encode(
            &ZcashSignBatch {
                data: request_data,
                request_id: request_id.to_vec(),
            },
            &mut batch_packet,
        )
        .map_err(|e| anyhow!("Failed to encode batch packet: {:?}", e))?;
        let mut send_encoder =
            ur::Encoder::new(&batch_packet, self.max_fragment_len, ZCASH_SIGN_BATCH)
                .map_err(|e| anyhow!("Failed to build UR encoder: {e}"))?;

        eprintln!(
            "Showing the outgoing batch QR -- scan it on the device, then review and sign as \
             usual. When you're ready to point the camera at the device to catch its signed \
             response, press Enter here."
        );

        let (ready_tx, mut ready_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let mut line = String::new();
            let mut reader = tokio::io::BufReader::new(stdin());
            let _ = tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line).await;
            let _ = ready_tx.send(());
        });

        let mut send_interval = tokio::time::interval(Duration::from_millis(self.interval));
        loop {
            tokio::select! {
                _ = send_interval.tick() => {
                    if shutdown.requested() {
                        return Ok(());
                    }
                    let ur = send_encoder
                        .next_part()
                        .map_err(|e| anyhow!("Failed to encode batch part: {e}"))?;
                    let code = QrCode::new(ur.to_ascii_uppercase())?;
                    let string = code
                        .render::<unicode::Dense1x2>()
                        .dark_color(unicode::Dense1x2::Light)
                        .light_color(unicode::Dense1x2::Dark)
                        .quiet_zone(true)
                        .build();
                    print!("{string}\n{ur}\n\n\n\n");
                }
                _ = &mut ready_rx => {
                    break;
                }
            }
        }

        nokhwa_initialize(|_| ());
        if !nokhwa_check() {
            return Err(anyhow!("Failed to obtain macOS camera permissions"));
        }
        let cameras = nokhwa::query(nokhwa::utils::ApiBackend::Auto)?;
        let camera = select_camera(&cameras, self.camera.as_deref()).await?;

        eprintln!("Creating camera");
        let mut camera = Camera::new(camera.index().clone(), scan_camera_format())?;

        eprintln!("Opening camera stream");
        camera
            .open_stream()
            .map_err(|e| anyhow!("Could not open camera stream: {e}"))?;

        eprintln!("Starting detection loop");
        let mut decoder = ur::Decoder::default();
        let mut progress = ScanProgress::default();
        let mut interval = tokio::time::interval(Duration::from_millis(self.interval));

        while !decoder.complete() {
            interval.tick().await;

            if shutdown.requested() {
                camera.stop_stream()?;
                return Ok(());
            }

            let frame = camera.frame()?;
            let decoded = convert_buffer_to_image(frame)?;
            let mut detected = false;

            let mut detect_grids = |mut img: rqrr::PreparedImage<
                image::ImageBuffer<image::Luma<u8>, Vec<u8>>,
            >|
             -> anyhow::Result<()> {
                let grids = img.detect_grids();
                if let Some(grid) = grids.first() {
                    detected = true;
                    let (_, content) = grid.decode()?;
                    let content = content.to_ascii_lowercase();
                    if content.starts_with(UR_ZCASH_BATCH_SIG_RESULT) {
                        progress.record(&content);
                        decoder
                            .receive(&content)
                            .map_err(|e| anyhow!("Failed to parse QR code: {:?}", e))?;
                    } else {
                        progress.last_status = format!("Unexpected UR type: {content}");
                    }
                }
                Ok(())
            };

            let result = detect_grids(rqrr::PreparedImage::prepare(decoded.convert()));
            if let Err(e) = &result {
                progress.last_status = format!("Error while detecting grids: {e}");
            }

            if self.no_preview {
                if let Err(e) = result {
                    eprintln!("{e}");
                }
            } else {
                render_preview(&decoded, detected, &progress);
            }
        }

        camera.stop_stream()?;

        let result_packet = decoder
            .message()
            .map_err(|e| anyhow!("Failed to extract full message from QR codes: {:?}", e))?
            .expect("complete");

        let result = minicbor::decode::<'_, ZcashBatchSigResult>(&result_packet)
            .map_err(|e| anyhow!("Failed to decode batch sig result packet: {:?}", e))?;

        println!(
            "Batch signing result from firmware {}.{}.{}, request id {}",
            result.firmware_version[0],
            result.firmware_version[1],
            result.firmware_version[2],
            hex::encode(&result.request_id),
        );

        let response = BatchSignResponse::parse(&result.data)
            .map_err(|e| anyhow!("Failed to parse batch sign response: {:?}", e))?;

        if response.signatures().len() != original_pczts.len() {
            return Err(anyhow!(
                "Batch sign response has {} PCZT('s) worth of signatures, but {} --pczt file(s) \
                 were given",
                response.signatures().len(),
                original_pczts.len()
            ));
        }

        for ((path, pczt), signatures) in self
            .pczts
            .iter()
            .zip(original_pczts)
            .zip(response.signatures().iter())
        {
            let mut signer = Signer::new(pczt)
                .map_err(|e| anyhow!("Failed to load {}: {:?}", path.display(), e))?;
            for signature in signatures {
                signer
                    .apply_orchard_spend_auth_signature(signature)
                    .map_err(|e| {
                        anyhow!("Failed to apply signature to {}: {:?}", path.display(), e)
                    })?;
            }
            let signed = signer.finish();
            let signed_bytes = signed
                .serialize()
                .map_err(|e| anyhow!("Failed to serialize signed {}: {:?}", path.display(), e))?;

            let out_path = match &self.out_suffix {
                Some(suffix) => PathBuf::from(format!("{}{suffix}", path.display())),
                None => path.clone(),
            };
            std::fs::write(&out_path, &signed_bytes)
                .map_err(|e| anyhow!("Failed to write {}: {e}", out_path.display()))?;
            println!("  wrote signed PCZT to {}", out_path.display());
        }

        Ok(())
    }
}

const DATA: u8 = 1;

struct ZcashPczt {
    data: Vec<u8>,
}

impl<C> minicbor::Encode<C> for ZcashPczt {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(1)?;

        e.int(Int::from(DATA))?.bytes(&self.data)?;

        Ok(())
    }
}

impl<'b, C> minicbor::Decode<'b, C> for ZcashPczt {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let mut result = ZcashPczt { data: vec![] };
        cbor_map(d, &mut result, |key, obj, d| {
            let key =
                u8::try_from(key).map_err(|e| minicbor::decode::Error::message(e.to_string()))?;
            if key == DATA {
                obj.data = d.bytes()?.to_vec();
            }
            Ok(())
        })?;
        Ok(result)
    }
}

const BATCH_REQUEST_ID: u8 = 2;

/// Mirrors `ur_registry::zcash::zcash_sign_batch::ZcashSignBatch`'s CBOR shape exactly (map keys
/// `1` = data, `2` = request id) rather than depending on the `ur-registry` crate, matching this
/// file's existing `ZcashPczt`/`keystone.rs`'s `ZcashAccounts` pattern of small local structs for
/// each UR type devtool produces.
struct ZcashSignBatch {
    /// The serialized `pczt::roles::signer::batch::BatchSignRequest` -- an opaque, versioned
    /// payload the PCZT crate owns; this wrapper only adds the UR envelope and request id.
    data: Vec<u8>,
    request_id: Vec<u8>,
}

impl<C> minicbor::Encode<C> for ZcashSignBatch {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(2)?;
        e.int(Int::from(DATA))?.bytes(&self.data)?;
        e.int(Int::from(BATCH_REQUEST_ID))?
            .bytes(&self.request_id)?;
        Ok(())
    }
}

const FIRMWARE_VERSION: u8 = 3;

/// Mirrors `ur_registry::zcash::zcash_batch_sig_result::ZcashBatchSigResult`'s CBOR shape
/// exactly (map keys `1` = data, `2` = request id, `3` = 3-byte firmware version) -- the
/// response counterpart to [`ZcashSignBatch`], decode-only since devtool only ever receives
/// this UR type, never produces it.
struct ZcashBatchSigResult {
    /// The serialized `pczt::roles::signer::batch::BatchSignResponse`.
    data: Vec<u8>,
    request_id: Vec<u8>,
    firmware_version: [u8; 3],
}

impl<'b, C> minicbor::Decode<'b, C> for ZcashBatchSigResult {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let mut result = ZcashBatchSigResult {
            data: vec![],
            request_id: vec![],
            firmware_version: [0; 3],
        };
        cbor_map(d, &mut result, |key, obj, d| {
            let key =
                u8::try_from(key).map_err(|e| minicbor::decode::Error::message(e.to_string()))?;
            if key == DATA {
                obj.data = d.bytes()?.to_vec();
            } else if key == BATCH_REQUEST_ID {
                obj.request_id = d.bytes()?.to_vec();
            } else if key == FIRMWARE_VERSION {
                let bytes = d.bytes()?;
                obj.firmware_version = bytes.try_into().map_err(|_| {
                    minicbor::decode::Error::message(format!(
                        "expected a 3-byte firmware version, got {} bytes",
                        bytes.len()
                    ))
                })?;
            }
            Ok(())
        })?;
        Ok(result)
    }
}

fn cbor_map<'b, F, T>(
    d: &mut minicbor::Decoder<'b>,
    obj: &mut T,
    mut cb: F,
) -> Result<(), minicbor::decode::Error>
where
    F: FnMut(Int, &mut T, &mut minicbor::Decoder<'b>) -> Result<(), minicbor::decode::Error>,
{
    let entries = d.map()?;
    let mut index = 0;
    loop {
        let key = d.int()?;
        (cb)(key, obj, d)?;
        index += 1;
        if let Some(len) = entries {
            if len == index {
                break;
            }
        }
        if let Type::Break = d.datatype()? {
            d.skip()?;
            break;
        }
    }
    Ok(())
}

/// Requesting `FrameFormat::MJPEG` explicitly (to decode via `image::load_from_memory`'s JPEG
/// decoder instead of hand-rolling raw pixel conversion) was tried and abandoned: nokhwa's
/// `Closest`/`Exact` matchers on this macOS backend refuse to fulfill an MJPEG request at all
/// (`Cannot fulfill request`, tried both an oversized 10000x10000 target and a realistic
/// 1920x1080 one), and `compatible_camera_formats()` returns empty before the stream opens, so
/// there's no reliable way to discover what the negotiator would actually accept. Left on
/// `AbsoluteHighestResolution` and fixed the real bug at the source instead -- see
/// `convert_buffer_to_image`'s YUYV byte-order comment.
fn scan_camera_format() -> RequestedFormat<'static> {
    RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestResolution)
}

/// Picks which camera to scan from. With `name_filter`, matches case-insensitively against
/// each camera's `human_name()` (e.g. "iphone" to always pick up a Continuity Camera phone
/// instead of the built-in webcam) and errors out if nothing matches, skipping the interactive
/// picker entirely -- useful since re-selecting a numbered camera by hand every run is exactly
/// the kind of friction that makes people reach for a phone as the steadier/better-positioned
/// camera in the first place. Without a filter, falls back to the previous behavior: the sole
/// camera if there's only one, otherwise an interactive numbered prompt.
async fn select_camera<'a>(
    cameras: &'a [CameraInfo],
    name_filter: Option<&str>,
) -> anyhow::Result<&'a CameraInfo> {
    if let Some(filter) = name_filter {
        let filter = filter.to_ascii_lowercase();
        return cameras
            .iter()
            .find(|camera| camera.human_name().to_ascii_lowercase().contains(&filter))
            .ok_or_else(|| {
                anyhow!(
                    "No camera name contains '{filter}'. Available cameras: {}",
                    cameras
                        .iter()
                        .map(|c| c.human_name())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            });
    }

    if cameras.len() > 1 {
        eprintln!("Available cameras:");
        for (i, camera) in cameras.iter().enumerate() {
            eprintln!("{}: {}", i, camera.human_name());
        }
        eprint!("Select a camera: ");
        cameras
            .get(usize::from(stdin().read_u8().await?) - 48)
            .ok_or(anyhow!("Invalid camera"))
    } else {
        cameras.first().ok_or(anyhow!("No camera"))
    }
}

/// Tracks how a QR scan is progressing across ticks, for live terminal feedback: how many
/// distinct fountain-code parts have been seen versus the total the sender announced (parsed
/// straight out of each frame's own `ur:<type>/<seq>-<total>/...` text, since neither `ur::Decoder`
/// nor `ur::fountain::Decoder` expose a public progress/received-count accessor), plus the most
/// recent scan-loop status line.
#[derive(Default)]
struct ScanProgress {
    seen_parts: std::collections::BTreeSet<usize>,
    total_parts: Option<usize>,
    frames_seen: usize,
    last_status: String,
}

impl ScanProgress {
    /// Records a successfully-decoded QR frame's raw UR text.
    fn record(&mut self, content: &str) {
        self.frames_seen += 1;
        match parse_ur_sequence(content) {
            Some((seq, total)) => {
                self.total_parts = Some(total);
                self.seen_parts.insert(seq);
                self.last_status = format!("received part {seq}/{total}");
            }
            None => self.last_status = "received part (no sequence info)".to_string(),
        }
    }
}

/// Extracts `(seq, total)` from a multi-part UR's `ur:<type>/<seq>-<total>/<payload>` text.
/// Fountain-code parts beyond the first full pass reuse this same field to announce a
/// (possibly combined) part index, so `seq` can exceed `total` -- that's normal, not an error.
fn parse_ur_sequence(content: &str) -> Option<(usize, usize)> {
    let mut segments = content.splitn(3, '/');
    segments.next()?; // "ur:<type>"
    let (seq, total) = segments.next()?.split_once('-')?;
    Some((seq.parse().ok()?, total.parse().ok()?))
}

/// Renders a live terminal preview of the camera feed while scanning: the current frame as
/// ANSI truecolor half-block characters (two vertical pixels per character row, so the aspect
/// ratio roughly matches a normal terminal font), followed by a status line covering QR
/// detection, unique-part progress, and the last scan event. Redraws in place (clear + home)
/// each call so it reads as a live video rather than scrolling text.
fn render_preview(
    img: &image::ImageBuffer<image::Rgb<u8>, Vec<u8>>,
    qr_detected: bool,
    progress: &ScanProgress,
) {
    use std::fmt::Write as _;

    const COLS: u32 = 100;
    let (w, h) = img.dimensions();
    if w == 0 || h == 0 {
        return;
    }
    let rows = (COLS * h / w / 2).max(1);

    let mut out = String::with_capacity((COLS * rows * 24) as usize);
    out.push_str("\x1B[2J\x1B[H");
    for row in 0..rows {
        for col in 0..COLS {
            let x = (col * w / COLS).min(w - 1);
            let y_top = ((row * 2) * h / (rows * 2)).min(h - 1);
            let y_bot = ((row * 2 + 1) * h / (rows * 2)).min(h - 1);
            let top = img.get_pixel(x, y_top);
            let bot = img.get_pixel(x, y_bot);
            let _ = write!(
                out,
                "\x1b[38;2;{};{};{}m\x1b[48;2;{};{};{}m▀",
                top[0], top[1], top[2], bot[0], bot[1], bot[2]
            );
        }
        out.push_str("\x1b[0m\n");
    }

    let total = progress
        .total_parts
        .map_or_else(|| "?".to_string(), |t| t.to_string());
    let _ = writeln!(
        out,
        "QR detected: {}   |   unique parts seen: {}/{total}   |   frames read: {}   |   {}",
        if qr_detected {
            "yes"
        } else {
            "no -- reposition the camera"
        },
        progress.seen_parts.len(),
        progress.frames_seen,
        progress.last_status,
    );

    eprint!("{out}");
}

fn convert_buffer_to_image(
    buffer: nokhwa::Buffer,
) -> anyhow::Result<image::ImageBuffer<image::Rgb<u8>, Vec<u8>>> {
    // `scan_camera_format` requests MJPEG, so this is the expected path -- see its doc comment
    // for why the raw-YUYV path below is unreliable on macOS and MJPEG isn't.
    if buffer.source_frame_format() == FrameFormat::MJPEG {
        return Ok(image::load_from_memory(buffer.buffer())?.to_rgb8());
    }

    let Resolution {
        width_x: width,
        height_y: height,
    } = buffer.resolution();
    let mut image_buffer = image::ImageBuffer::<image::Rgb<u8>, Vec<u8>>::new(width, height);
    let data = buffer.buffer();

    for (y, chunk) in data
        .chunks_exact((width * 2) as usize)
        .enumerate()
        .take(height as usize)
    {
        for (x, pixel) in chunk.chunks_exact(4).enumerate() {
            // `FrameFormat::YUYV` is packed 4:2:2 in Y0 U Y1 V byte order (the fourcc's own
            // name), not U Y0 V Y1 (UYVY) -- confirmed against a real capture, where reading
            // this as UYVY pinned red and blue to 0 in every frame.
            let [y1, u, y2, v] = [
                pixel[0] as f32,
                pixel[1] as f32,
                pixel[2] as f32,
                pixel[3] as f32,
            ];
            let x = (x * 2) as u32;
            image_buffer.put_pixel(x, y as u32, yuv_to_rgb(y1, u, v));
            image_buffer.put_pixel(x + 1, y as u32, yuv_to_rgb(y2, u, v));
        }
    }

    Ok(image_buffer)
}

//YUV to RGB conversion BT.709
fn yuv_to_rgb(y: f32, u: f32, v: f32) -> image::Rgb<u8> {
    let r = y + 1.5748 * (v - 128.0);
    let g = y - 0.1873 * (u - 128.0) - 0.4681 * (v - 128.0);
    let b = y + 1.8556 * (u - 128.0);

    image::Rgb([r as u8, g as u8, b as u8])
}
