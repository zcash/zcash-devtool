use std::path::{Path, PathBuf};
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
                stdout.write_all(render_qr_frame(&ur)?.as_bytes()).await?;
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

    /// Redact the batch-signer fields (clears spend_auth_sig/output_ock/
    /// output_zip32_derivation/output_user_address from every Orchard and Ironwood action)
    /// before batching. Required for Keystone: a freshly-built PCZT's dummy padding actions
    /// already carry a self-signed spend_auth_sig (correct PCZT behavior -- the wallet is the
    /// only party that ever holds their throwaway keys), and Keystone firmware rejects any
    /// batch member with a pre-existing spend_auth_sig outright, real or dummy. Off by default
    /// since this is a destructive, Keystone-specific transform, not something every batch
    /// consumer wants -- pass it explicitly when Keystone is the target.
    #[arg(long)]
    redact: bool,
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
/// `zcash_pool_migration`'s PCZTs never populate that field (confirmed directly:
/// every action's `zip32_derivation` is `None`, real and dummy alike, while `fvk` is always
/// `Some`), so clearing `fvk` here leaves the device with no way to attribute ANY input to
/// the account -- this was confirmed against real hardware output ("Invalid QR Code / None of
/// inputs belong to the provided account").
///
/// The caller keeps the original, unredacted PCZT (whose dummy `spend_auth_sig`s are still
/// intact) for the post-signing combine -- see `apply_batch_signatures_and_write`, which
/// applies the device's returned real-spend signatures onto the original files, not the
/// redacted copies sent over the wire.
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

/// Applies [`redact_for_batch_signer`] to every PCZT when `redact` is set, otherwise passes
/// them through unchanged. Shared by `to-qr-batch` and `batch-sign`'s outgoing side.
fn maybe_redact_batch(pczts: Vec<Pczt>, redact: bool) -> Vec<Pczt> {
    if redact {
        pczts.into_iter().map(redact_for_batch_signer).collect()
    } else {
        pczts
    }
}

/// Reads and parses every `--pczt` path given, in order. Shared by every command that takes a
/// batch of PCZT files.
fn read_pczts(paths: &[PathBuf]) -> anyhow::Result<Vec<Pczt>> {
    paths
        .iter()
        .map(|path| {
            let bytes = std::fs::read(path)
                .map_err(|e| anyhow!("Failed to read {}: {e}", path.display()))?;
            Pczt::parse(&bytes).map_err(|e| anyhow!("Failed to parse {}: {:?}", path.display(), e))
        })
        .collect()
}

/// Serializes a [`BatchSignRequest`] and wraps it in the `zcash-sign-batch` CBOR envelope
/// (with a fresh random request id, also returned so the caller can verify a later response
/// actually correlates to this request -- see [`decode_batch_sig_result`]), ready to hand to a
/// `ur::Encoder`. Shared by `to-qr-batch` and `batch-sign`'s outgoing side.
fn build_batch_request_packet(pczts: Vec<Pczt>) -> anyhow::Result<(Vec<u8>, [u8; 16])> {
    let data = BatchSignRequest::new(pczts)
        .serialize()
        .map_err(|e| anyhow!("Failed to serialize batch: {:?}", e))?;

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
    Ok((batch_packet, request_id))
}

/// Renders one animated-QR-loop frame: the QR image (as unicode block art) followed by the raw
/// UR text, ready to print. Shared by `to-qr`, `to-qr-batch`, and `batch-sign`'s outgoing side.
fn render_qr_frame(ur: &str) -> anyhow::Result<String> {
    let code = QrCode::new(ur.to_ascii_uppercase())?;
    let string = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .quiet_zone(true)
        .build();
    Ok(format!("{string}\n{ur}\n\n\n\n"))
}

impl SendBatch {
    pub(crate) async fn run(self, mut shutdown: ShutdownListener) -> Result<(), anyhow::Error> {
        let pczts = maybe_redact_batch(read_pczts(&self.pczts)?, self.redact);
        println!("Batching {} PCZT(s)", pczts.len());

        // `to-qr-batch` never scans for a response itself, so it has no use for the request id
        // beyond what's already embedded in the outgoing packet.
        let (batch_packet, _request_id) = build_batch_request_packet(pczts)?;
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
            stdout.write_all(render_qr_frame(&ur)?.as_bytes()).await?;
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
        let mut camera = open_scan_camera(self.camera.as_deref()).await?;

        eprintln!("Starting detection loop");
        let outcome = scan_for_ur(
            &mut camera,
            UR_ZCASH_PCZT,
            self.interval,
            self.no_preview,
            &mut shutdown,
        )
        .await?;
        camera.stop_stream()?;

        let pczt_packet = match outcome {
            ScanOutcome::Complete(bytes) => bytes,
            ScanOutcome::ShutdownRequested => return Ok(()),
        };

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
        let pczts = read_pczts(&self.pczts)?;
        let mut camera = open_scan_camera(self.camera.as_deref()).await?;

        eprintln!("Starting detection loop");
        let outcome = scan_for_ur(
            &mut camera,
            UR_ZCASH_BATCH_SIG_RESULT,
            self.interval,
            self.no_preview,
            &mut shutdown,
        )
        .await?;
        camera.stop_stream()?;

        let result_packet = match outcome {
            ScanOutcome::Complete(bytes) => bytes,
            ScanOutcome::ShutdownRequested => return Ok(()),
        };

        // No expected request id to check against -- `from-qr-batch` is a standalone command
        // that never saw the original `to-qr-batch` invocation's request id.
        let response = decode_batch_sig_result(&result_packet, None)?;
        apply_batch_signatures_and_write(&self.pczts, pczts, &response, self.out_suffix.as_deref())
    }
}

// Options accepted for the `pczt batch-sign` command
#[cfg(feature = "pczt-qr")]
#[derive(Debug, Args)]
pub(crate) struct BatchSign {
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

    /// Redact the outgoing batch before sending. See `to-qr-batch --redact`.
    #[arg(long)]
    redact: bool,

    /// Don't render a live terminal preview of the camera feed once scanning starts.
    #[arg(long)]
    no_preview: bool,

    /// Select the camera whose name contains this text (case-insensitive), e.g. "iphone".
    /// Skips the interactive picker and errors out if no camera name matches.
    #[arg(long)]
    camera: Option<String>,
}

impl BatchSign {
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
        let original_pczts = read_pczts(&self.pczts)?;
        let outgoing_pczts = maybe_redact_batch(original_pczts.clone(), self.redact);
        println!("Sending batch of {} PCZT(s)", outgoing_pczts.len());

        let (batch_packet, request_id) = build_batch_request_packet(outgoing_pczts)?;
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
                    print!("{}", render_qr_frame(&ur)?);
                }
                _ = &mut ready_rx => {
                    break;
                }
            }
        }

        let mut camera = open_scan_camera(self.camera.as_deref()).await?;

        eprintln!("Starting detection loop");
        let outcome = scan_for_ur(
            &mut camera,
            UR_ZCASH_BATCH_SIG_RESULT,
            self.interval,
            self.no_preview,
            &mut shutdown,
        )
        .await?;
        camera.stop_stream()?;

        let result_packet = match outcome {
            ScanOutcome::Complete(bytes) => bytes,
            ScanOutcome::ShutdownRequested => return Ok(()),
        };

        // Same process sent and is now scanning, so it always has the request id to check the
        // response actually correlates to this batch, not a stale/unrelated one.
        let response = decode_batch_sig_result(&result_packet, Some(&request_id))?;
        apply_batch_signatures_and_write(
            &self.pczts,
            original_pczts,
            &response,
            self.out_suffix.as_deref(),
        )
    }
}

/// Decodes a `zcash-batch-sig-result` message into its [`BatchSignResponse`], printing the
/// signing device's firmware version and the response's request id along the way. Shared by
/// `from-qr-batch` and `batch-sign`'s scan phase.
///
/// With `expected_request_id`, verifies the response's id matches the request this batch was
/// actually sent with -- the `pczt` crate's own doc comment on `BatchSignRequest`/
/// `BatchSignResponse` is explicit that "request and response correlation is the responsibility
/// of the application transport," i.e. this tool, not the crate. `batch-sign` sends and scans in
/// the same run, so it always has the id to check. `from-qr-batch` is a standalone command that
/// never saw the original request (that id only ever existed in the sender's process and the
/// QR code itself, not persisted anywhere a separate `from-qr-batch` invocation could read it),
/// so it passes `None` and skips the check -- there's nothing to compare against.
fn decode_batch_sig_result(
    result_packet: &[u8],
    expected_request_id: Option<&[u8]>,
) -> anyhow::Result<BatchSignResponse> {
    let result = minicbor::decode::<'_, ZcashBatchSigResult>(result_packet)
        .map_err(|e| anyhow!("Failed to decode batch sig result packet: {:?}", e))?;

    println!(
        "Batch signing result from firmware {}.{}.{}, request id {}",
        result.firmware_version[0],
        result.firmware_version[1],
        result.firmware_version[2],
        hex::encode(&result.request_id),
    );

    if let Some(expected) = expected_request_id
        && result.request_id != expected
    {
        return Err(anyhow!(
            "Response request id {} does not match the request id {} this batch was sent \
                 with -- this response may belong to a different, unrelated batch request",
            hex::encode(&result.request_id),
            hex::encode(expected),
        ));
    }

    BatchSignResponse::parse(&result.data)
        .map_err(|e| anyhow!("Failed to parse batch sign response: {:?}", e))
}

/// Applies a [`BatchSignResponse`]'s signatures onto the original (unredacted) PCZTs, in the
/// same order as `paths`, and writes each result out -- overwriting in place, or alongside with
/// `out_suffix` appended to the filename. Shared by `from-qr-batch` and `batch-sign`.
///
/// Each signature is applied via [`Signer::apply_orchard_spend_auth_signature`], which --
/// despite its name -- dispatches on the signature's value pool, routing Ironwood signatures
/// to the Ironwood bundle: a future batch carrying real Ironwood spends is already handled
/// here. Every batch this tool produces today only exercises the Orchard arm (a migration
/// batch's real spends are all Orchard, and its Ironwood actions' dummy `spend_auth_sig`s are
/// still intact on the original files -- redaction only ever touched the copies sent over the
/// wire). The crate verifies each signature against its action's randomized verification key
/// (`rk`) before storing it, so a wrong or hostile response errors out with nothing written --
/// which is what makes `from-qr-batch`'s documented opt-out of request-id correlation safe.
fn apply_batch_signatures_and_write(
    paths: &[PathBuf],
    pczts: Vec<Pczt>,
    response: &BatchSignResponse,
    out_suffix: Option<&str>,
) -> anyhow::Result<()> {
    if response.signatures().len() != pczts.len() {
        return Err(anyhow!(
            "Batch sign response has {} PCZT(s) worth of signatures, but {} --pczt file(s) \
             were given -- pass the SAME files, in the SAME order, given when sending the batch",
            response.signatures().len(),
            pczts.len()
        ));
    }

    for ((path, pczt), signatures) in paths.iter().zip(pczts).zip(response.signatures().iter()) {
        let mut signer =
            Signer::new(pczt).map_err(|e| anyhow!("Failed to load {}: {:?}", path.display(), e))?;
        for signature in signatures {
            signer
                .apply_orchard_spend_auth_signature(signature)
                .map_err(|e| anyhow!("Failed to apply signature to {}: {:?}", path.display(), e))?;
        }
        let signed = signer.finish();
        let signed_bytes = signed
            .serialize()
            .map_err(|e| anyhow!("Failed to serialize signed {}: {:?}", path.display(), e))?;

        let out_path = match out_suffix {
            Some(suffix) => PathBuf::from(format!("{}{suffix}", path.display())),
            None => path.clone(),
        };
        // Stage-and-rename rather than writing in place: without a suffix, `out_path` IS the
        // unsigned original, and a crash mid-write would destroy both it and the signed result
        // -- the only output of a signing session that cost a physical device round trip.
        let staged_path = PathBuf::from(format!("{}.tmp", out_path.display()));
        std::fs::write(&staged_path, &signed_bytes)
            .map_err(|e| anyhow!("Failed to write {}: {e}", staged_path.display()))?;
        replace_file(&staged_path, &out_path)
            .map_err(|e| anyhow!("Failed to move signed PCZT to {}: {e}", out_path.display()))?;
        println!("  wrote signed PCZT to {}", out_path.display());
    }

    Ok(())
}

/// Moves `staged` over `dest`, replacing `dest` if it exists. `staged` must be on the same
/// filesystem as `dest` (the callers stage as `<dest>.tmp`, so it always is).
///
/// A plain `std::fs::rename` replaces an existing destination on every supported platform
/// (on Windows, Rust maps it to a replace-if-exists move rather than C `rename` semantics),
/// but on Windows that replacement can still fail where Unix would succeed: the destination
/// being momentarily held open by antivirus/indexing, or carrying the read-only attribute.
/// If the rename fails while `dest` exists, clear `dest` and retry once. The fallback gives
/// up crash-atomicity, but `staged` survives any failure, so the signed PCZT is never lost.
fn replace_file(staged: &Path, dest: &Path) -> std::io::Result<()> {
    match std::fs::rename(staged, dest) {
        Ok(()) => Ok(()),
        Err(_) if dest.exists() => {
            if let Ok(metadata) = dest.metadata() {
                let mut permissions = metadata.permissions();
                if permissions.readonly() {
                    #[allow(clippy::permissions_set_readonly_false)]
                    permissions.set_readonly(false);
                    let _ = std::fs::set_permissions(dest, permissions);
                }
            }
            std::fs::remove_file(dest)?;
            std::fs::rename(staged, dest)
        }
        Err(e) => Err(e),
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
        if let Some(len) = entries
            && len == index
        {
            break;
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
        // `read_u8` reads a single raw byte, not a parsed number -- any non-ASCII-digit byte
        // (including a bare Enter, which sends '\n' = 10) must be rejected before subtracting
        // b'0', since the subtraction would otherwise underflow (panics in debug, wraps to a
        // huge bogus index in release).
        let byte = stdin().read_u8().await?;
        let index = (byte as char)
            .to_digit(10)
            .ok_or_else(|| anyhow!("Invalid camera selection: expected a single digit"))?;
        cameras.get(index as usize).ok_or(anyhow!("Invalid camera"))
    } else {
        cameras.first().ok_or(anyhow!("No camera"))
    }
}

/// Finds, opens, and starts streaming a camera in one call: permissions check, device query and
/// selection (see [`select_camera`]), and stream startup. Shared by every command that scans a
/// QR via the camera.
async fn open_scan_camera(name_filter: Option<&str>) -> anyhow::Result<Camera> {
    nokhwa_initialize(|_| ());
    if !nokhwa_check() {
        return Err(anyhow!("Failed to obtain macOS camera permissions"));
    }

    let cameras = nokhwa::query(nokhwa::utils::ApiBackend::Auto)?;
    let camera = select_camera(&cameras, name_filter).await?;

    eprintln!("Creating camera");
    let mut camera = Camera::new(camera.index().clone(), scan_camera_format())?;

    eprintln!("Opening camera stream");
    camera
        .open_stream()
        .map_err(|e| anyhow!("Could not open camera stream: {e}"))?;

    Ok(camera)
}

/// What [`scan_for_ur`] found once its loop ends: either the fully-reconstructed message, or
/// notice that shutdown was requested mid-scan (the camera is left open; callers should stop it
/// themselves before returning, same as they already do on every other early-return path).
enum ScanOutcome {
    Complete(Vec<u8>),
    ShutdownRequested,
}

/// Reads camera frames on a fixed interval, looking for a multi-part UR whose text starts with
/// `expected_ur_type`, until the full message is reconstructed. Renders the live terminal
/// preview (or, with `no_preview`, nothing but error lines) each tick. Shared by `from-qr`,
/// `from-qr-batch`, and `batch-sign`'s scan phase -- the only thing that differs between them is
/// which UR type they're waiting for and what they do with the bytes once complete.
async fn scan_for_ur(
    camera: &mut Camera,
    expected_ur_type: &str,
    interval_ms: u64,
    no_preview: bool,
    shutdown: &mut ShutdownListener,
) -> anyhow::Result<ScanOutcome> {
    let mut decoder = ur::Decoder::default();
    let mut progress = ScanProgress::default();
    let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));

    while !decoder.complete() {
        interval.tick().await;

        if shutdown.requested() {
            return Ok(ScanOutcome::ShutdownRequested);
        }

        let frame = camera.frame()?;
        let decoded = convert_buffer_to_image(frame)?;

        let detected_result = detect_qr(&decoded);
        let detected = matches!(detected_result, Ok((true, _)));

        match &detected_result {
            Ok((_, Some(content))) if content.starts_with(expected_ur_type) => {
                progress.record(content);
                // A frame of the right UR type can still be rejected by the decoder -- a stale
                // QR from a previous run, the device looping back to an earlier message, or a
                // corrupted read that kept the type prefix intact. That's a property of the one
                // frame, not the scan: record it and keep scanning (same as grid-decode errors
                // below) rather than aborting a possibly hundreds-of-parts session.
                if let Err(e) = decoder.receive(content) {
                    progress.last_status = format!("Rejected QR part: {e:?}");
                    if no_preview {
                        eprintln!("Rejected QR part: {e:?}");
                    }
                }
            }
            Ok((_, Some(content))) => {
                progress.last_status = format!("Unexpected UR type: {content}");
            }
            Ok((_, None)) => {}
            Err(e) => {
                progress.last_status = format!("Error while detecting grids: {e}");
            }
        }

        if no_preview {
            if let Err(e) = &detected_result {
                eprintln!("{e}");
            }
        } else {
            render_preview(&decoded, detected, &progress);
        }
    }

    Ok(ScanOutcome::Complete(
        decoder
            .message()
            .map_err(|e| anyhow!("Failed to extract full message from QR codes: {:?}", e))?
            .expect("complete"),
    ))
}

/// Tries to find and decode a single QR code in a captured camera frame. `Ok((true, Some(_)))`
/// means a grid was found and decoded; `Ok((false, None))` means no grid was found this frame
/// (normal -- most ticks won't have one, e.g. while a device is still on a review screen);
/// `Err` means a grid was found but failed to decode (a corrupted/partial read). Shared by
/// `from-qr`, `from-qr-batch`, and `batch-sign`'s scan phase.
fn detect_qr(
    img: &image::ImageBuffer<image::Rgb<u8>, Vec<u8>>,
) -> anyhow::Result<(bool, Option<String>)> {
    let mut prepared = rqrr::PreparedImage::prepare(img.convert());
    match prepared.detect_grids().first() {
        Some(grid) => {
            let (_, content) = grid.decode()?;
            Ok((true, Some(content.to_ascii_lowercase())))
        }
        None => Ok((false, None)),
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
        "QR detected: {}   |   unique parts seen: {}/{total}   |   matching frames read: {}   |   {}",
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
    // `scan_camera_format` does NOT request MJPEG (see its doc comment for why that was tried
    // and abandoned on macOS), but nokhwa's negotiator may still hand back an MJPEG stream on
    // other backends -- decode it via the JPEG decoder rather than falling through to the
    // raw-YUYV path, which would misread compressed bytes as pixels.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ur_sequence_parses_valid_multi_part_ur() {
        assert_eq!(
            parse_ur_sequence("ur:zcash-sign-batch/1-619/lpadcfaojecfwnnecys"),
            Some((1, 619))
        );
        assert_eq!(
            parse_ur_sequence("ur:zcash-batch-sig-result/42-42/payload"),
            Some((42, 42))
        );
    }

    #[test]
    fn parse_ur_sequence_allows_seq_past_total_for_fountain_tail_parts() {
        // Fountain-code parts beyond the first full pass reuse the seq field for a combined
        // part index, which can legitimately exceed the announced total.
        assert_eq!(
            parse_ur_sequence("ur:zcash-pczt/650-619/data"),
            Some((650, 619))
        );
    }

    #[test]
    fn parse_ur_sequence_rejects_malformed_input() {
        assert_eq!(parse_ur_sequence(""), None);
        assert_eq!(parse_ur_sequence("not-a-ur-at-all"), None);
        assert_eq!(parse_ur_sequence("ur:zcash-pczt"), None); // no sequence segment
        assert_eq!(parse_ur_sequence("ur:zcash-pczt/nope/data"), None); // no '-'
        assert_eq!(parse_ur_sequence("ur:zcash-pczt/one-two/data"), None); // non-numeric
    }

    #[test]
    fn scan_progress_tracks_unique_parts_and_total() {
        let mut progress = ScanProgress::default();
        progress.record("ur:zcash-pczt/1-3/aaa");
        progress.record("ur:zcash-pczt/2-3/bbb");
        progress.record("ur:zcash-pczt/1-3/aaa"); // duplicate frame, e.g. re-scanned

        assert_eq!(progress.total_parts, Some(3));
        assert_eq!(progress.seen_parts.len(), 2);
        assert_eq!(progress.frames_seen, 3); // every recorded frame counts, dup or not
        assert_eq!(progress.last_status, "received part 1/3");
    }

    #[test]
    fn scan_progress_handles_content_with_no_sequence_info() {
        let mut progress = ScanProgress::default();
        progress.record("ur:zcash-pczt");

        assert_eq!(progress.total_parts, None);
        assert!(progress.seen_parts.is_empty());
        assert_eq!(progress.last_status, "received part (no sequence info)");
    }

    /// A scratch directory under the platform temp dir, removed on drop. Unique per test via
    /// the test name (tests run in one process, so pid alone wouldn't disambiguate them).
    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new(test_name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("zcash-devtool-{test_name}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn replace_file_replaces_an_existing_destination() {
        let scratch = ScratchDir::new("replace-existing");
        let staged = scratch.0.join("out.pczt.tmp");
        let dest = scratch.0.join("out.pczt");
        std::fs::write(&staged, b"signed").unwrap();
        std::fs::write(&dest, b"unsigned original").unwrap();

        replace_file(&staged, &dest).unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), b"signed");
        assert!(!staged.exists());
    }

    #[test]
    fn replace_file_replaces_a_read_only_destination() {
        let scratch = ScratchDir::new("replace-read-only");
        let staged = scratch.0.join("out.pczt.tmp");
        let dest = scratch.0.join("out.pczt");
        std::fs::write(&staged, b"signed").unwrap();
        std::fs::write(&dest, b"unsigned original").unwrap();
        let mut permissions = dest.metadata().unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&dest, permissions).unwrap();

        replace_file(&staged, &dest).unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), b"signed");
        assert!(!staged.exists());
    }

    #[test]
    fn replace_file_works_when_destination_does_not_exist() {
        let scratch = ScratchDir::new("replace-fresh");
        let staged = scratch.0.join("out.pczt-signed.tmp");
        let dest = scratch.0.join("out.pczt-signed");
        std::fs::write(&staged, b"signed").unwrap();

        replace_file(&staged, &dest).unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), b"signed");
        assert!(!staged.exists());
    }

    /// Smoke test for `redact_for_batch_signer`: an empty PCZT (no Orchard/Ironwood actions,
    /// via the same `Creator`-only construction the `pczt` crate's own batch-signing tests use)
    /// should redact and round-trip without error. This only exercises the plumbing -- it can't
    /// assert field-level clearing on real actions without a fixture PCZT with actual dummy
    /// spends, which needs the full note-construction pipeline to produce. Field-level
    /// correctness (spend_auth_sig cleared, fvk retained) is verified against real migration
    /// PCZTs and real Keystone hardware output; see keystone-batch-migration-testing-plan.md.
    #[test]
    fn redact_for_batch_signer_round_trips_an_empty_pczt() {
        use pczt::roles::creator::Creator;
        use zcash_protocol::consensus::BranchId;

        let pczt = Creator::new(BranchId::Nu6_3.into(), 3_000_000, 133, None, None)
            .expect("valid consensus branch id")
            .build()
            .expect("empty PCZT builds");

        let redacted = redact_for_batch_signer(pczt);
        redacted.serialize().expect("redacted PCZT serializes");
    }

    #[test]
    fn maybe_redact_batch_is_a_no_op_when_not_requested() {
        use pczt::roles::creator::Creator;
        use zcash_protocol::consensus::BranchId;

        let pczt = Creator::new(BranchId::Nu6_3.into(), 3_000_000, 133, None, None)
            .expect("valid consensus branch id")
            .build()
            .expect("empty PCZT builds");
        let original_bytes = pczt.clone().serialize().expect("serializes");

        let passed_through = maybe_redact_batch(vec![pczt], false);
        assert_eq!(passed_through.len(), 1);
        assert_eq!(
            passed_through[0].clone().serialize().expect("serializes"),
            original_bytes
        );
    }
}
