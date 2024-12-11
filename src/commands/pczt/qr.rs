use std::time::Duration;

use anyhow::anyhow;
use gumdrop::Options;
use pczt::Pczt;
use qrcode::{render::unicode, QrCode};
use tokio::io::{stdin, stdout, AsyncReadExt, AsyncWriteExt};

use crate::ShutdownListener;

const ZCASH_PCZT: &str = "zcash-pczt";

// Options accepted for the `pczt to-qr` command
#[derive(Debug, Options)]
pub(crate) struct Send {
    #[options(
        help = "the duration in milliseconds to wait between QR codes (default is 500)",
        default = "500"
    )]
    interval: u64,
}

impl Send {
    pub(crate) async fn run(self, mut shutdown: ShutdownListener) -> Result<(), anyhow::Error> {
        let mut buf = vec![];
        stdin().read_to_end(&mut buf).await?;

        let pczt = Pczt::parse(&buf).map_err(|e| anyhow!("Failed to read PCZT: {:?}", e))?;

        let mut encoder = ur::Encoder::new(&pczt.serialize(), 100, ZCASH_PCZT)
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
            let code = QrCode::new(&ur.to_uppercase())?;
            let string = code
                .render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Dark)
                .light_color(unicode::Dense1x2::Light)
                .quiet_zone(false)
                .build();

            stdout.write_all(format!("{string}\n").as_bytes()).await?;
            stdout.write_all(format!("{ur}\n\n\n\n").as_bytes()).await?;
            stdout.flush().await?;
        }
    }
}
