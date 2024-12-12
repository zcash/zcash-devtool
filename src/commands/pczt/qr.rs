use std::time::Duration;

use anyhow::anyhow;
use gumdrop::Options;
use minicbor::data::{Int, Type};
use nokhwa::{
    pixel_format::LumaFormat,
    utils::{CameraIndex, RequestedFormat, RequestedFormatType},
    Camera,
};
use pczt::Pczt;
use qrcode::{render::unicode, QrCode};
use tokio::io::{stdin, stdout, AsyncReadExt, AsyncWriteExt};

use crate::ShutdownListener;

const ZCASH_PCZT: &str = "zcash-pczt";
const UR_ZCASH_PCZT: &str = "ur:zcash-pczt";

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

        let mut pczt_packet = vec![];
        minicbor::encode(
            &ZcashPczt {
                data: pczt.serialize(),
            },
            &mut pczt_packet,
        )
        .map_err(|e| anyhow!("Failed to encode PCZT packet: {:?}", e))?;

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
            let code = QrCode::new(&ur.to_ascii_uppercase())?;
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

// Options accepted for the `pczt from-qr` command
#[derive(Debug, Options)]
pub(crate) struct Receive {
    #[options(
        help = "the duration in milliseconds to wait between scanning for QR codes (default is 500)",
        default = "500"
    )]
    interval: u64,
}

impl Receive {
    pub(crate) async fn run(self, mut shutdown: ShutdownListener) -> Result<(), anyhow::Error> {
        let mut camera = Camera::new(
            CameraIndex::Index(0),
            RequestedFormat::new::<LumaFormat>(RequestedFormatType::AbsoluteHighestFrameRate),
        )?;
        let mut decoder = ur::Decoder::default();
        let mut interval = tokio::time::interval(Duration::from_millis(self.interval));

        while !decoder.complete() {
            interval.tick().await;

            if shutdown.requested() {
                return Ok(());
            }

            let frame = camera.frame()?;
            let decoded = frame.decode_image::<LumaFormat>()?;

            let mut detect_grids = |mut img: rqrr::PreparedImage<
                image::ImageBuffer<image::Luma<u8>, Vec<u8>>,
            >|
             -> anyhow::Result<()> {
                let grids = img.detect_grids();
                if let Some(grid) = grids.first() {
                    let (_, content) = grid.decode()?;
                    let content = content.to_ascii_lowercase();
                    if content.starts_with(UR_ZCASH_PCZT) {
                        eprintln!("{content}");
                        decoder
                            .receive(&content)
                            .map_err(|e| anyhow!("Failed to parse QR code: {:?}", e))?;
                    } else {
                        eprintln!("Unexpected UR type: {content}");
                    }
                }
                Ok(())
            };

            if let Err(e) = detect_grids(rqrr::PreparedImage::prepare(decoded)) {
                eprintln!("Error while detecting grids: {e}");
            }
        }

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

        stdout().write_all(&pczt.serialize()).await?;

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
            match key {
                DATA => {
                    obj.data = d.bytes()?.to_vec();
                }
                _ => {}
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
