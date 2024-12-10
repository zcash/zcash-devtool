use std::path::PathBuf;

use anyhow::anyhow;
use gumdrop::Options;
use pczt::{roles::combiner::Combiner, Pczt};
use tokio::{
    fs::File,
    io::{stdout, AsyncReadExt, AsyncWriteExt},
};

// Options accepted for the `pczt combine` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(help = "a list of PCZT files to combine")]
    input: Vec<PathBuf>,
}

impl Command {
    pub(crate) async fn run(self) -> Result<(), anyhow::Error> {
        let mut pczts = vec![];
        for f in self.input {
            let mut f = File::open(f).await?;

            let mut buf = vec![];
            f.read_to_end(&mut buf).await?;

            let pczt = Pczt::parse(&buf).map_err(|e| anyhow!("Failed to read PCZT: {:?}", e))?;

            pczts.push(pczt);
        }

        let pczt = Combiner::new(pczts)
            .combine()
            .map_err(|e| anyhow!("Failed to combine PCZTs: {:?}", e))?;

        stdout().write_all(&pczt.serialize()).await?;

        Ok(())
    }
}
