use std::path::PathBuf;

use anyhow::anyhow;
use clap::Args;
use pczt::{Pczt, roles::combiner::Combiner};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt, stdout},
};

// Options accepted for the `pczt combine` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// A list of PCZT files to combine
    #[arg(short, long)]
    input: Vec<PathBuf>,

    /// Path to a file to which to write the combined PCZT. If not provided, writes to stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
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

        let pczt_bytes = pczt
            .serialize()
            .map_err(|e| anyhow!("Failed to serialize PCZT: {:?}", e))?;
        if let Some(output_path) = &self.output {
            File::create(output_path)
                .await?
                .write_all(&pczt_bytes)
                .await?;
        } else {
            let mut stdout = stdout();
            stdout.write_all(&pczt_bytes).await?;
            stdout.flush().await?;
        }

        Ok(())
    }
}
