use anyhow::anyhow;
use clap::Args;
use pczt::{
    Pczt,
    roles::{spend_finalizer::SpendFinalizer, tx_extractor::TransactionExtractor},
};
use tokio::io::{AsyncReadExt, stdin};
use zcash_client_backend::proto::service;
use zcash_proofs::prover::LocalTxProver;

use crate::{config::WalletConfig, error, remote::ConnectionArgs};

// Options accepted for the `pczt send-without-storing` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    #[command(flatten)]
    connection: ConnectionArgs,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();

        let mut client = self.connection.connect(params, wallet_dir.as_ref()).await?;

        let mut buf = vec![];
        stdin().read_to_end(&mut buf).await?;

        let pczt = Pczt::parse(&buf).map_err(|e| anyhow!("Failed to read PCZT: {:?}", e))?;

        let prover = LocalTxProver::bundled();
        let (spend_vk, output_vk) = prover.verifying_keys();

        let finalized = SpendFinalizer::new(pczt)
            .finalize_spends()
            .map_err(|e| anyhow!("Failed to finalize PCZT spends: {e:?}"))?;

        let tx = TransactionExtractor::new(finalized)
            .with_sapling(&spend_vk, &output_vk)
            .extract()
            .map_err(|e| anyhow!("Failed to extract transaction from PCZT: {e:?}"))?;
        let txid = tx.txid();

        // Send the transaction.
        println!("Sending transaction...");
        let raw_tx = {
            let mut raw_tx = service::RawTransaction::default();
            tx.write(&mut raw_tx.data).unwrap();
            raw_tx
        };
        let response = client.send_transaction(raw_tx).await?.into_inner();

        if response.error_code != 0 {
            Err(error::Error::SendFailed {
                code: response.error_code,
                reason: response.error_message,
            }
            .into())
        } else {
            println!("{txid}");
            Ok(())
        }
    }
}
