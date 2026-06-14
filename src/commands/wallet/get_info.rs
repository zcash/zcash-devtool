use clap::Args;
use zcash_client_backend::proto::service;

use crate::{config::get_wallet_network, remote::ConnectionArgs};

// Options accepted for the `get-info` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    #[command(flatten)]
    connection: ConnectionArgs,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let params = get_wallet_network(wallet_dir.as_ref())?;

        // The server we are about to connect to (for the reported URI).
        let server_uri = self.connection.server.pick(params)?.uri();

        let mut client = self.connection.connect(params, wallet_dir.as_ref()).await?;
        let info = client
            .get_lightd_info(service::Empty {})
            .await?
            .into_inner();

        // Stable, machine-consumed shape (see zcash_local_net's
        // `client::zcash_devtool` GetInfoResponse parser).
        let json = serde_json::json!({
            "server_uri": server_uri,
            "chain_name": info.chain_name,
            "chain_tip_height": info.block_height,
        });
        println!("{}", serde_json::to_string(&json)?);

        Ok(())
    }
}
