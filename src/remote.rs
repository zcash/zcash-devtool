use tonic::transport::{Channel, ClientTlsConfig};

use tracing::info;
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_primitives::consensus;

pub(crate) trait Lightwalletd {
    fn host(&self) -> &str;
    fn port(&self) -> u16;
}

impl Lightwalletd for consensus::Network {
    fn host(&self) -> &str {
        match self {
            consensus::Network::MainNetwork => "mainnet.lightwalletd.com",
            consensus::Network::TestNetwork => "lightwalletd.testnet.electriccoin.co",
        }
    }

    fn port(&self) -> u16 {
        9067
    }
}

pub(crate) async fn connect_to_lightwalletd(
    network: &impl Lightwalletd,
) -> Result<CompactTxStreamerClient<Channel>, anyhow::Error> {
    info!("Connecting to {}:{}", network.host(), network.port());

    let tls = ClientTlsConfig::new().domain_name(network.host());

    let channel = Channel::from_shared(format!("https://{}:{}", network.host(), network.port()))?
        .tls_config(tls)?
        .connect()
        .await?;

    Ok(CompactTxStreamerClient::new(channel))
}
