use tonic::transport::{Channel, ClientTlsConfig};
use zcash_client_backend::proto::{
    compact_formats::CompactBlock,
    service::{BlockId, TxFilter, compact_tx_streamer_client::CompactTxStreamerClient},
};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};

const MAINNET: Server = Server {
    host: "zec.rocks",
    port: 443,
};

const TESTNET: Server = Server {
    host: "testnet.zec.rocks",
    port: 443,
};

struct Server {
    host: &'static str,
    port: u16,
}

impl Server {
    fn endpoint(&self) -> String {
        format!("https://{}:{}", self.host, self.port)
    }
}

async fn connect(server: &Server) -> anyhow::Result<CompactTxStreamerClient<Channel>> {
    let channel = Channel::from_shared(server.endpoint())?;

    let tls = ClientTlsConfig::new()
        .domain_name(server.host.to_string())
        .with_webpki_roots();
    let channel = channel.tls_config(tls)?;

    Ok(CompactTxStreamerClient::new(channel.connect().await?))
}

#[derive(Debug)]
pub(crate) struct Lightwalletd {
    inner: CompactTxStreamerClient<Channel>,
    parameters: Network,
}

impl Lightwalletd {
    pub(crate) async fn mainnet() -> anyhow::Result<Self> {
        Ok(Self {
            inner: connect(&MAINNET).await?,
            parameters: Network::MainNetwork,
        })
    }

    pub(crate) async fn testnet() -> anyhow::Result<Self> {
        Ok(Self {
            inner: connect(&TESTNET).await?,
            parameters: Network::TestNetwork,
        })
    }

    pub(crate) async fn lookup_block_hash(&mut self, candidate: [u8; 32]) -> Option<CompactBlock> {
        let request = BlockId {
            hash: candidate.into(),
            ..Default::default()
        };
        self.inner
            .get_block(request)
            .await
            .ok()
            .map(|b| b.into_inner())
    }

    pub(crate) async fn lookup_txid(
        &mut self,
        candidate: [u8; 32],
    ) -> Option<(Transaction, Option<BlockHeight>)> {
        let request = TxFilter {
            hash: candidate.into(),
            ..Default::default()
        };
        let response = self.inner.get_transaction(request).await.ok()?.into_inner();

        // lightwalletd reports `RawTransaction.height` as 0 for a transaction in the
        // mempool and as u64::MAX (-1 in two's complement) for one mined outside the main
        // chain; neither is a main-chain block height. Treating 0 as a height reported
        // mempool transactions as "Mined in … block 0" and parsed them with that height's
        // consensus branch.
        let mined_height = match response.height {
            0 => None,
            height => height.try_into().ok(),
        };

        Transaction::read(
            &response.data[..],
            mined_height
                .map(|height| BranchId::for_height(&self.parameters, height))
                .unwrap_or(BranchId::Nu5),
        )
        .ok()
        .map(|tx| (tx, mined_height))
    }
}
