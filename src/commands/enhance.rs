use std::collections::BTreeSet;

use anyhow::anyhow;
use futures_util::StreamExt;
use gumdrop::Options;
use tonic::{transport::Channel, Code};
use tracing::info;
use zcash_client_backend::{
    data_api::{
        wallet::decrypt_and_store_transaction, TransactionDataRequest, TransactionStatus,
        WalletRead, WalletWrite,
    },
    proto::service::{
        self, compact_tx_streamer_client::CompactTxStreamerClient, BlockRange, RawTransaction,
    },
};
use zcash_keys::encoding::AddressCodec;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};

use crate::{
    data::get_wallet_network,
    remote::{tor_client, Servers},
};

// Options accepted for the `enhance` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(
        help = "the server to enhance with (default is \"ecc\")",
        default = "ecc",
        parse(try_from_str = "Servers::parse")
    )]
    server: Servers,
}

fn parse_raw_transaction(
    params: &Network,
    chain_tip: BlockHeight,
    tx: RawTransaction,
) -> Result<(Transaction, Option<BlockHeight>), anyhow::Error> {
    let mined_height = (tx.height > 0 && tx.height <= u64::from(u32::MAX))
        .then(|| BlockHeight::from_u32(u32::try_from(tx.height).unwrap()));

    let tx = Transaction::read(
        &tx.data[..],
        // We assume unmined transactions are created with the current consensus branch ID.
        BranchId::for_height(params, mined_height.unwrap_or(chain_tip)),
    )?;

    Ok((tx, mined_height))
}

async fn fetch_transaction(
    client: &mut CompactTxStreamerClient<Channel>,
    params: &Network,
    chain_tip: BlockHeight,
    txid: TxId,
) -> Result<Option<(Transaction, Option<BlockHeight>)>, anyhow::Error> {
    let request = service::TxFilter {
        hash: txid.as_ref().to_vec(),
        ..Default::default()
    };

    let raw_tx = match client.get_transaction(request).await {
        Ok(response) => Ok(Some(response.into_inner())),
        Err(status) => {
            if status.code() == Code::NotFound {
                Ok(None)
            } else {
                Err(status)
            }
        }
    }?;

    raw_tx
        .map(|raw_tx| parse_raw_transaction(params, chain_tip, raw_tx))
        .transpose()
}

impl Command {
    pub(crate) async fn run<W>(self, wallet_dir: Option<String>, db_data: &mut W) -> Result<(), anyhow::Error> where W: WalletRead + WalletWrite, <W as WalletRead>::Error: std::error::Error + Send + Sync + 'static {
        let params = get_wallet_network(wallet_dir.as_ref())?;

        let chain_tip = db_data.chain_height()?.ok_or_else(|| {
            anyhow!("Chain height must be available to perform transaction enhancement.")
        })?;

        // TODO:
        // - Create a shared Tor client.
        // - Create an isolated `lightwalletd` connection for each transaction.
        // - Spread transactions across all available servers.
        // - Fetch transactions in parallel, with timing noise.
        let mut client = self
            .server
            .pick(params)?
            .connect(|| tor_client(wallet_dir.as_ref()))
            .await?;

        let mut satisfied_requests = BTreeSet::new();
        loop {
            let mut new_request_encountered = false;
            for data_request in db_data.transaction_data_requests()? {
                if satisfied_requests.contains(&data_request) {
                    continue;
                } else {
                    new_request_encountered = true;
                }

                info!("Fetching data for request {:?}", data_request);
                match data_request {
                    TransactionDataRequest::GetStatus(txid) => {
                        let status = fetch_transaction(&mut client, &params, chain_tip, txid)
                            .await?
                            .map_or(TransactionStatus::TxidNotRecognized, |(_, mined_height)| {
                                mined_height.map_or(
                                    TransactionStatus::NotInMainChain,
                                    TransactionStatus::Mined,
                                )
                            });
                        info!("Got status {:?}", status);
                        db_data.set_transaction_status(txid, status)?;
                    }
                    TransactionDataRequest::Enhancement(txid) => {
                        match fetch_transaction(&mut client, &params, chain_tip, txid).await? {
                            None => {
                                info!("Txid not recognized {:?}", txid);
                                db_data.set_transaction_status(
                                    txid,
                                    TransactionStatus::TxidNotRecognized,
                                )?;
                            }
                            Some((tx, mined_height)) => {
                                info!(
                                    "Enhancing tx {:?} with mined height {:?}",
                                    txid, mined_height
                                );
                                decrypt_and_store_transaction(
                                    &params,
                                    db_data,
                                    &tx,
                                    mined_height,
                                )?;
                            }
                        }
                    }
                    TransactionDataRequest::SpendsFromAddress {
                        address,
                        block_range_start,
                        block_range_end,
                    } => {
                        let address = address.encode(&params);
                        let request = service::TransparentAddressBlockFilter {
                            address: address.clone(),
                            range: Some(BlockRange {
                                start: Some(service::BlockId {
                                    height: u64::from(block_range_start),
                                    ..Default::default()
                                }),
                                end: block_range_end.map(|h| service::BlockId {
                                    height: u64::from(h - 1), // `BlockRange` end is inclusive.
                                    ..Default::default()
                                }),
                            }),
                        };

                        let mut stream = client.get_taddress_txids(request).await?.into_inner();
                        while let Some(raw_tx) = stream.next().await {
                            let (tx, mined_height) =
                                parse_raw_transaction(&params, chain_tip, raw_tx?)?;
                            info!(
                                "Found tx {:?} for address {} with mined height {:?}",
                                tx.txid(),
                                address,
                                mined_height
                            );
                            decrypt_and_store_transaction(&params, db_data, &tx, mined_height)?
                        }
                    }
                }

                satisfied_requests.insert(data_request);
            }

            if !new_request_encountered {
                break;
            }
        }

        Ok(())
    }
}
