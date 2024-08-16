use gumdrop::Options;
use tracing::info;
use zcash_client_backend::{data_api::wallet::decrypt_and_store_transaction, proto::service};
use zcash_client_sqlite::WalletDb;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, BranchId};

use crate::{
    data::{get_db_paths, get_wallet_network},
    remote::{connect_to_lightwalletd, Servers},
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

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_data) = get_db_paths(wallet_dir.as_ref());

        let txids = {
            let conn = rusqlite::Connection::open(&db_data)?;
            rusqlite::vtab::array::load_module(&conn)?;

            let mut stmt_unenhanced = conn.prepare(
                "SELECT txid
                FROM v_transactions
                WHERE raw IS NULL",
            )?;

            let txids = stmt_unenhanced
                .query_and_then([], |row| -> anyhow::Result<_> {
                    row.get(0)
                        .map(TxId::from_bytes)
                        .map_err(anyhow::Error::from)
                })?
                .collect::<Result<Vec<_>, _>>()?;

            // Needed to avoid a "doesn't live long enough" error.
            #[allow(clippy::let_and_return)]
            txids
        };

        let mut db_data = WalletDb::for_path(db_data, params)?;
        let mut client = connect_to_lightwalletd(self.server.pick(params)?).await?;

        for txid in txids {
            info!("Fetching {}", txid);

            let request = service::TxFilter {
                hash: txid.as_ref().to_vec(),
                ..Default::default()
            };

            let raw_tx = client.get_transaction(request).await?.into_inner();
            let mined_height = (raw_tx.height > 0 && raw_tx.height <= u64::from(u32::MAX))
                .then(|| BlockHeight::from_u32(u32::try_from(raw_tx.height).unwrap()));

            let tx = Transaction::read(
                &raw_tx.data[..],
                BranchId::for_height(
                    &params,
                    BlockHeight::from_u32(u32::try_from(raw_tx.height)?),
                ),
            )?;

            decrypt_and_store_transaction(&params, &mut db_data, &tx, mined_height)?;
        }

        Ok(())
    }
}
