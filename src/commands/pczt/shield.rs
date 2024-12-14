use std::num::NonZeroUsize;

use anyhow::anyhow;
use gumdrop::Options;

use tokio::io::{stdout, AsyncWriteExt};
use zcash_client_backend::{
    data_api::{
        wallet::{
            create_pczt_from_proposal, input_selection::GreedyInputSelector, propose_shielding,
        },
        WalletRead,
    },
    fees::{standard::MultiOutputChangeStrategy, DustOutputPolicy, SplitPolicy, StandardFeeRule},
    wallet::OvkPolicy,
    ShieldedProtocol,
};
use zcash_client_sqlite::WalletDb;
use zcash_protocol::value::Zatoshis;

use crate::{config::WalletConfig, data::get_db_paths, error};

// Options accepted for the `pczt shield` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(
        help = "note management: the number of notes to maintain in the wallet",
        default = "4"
    )]
    target_note_count: usize,

    #[options(
        help = "note management: the minimum allowed value for split change amounts",
        default = "10000000"
    )]
    min_split_output_value: u64,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();

        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let mut db_data = WalletDb::for_path(db_data, params)?;
        let account_id = *db_data
            .get_account_ids()?
            .first()
            .ok_or(anyhow!("Wallet has no accounts"))?;

        // Create the PCZT.
        let change_strategy = MultiOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            None,
            ShieldedProtocol::Orchard,
            DustOutputPolicy::default(),
            SplitPolicy::with_min_output_value(
                NonZeroUsize::new(self.target_note_count)
                    .ok_or(anyhow!("target note count must be nonzero"))?,
                Zatoshis::from_u64(self.min_split_output_value)?,
            ),
        );
        let input_selector = GreedyInputSelector::new();

        // For this dev tool, shield all funds immediately.
        let max_height = match db_data.chain_height()? {
            Some(max_height) => max_height,
            // If we haven't scanned anything, there's nothing to do.
            None => return Ok(()),
        };
        let transparent_balances = db_data.get_transparent_balances(account_id, max_height)?;
        let from_addrs = transparent_balances.into_keys().collect::<Vec<_>>();

        let proposal = propose_shielding(
            &mut db_data,
            &params,
            &input_selector,
            &change_strategy,
            Zatoshis::ZERO,
            &from_addrs,
            account_id,
            0,
        )
        .map_err(error::Error::Shield)?;

        let pczt = create_pczt_from_proposal(
            &mut db_data,
            &params,
            account_id,
            OvkPolicy::Sender,
            &proposal,
        )
        .map_err(error::Error::Shield)?;

        stdout().write_all(&pczt.serialize()).await?;

        Ok(())
    }
}
