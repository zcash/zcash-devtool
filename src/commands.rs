use anyhow::anyhow;
use uuid::Uuid;
use zcash_client_backend::data_api::WalletRead;
use zcash_client_sqlite::AccountUuid;

pub(crate) mod balance;
pub(crate) mod enhance;
pub(crate) mod import_ufvk;
pub(crate) mod init;
pub(crate) mod init_fvk;
pub(crate) mod list_accounts;
pub(crate) mod list_addresses;
pub(crate) mod list_tx;
pub(crate) mod list_unspent;
pub(crate) mod pczt;
pub(crate) mod propose;
pub(crate) mod reset;
pub(crate) mod send;
pub(crate) mod shield;
pub(crate) mod sync;
pub(crate) mod upgrade;

#[cfg(feature = "pczt-qr")]
pub(crate) mod keystone;

pub(crate) fn select_account<DbT: WalletRead<AccountId = AccountUuid>>(
    db_data: &DbT,
    account_uuid: Option<Uuid>,
) -> Result<DbT::Account, anyhow::Error>
where
    DbT::Error: std::error::Error + Sync + Send + 'static,
{
    let account_id = match account_uuid {
        Some(uuid) => Ok(AccountUuid::from_uuid(uuid)),
        None => {
            let account_ids = db_data.get_account_ids()?;
            match &account_ids[..] {
                [] => Err(anyhow!("Wallet contains no accounts.")),
                [account_id] => Ok(*account_id),
                _ => Err(anyhow!(
                    "More than one account is available; please specify the account UUID."
                )),
            }
        }
    }?;

    db_data
        .get_account(account_id)?
        .ok_or(anyhow!("Account missing: {:?}", account_id))
}
