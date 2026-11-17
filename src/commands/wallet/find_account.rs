use std::{fmt, str::FromStr};

use anyhow::anyhow;
use clap::Args;
use zcash_address::{ConversionError, ParseError, ZcashAddress};
use zcash_client_backend::data_api::{WalletRead, error::FindAccountForAddressError};
use zcash_client_sqlite::WalletDb;
use zcash_keys::address::Address;
use zcash_protocol::consensus;

use crate::{config::get_wallet_network, data::get_db_paths};

use super::list_accounts::print_account;

// Options accepted for the `find-account` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The address to look up: a unified, Sapling, transparent, or TEX address for the
    /// wallet's network.
    ///
    /// A unified or Sapling address is found if the viewing key of an account derives it,
    /// even if the wallet never generated it. A transparent address is found only if the
    /// wallet has generated or imported it. A TEX address is found if the wallet has
    /// generated or imported the transparent address with the same public key hash.
    address: String,
}

impl Command {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let db_data = WalletDb::for_path(db_data, params, (), ())?;

        let account_id = find_account(&db_data, &params, &self.address)?;
        let account = db_data
            .get_account(account_id)?
            .ok_or_else(|| anyhow!("Account missing: {:?}", account_id))?;

        print_account(&params, &account)
    }
}

/// The reason that the lookup of an address did not produce an account.
#[derive(Debug)]
enum Error<WalletError> {
    /// The text is not the encoding of a Zcash address.
    InvalidAddress(ParseError),
    /// The address is for a different network than the wallet, or the wallet does not
    /// support this kind of address.
    UnusableAddress(ConversionError<&'static str>),
    /// No account in the wallet controls the address.
    NoAccount,
    /// The wallet could not attribute the address to one account. Either it could not be
    /// read, or the receivers of a unified address belong to different accounts.
    Lookup(FindAccountForAddressError<WalletError>),
}

impl<WalletError: fmt::Display> fmt::Display for Error<WalletError> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidAddress(e) => write!(f, "Not a valid Zcash address: {e}"),
            Error::UnusableAddress(e) => write!(f, "The wallet cannot use this address: {e}"),
            Error::NoAccount => write!(f, "No account in this wallet controls the address"),
            Error::Lookup(e) => e.fmt(f),
        }
    }
}

impl<WalletError: fmt::Debug + fmt::Display> std::error::Error for Error<WalletError> {}

/// Finds the account that controls an address.
///
/// - Preconditions: `params` describes the network of the accounts in `wallet`.
/// - Inputs: the wallet, the parameters of its network, and the encoded address.
/// - Outputs: the identifier of the account that controls the address. An [`Error`] if the
///   text is not an address that the wallet can use, if no account controls the address,
///   if the receivers of a unified address belong to different accounts, or if the wallet
///   cannot be read.
/// - Side effects: reads the wallet.
fn find_account<W: WalletRead, P: consensus::Parameters>(
    wallet: &W,
    params: &P,
    encoded_address: &str,
) -> Result<W::AccountId, Error<W::Error>> {
    let address = ZcashAddress::from_str(encoded_address)
        .map_err(Error::InvalidAddress)?
        .convert_if_network::<Address>(params.network_type())
        .map_err(Error::UnusableAddress)?;

    wallet
        .find_account_for_address(params, &address)
        .map_err(Error::Lookup)?
        .ok_or(Error::NoAccount)
}

#[cfg(test)]
mod tests {
    use rand::{rand_core::UnwrapErr, rngs::SysRng};
    use secrecy::SecretVec;
    use transparent::address::TransparentAddress;
    use zcash_address::ConversionError;
    use zcash_client_backend::data_api::{
        Account as _, AccountBirthday, WalletRead, WalletWrite, chain::ChainState,
    };
    use zcash_client_sqlite::{
        AccountUuid, WalletDb, util::SystemClock, wallet::init::init_wallet_db,
    };
    use zcash_keys::{
        address::Address,
        keys::{UnifiedAddressRequest, UnifiedSpendingKey},
    };
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::consensus::{
        MAIN_NETWORK, NetworkUpgrade, Parameters, TEST_NETWORK, TestNetwork,
    };
    use zip32::DiversifierIndex;

    use super::{Error, find_account};

    type TestWallet = WalletDb<rusqlite::Connection, TestNetwork, SystemClock, UnwrapErr<SysRng>>;

    /// Creates a testnet wallet in memory that holds one account.
    ///
    /// - Preconditions: none.
    /// - Inputs: none.
    /// - Outputs: the wallet, and the identifier of its account. The chain tip of the
    ///   wallet is the birthday height of the account.
    /// - Side effects: none.
    fn wallet_with_one_account() -> (TestWallet, AccountUuid) {
        let mut wallet =
            WalletDb::for_path(":memory:", TEST_NETWORK, SystemClock, UnwrapErr(SysRng)).unwrap();
        init_wallet_db(&mut wallet, None).unwrap();

        let birthday_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Nu5)
            .expect("NU5 is active on testnet");
        let birthday = AccountBirthday::from_parts(
            ChainState::empty(birthday_height - 1, BlockHash([0; 32])),
            None,
        );
        let (account_id, _) = wallet
            .create_account("", &SecretVec::new(vec![0u8; 32]), &birthday, None)
            .unwrap();
        wallet.update_chain_tip(birthday_height).unwrap();

        (wallet, account_id)
    }

    /// Returns the spending key of an account that no test wallet holds.
    fn unknown_spending_key<P: Parameters>(params: &P) -> UnifiedSpendingKey {
        UnifiedSpendingKey::from_seed(params, &[7u8; 32], zip32::AccountId::ZERO).unwrap()
    }

    #[test]
    fn unified_address_of_account_resolves_to_account() {
        let (mut wallet, account_id) = wallet_with_one_account();
        let (address, _) = wallet
            .get_next_available_address(account_id, UnifiedAddressRequest::AllAvailableKeys)
            .unwrap()
            .expect("the wallet contains the account");

        assert_eq!(
            find_account(&wallet, &TEST_NETWORK, &address.encode(&TEST_NETWORK)).unwrap(),
            account_id,
        );
    }

    #[test]
    fn transparent_receiver_of_generated_address_resolves_to_account() {
        let (mut wallet, account_id) = wallet_with_one_account();
        let (address, _) = wallet
            .get_next_available_address(account_id, UnifiedAddressRequest::AllAvailableKeys)
            .unwrap()
            .expect("the wallet contains the account");
        let transparent_address = Address::Transparent(
            *address
                .transparent()
                .expect("the address has a transparent receiver"),
        );

        assert_eq!(
            find_account(
                &wallet,
                &TEST_NETWORK,
                &transparent_address.encode(&TEST_NETWORK),
            )
            .unwrap(),
            account_id,
        );
    }

    #[test]
    fn tex_address_of_generated_transparent_receiver_resolves_to_account() {
        let (mut wallet, account_id) = wallet_with_one_account();
        let (address, _) = wallet
            .get_next_available_address(account_id, UnifiedAddressRequest::AllAvailableKeys)
            .unwrap()
            .expect("the wallet contains the account");
        let TransparentAddress::PublicKeyHash(pubkey_hash) = address
            .transparent()
            .expect("the address has a transparent receiver")
        else {
            panic!("the transparent receiver must be a P2PKH address");
        };

        assert_eq!(
            find_account(
                &wallet,
                &TEST_NETWORK,
                &Address::Tex(*pubkey_hash).encode(&TEST_NETWORK),
            )
            .unwrap(),
            account_id,
        );
    }

    #[test]
    fn sapling_address_that_wallet_never_generated_resolves_to_account() {
        let (wallet, account_id) = wallet_with_one_account();
        let account = wallet
            .get_account(account_id)
            .unwrap()
            .expect("the wallet contains the account");
        let (_, sapling_address) = account
            .uivk()
            .sapling()
            .as_ref()
            .expect("the account has a Sapling viewing key")
            .find_address(DiversifierIndex::from(1_000_000u32))
            .expect("a valid diversifier exists at or above the start index");

        assert_eq!(
            find_account(
                &wallet,
                &TEST_NETWORK,
                &Address::from(sapling_address).encode(&TEST_NETWORK),
            )
            .unwrap(),
            account_id,
        );
    }

    #[test]
    fn address_of_unknown_key_resolves_to_no_account() {
        let (wallet, _) = wallet_with_one_account();
        let (address, _) = unknown_spending_key(&TEST_NETWORK)
            .to_unified_full_viewing_key()
            .default_address(UnifiedAddressRequest::AllAvailableKeys)
            .unwrap();
        let sapling_address = Address::from(*address.sapling().expect("has a Sapling receiver"));
        let transparent_address =
            Address::Transparent(*address.transparent().expect("has a transparent receiver"));

        for encoded_address in [
            address.encode(&TEST_NETWORK),
            sapling_address.encode(&TEST_NETWORK),
            transparent_address.encode(&TEST_NETWORK),
        ] {
            assert!(matches!(
                find_account(&wallet, &TEST_NETWORK, &encoded_address),
                Err(Error::NoAccount),
            ));
        }
    }

    #[test]
    fn address_for_another_network_is_rejected() {
        let (wallet, _) = wallet_with_one_account();
        let (mainnet_address, _) = unknown_spending_key(&MAIN_NETWORK)
            .to_unified_full_viewing_key()
            .default_address(UnifiedAddressRequest::AllAvailableKeys)
            .unwrap();

        assert!(matches!(
            find_account(
                &wallet,
                &TEST_NETWORK,
                &mainnet_address.encode(&MAIN_NETWORK),
            ),
            Err(Error::UnusableAddress(
                ConversionError::IncorrectNetwork { .. }
            )),
        ));
    }

    #[test]
    fn text_that_is_not_an_address_is_rejected() {
        let (wallet, _) = wallet_with_one_account();

        assert!(matches!(
            find_account(&wallet, &TEST_NETWORK, "not an address"),
            Err(Error::InvalidAddress(_)),
        ));
    }
}
