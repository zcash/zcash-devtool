use std::convert::TryInto;
use std::iter;

use bech32::{Bech32, Hrp};
use secrecy::Zeroize;

use ::transparent::{
    address::TransparentAddress,
    keys::{AccountPrivKey, IncomingViewingKey},
};
use zcash_address::{
    ToAddress, ZcashAddress,
    unified::{self, Encoding},
};
use zcash_keys::{
    encoding::AddressCodec,
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey},
};
use zcash_protocol::{
    consensus::{self, Network, NetworkConstants, NetworkType},
    local_consensus::LocalNetwork,
};

use super::Context;

pub(crate) mod view;

pub(crate) fn inspect_mnemonic(mnemonic: bip0039::Mnemonic, context: Option<Context>) {
    eprintln!("Mnemonic phrase");
    eprintln!(" - Language: English");

    if let Some(((network, addr_net), accounts)) =
        context.and_then(|c| c.network().zip(c.addr_network()).zip(c.accounts()))
    {
        let mut seed = mnemonic.to_seed("");
        for account in accounts {
            eprintln!(" - Account {}:", u32::from(account));

            let orchard_fvk = match orchard::keys::SpendingKey::from_zip32_seed(
                &seed,
                network.coin_type(),
                account,
            ) {
                Ok(sk) => Some(orchard::keys::FullViewingKey::from(&sk)),
                Err(e) => {
                    eprintln!("  ⚠️  No valid Orchard key for this account under this seed: {e}");
                    None
                }
            };

            eprintln!("   - Sapling:");
            let sapling_extsk =
                sapling::zip32::ExtendedSpendingKey::master(&seed).and_then(|sapling_master| {
                    sapling::zip32::ExtendedSpendingKey::from_path(
                        &sapling_master,
                        &[
                            zip32::ChildIndex::hardened(32),
                            zip32::ChildIndex::hardened(network.coin_type()),
                            account.into(),
                        ],
                    )
                });
            let sapling_fvk_bytes: Option<[u8; 128]> = match sapling_extsk {
                Some(sapling_extsk) => {
                    #[allow(deprecated)]
                    let sapling_extfvk = sapling_extsk.to_extended_full_viewing_key();
                    let sapling_default_addr = sapling_extfvk.default_address();

                    let mut sapling_extsk_bytes = vec![];
                    sapling_extsk.write(&mut sapling_extsk_bytes).unwrap();
                    eprintln!(
                        "     - ExtSK:  {}",
                        bech32::encode::<Bech32>(
                            Hrp::parse_unchecked(
                                zcash_keys::constants::hrp_sapling_extended_spending_key(addr_net)
                            ),
                            &sapling_extsk_bytes,
                        )
                        .unwrap(),
                    );

                    let mut sapling_extfvk_bytes = vec![];
                    sapling_extfvk.write(&mut sapling_extfvk_bytes).unwrap();
                    eprintln!(
                        "     - ExtFVK: {}",
                        bech32::encode::<Bech32>(
                            Hrp::parse_unchecked(
                                zcash_keys::constants::hrp_sapling_extended_full_viewing_key(
                                    addr_net
                                )
                            ),
                            &sapling_extfvk_bytes
                        )
                        .unwrap(),
                    );

                    let sapling_addr_bytes = sapling_default_addr.1.to_bytes();
                    eprintln!(
                        "     - Default address: {}",
                        bech32::encode::<Bech32>(
                            Hrp::parse_unchecked(
                                zcash_address::constants::hrp_sapling_payment_address(addr_net)
                            ),
                            &sapling_addr_bytes,
                        )
                        .unwrap(),
                    );

                    Some(sapling_extfvk_bytes[41..].try_into().unwrap())
                }
                None => {
                    eprintln!("     ⚠️  No valid Sapling key for this account under this seed");
                    None
                }
            };

            let transparent_fvk = match AccountPrivKey::from_seed(&network, &seed, account)
                .map(|sk| sk.to_account_pubkey())
            {
                Ok(fvk) => {
                    eprintln!("   - Transparent:");
                    match fvk.derive_external_ivk().map(|ivk| ivk.default_address().0) {
                        Ok(addr) => eprintln!(
                            "     - Default address: {}",
                            match addr {
                                TransparentAddress::PublicKeyHash(data) =>
                                    ZcashAddress::from_transparent_p2pkh(addr_net, data),
                                TransparentAddress::ScriptHash(_) => unreachable!(),
                            }
                            .encode(),
                        ),
                        Err(e) => eprintln!(
                            "    ⚠️  No valid transparent default address for this account under this seed: {e:?}"
                        ),
                    }

                    Some(fvk)
                }
                Err(e) => {
                    eprintln!(
                        "  ⚠️  No valid transparent key for this account under this seed: {e:?}"
                    );
                    None
                }
            };

            let items: Vec<_> = iter::empty()
                .chain(
                    orchard_fvk
                        .map(|fvk| fvk.to_bytes())
                        .map(unified::Fvk::Orchard),
                )
                .chain(sapling_fvk_bytes.map(unified::Fvk::Sapling))
                .chain(
                    transparent_fvk
                        .map(|fvk| fvk.serialize()[..].try_into().unwrap())
                        .map(unified::Fvk::P2pkh),
                )
                .collect();
            let item_names: Vec<_> = items
                .iter()
                .map(|item| match item {
                    unified::Fvk::Orchard(_) => "Orchard",
                    unified::Fvk::Sapling(_) => "Sapling",
                    unified::Fvk::P2pkh(_) => "Transparent",
                    unified::Fvk::P2sh(_) => "Transparent multisig",
                    unified::Fvk::Unknown { .. } => unreachable!(),
                })
                .collect();

            eprintln!("   - Unified ({}):", item_names.join(", "));
            let ufvk = unified::Ufvk::try_from_items(
                unified::Revision::R0,
                items.into_iter().map(unified::Uitem::Data).collect(),
            )
            .unwrap();
            eprintln!("     - UFVK: {}", ufvk.encode(&addr_net));
        }
        seed.zeroize();
    } else {
        eprintln!(
            "🔎 To show account details, add \"network\" (either \"main\" or \"test\") and \"accounts\" array to context"
        );
    }

    eprintln!();
    eprintln!(
        "WARNING: This mnemonic phrase is now likely cached in your terminal's history buffer."
    );
}

pub(crate) fn inspect_sapling_extsk(data: Vec<u8>, network: NetworkType) {
    match sapling::zip32::ExtendedSpendingKey::read(&data[..]).map_err(|_| ()) {
        Err(_) => {
            eprintln!("Invalid encoding that claims to be a Sapling extended spending key");
        }
        Ok(extsk) => {
            eprintln!("Sapling extended spending key");

            let default_addr_bytes = extsk.default_address().1.to_bytes();
            eprintln!(
                "- Default address: {}",
                bech32::encode::<Bech32>(
                    Hrp::parse_unchecked(zcash_address::constants::hrp_sapling_payment_address(
                        network
                    )),
                    &default_addr_bytes,
                )
                .unwrap(),
            );

            #[allow(deprecated)]
            if let Ok(ufvk) = UnifiedFullViewingKey::from_sapling_extended_full_viewing_key(
                extsk.to_extended_full_viewing_key(),
            ) {
                let encoded_ufvk = match network {
                    NetworkType::Main => ufvk.encode(&Network::MainNetwork),
                    NetworkType::Test => ufvk.encode(&Network::TestNetwork),
                    NetworkType::Regtest => ufvk.encode(&LocalNetwork {
                        overwinter: None,
                        sapling: None,
                        blossom: None,
                        heartwood: None,
                        canopy: None,
                        nu5: None,
                        nu6: None,
                        nu6_1: None,
                        nu6_2: None,
                        nu6_3: None,
                        nu7: None,
                    }),
                };
                match encoded_ufvk {
                    Ok(encoded_ufvk) => eprintln!("- UFVK: {encoded_ufvk}"),
                    Err(e) => eprintln!("- UFVK: cannot be encoded ({e})"),
                }

                let (default_ua, _) = ufvk
                    .default_address(UnifiedAddressRequest::AllAvailableKeys)
                    .expect("should exist");
                let encoded_ua = match network {
                    NetworkType::Main => default_ua.encode(&Network::MainNetwork),
                    NetworkType::Test => default_ua.encode(&Network::TestNetwork),
                    NetworkType::Regtest => default_ua.encode(&LocalNetwork {
                        overwinter: None,
                        sapling: None,
                        blossom: None,
                        heartwood: None,
                        canopy: None,
                        nu5: None,
                        nu6: None,
                        nu6_1: None,
                        nu6_2: None,
                        nu6_3: None,
                        nu7: None,
                    }),
                };
                eprintln!("  - Default address: {encoded_ua}");
            }
        }
    }

    eprintln!();
    eprintln!("WARNING: This spending key is now likely cached in your terminal's history buffer.");
}

pub(crate) fn inspect_transparent_sk(data: &[u8], network: NetworkType) {
    let (data, compressed) = match data.split_last() {
        Some((b, rest)) if *b == 1 => (rest, true),
        _ => (data, false),
    };

    let secret_key = <[u8; 32]>::try_from(data)
        .ok()
        .and_then(|bytes| secp256k1::SecretKey::from_secret_bytes(bytes).ok());
    match secret_key {
        None => {
            eprintln!("Invalid encoding that claims to be a transparent secret key");
        }
        Some(sk) => {
            eprintln!("Transparent secret key");

            let pubkey = sk.public_key();
            eprintln!(
                "- Public key: {}",
                if compressed {
                    hex::encode(pubkey.serialize())
                } else {
                    hex::encode(pubkey.serialize_uncompressed())
                }
            );

            if compressed {
                let params = match network {
                    NetworkType::Main => consensus::Network::MainNetwork,
                    NetworkType::Test => consensus::Network::TestNetwork,
                    NetworkType::Regtest => unreachable!(),
                };

                // `TransparentAddress::from_pubkey` only supports compressed encodings.
                eprintln!(
                    "- P2PKH address: {}",
                    TransparentAddress::from_pubkey(&pubkey).encode(&params),
                );
            }
        }
    }

    eprintln!();
    eprintln!("WARNING: This secret key is now likely cached in your terminal's history buffer.");
}
